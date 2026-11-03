"""Tests for LLM Client & Provider Interface (Task A10).

Validates:
- Structured JSON output with Pydantic model validation
- Single-retry with validation error feedback on invalid JSON output (AGENTS.md Rule 5)
- Fallback to deterministic rule-based output on retry exhaustion (Rule 13)
- Dual-Key Failover: Primary rate limit (429) fails over to Secondary key/model
- Call budget exhaustion triggers fallback without crashing
- Prompt-hash cache hit avoids duplicate network calls
- Trace event recording to SQLite for every invocation (AGENTS.md Rule 7)
"""

import sqlite3
from typing import Any

import pytest
from pydantic import BaseModel, Field

from cipher_lens.planner.llm import LlmClient, LlmResponse
from cipher_lens.store.db import init_db


class SampleActionModel(BaseModel):
    action: str
    target: str
    priority: int = Field(ge=1, le=10)


def fallback_action() -> SampleActionModel:
    return SampleActionModel(action="rule_based_scan", target="10.0.0.5", priority=1)


@pytest.fixture
def test_db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=True)
    init_db(conn)
    return conn


def test_complete_json_success(test_db_conn: sqlite3.Connection) -> None:
    calls = []

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        calls.append((prompt, model, api_key))
        return '{"action": "port_scan", "target": "10.0.0.5", "priority": 5}'

    client = LlmClient(
        primary_key="key-primary-123",
        primary_model="gemini-3.8-flash",
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    resp: LlmResponse[SampleActionModel] = client.complete_json(
        system_instruction="Security planner",
        user_prompt="Scan open ports",
        schema=SampleActionModel,
        fallback_factory=fallback_action,
    )

    assert resp.label == "live"
    assert resp.data.action == "port_scan"
    assert resp.data.priority == 5
    assert len(calls) == 1
    assert calls[0][1] == "gemini-3.8-flash"
    assert calls[0][2] == "key-primary-123"

    # Verify trace in SQLite
    cur = test_db_conn.execute("SELECT provider, model, outcome, label FROM llm_traces")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "gemini"
    assert row[1] == "gemini-3.8-flash"
    assert row[2] == "success"
    assert row[3] == "live"


def test_complete_json_invalid_schema_retry_success(
    test_db_conn: sqlite3.Connection,
) -> None:
    """AGENTS.md Rule 5: If output fails schema validation, retry ONCE with error feedback."""
    attempt = 0

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            # Missing required field 'priority'
            return '{"action": "port_scan", "target": "10.0.0.5"}'
        # Retry response provides correct schema
        assert "Validation error" in prompt
        return '{"action": "port_scan", "target": "10.0.0.5", "priority": 3}'

    client = LlmClient(
        primary_key="key-primary-123",
        primary_model="gemini-3.8-flash",
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    resp = client.complete_json(
        system_instruction="Security planner",
        user_prompt="Scan open ports",
        schema=SampleActionModel,
        fallback_factory=fallback_action,
    )

    assert resp.label == "live"
    assert resp.data.priority == 3
    assert attempt == 2


def test_complete_json_invalid_schema_retry_exhausted_fallback(
    test_db_conn: sqlite3.Connection,
) -> None:
    """If retry fails a second time, trigger fallback and label as rule-based."""

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        return '{"invalid_field": "nonsense"}'

    client = LlmClient(
        primary_key="key-primary-123",
        primary_model="gemini-3.8-flash",
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    resp = client.complete_json(
        system_instruction="Security planner",
        user_prompt="Scan open ports",
        schema=SampleActionModel,
        fallback_factory=fallback_action,
    )

    assert resp.label == "rule-based"
    assert resp.data.action == "rule_based_scan"
    assert resp.data.priority == 1


def test_dual_key_failover_on_rate_limit(test_db_conn: sqlite3.Connection) -> None:
    """When primary key hits HTTP 429 quota exhaustion, failover to secondary key."""
    calls = []

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        calls.append((model, api_key))
        if api_key == "primary-key-1":
            raise RuntimeError("429 ResourceExhausted: Quota exceeded for project")
        return '{"action": "secondary_scan", "target": "10.0.0.5", "priority": 7}'

    client = LlmClient(
        primary_key="primary-key-1",
        primary_model="gemini-3.8-flash",
        secondary_key="secondary-key-2",
        secondary_model="gemini-3.5-flash-lite",
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    resp = client.complete_json(
        system_instruction="Security planner",
        user_prompt="Scan open ports",
        schema=SampleActionModel,
        fallback_factory=fallback_action,
    )

    assert resp.label == "live"
    assert resp.model == "gemini-3.5-flash-lite"
    assert resp.data.action == "secondary_scan"
    assert len(calls) == 2
    assert calls[0][1] == "primary-key-1"
    assert calls[1][1] == "secondary-key-2"


def test_call_budget_exhaustion_triggers_fallback(
    test_db_conn: sqlite3.Connection,
) -> None:
    """When call budget is reached, calls fall back to rule-based without crashing."""
    calls_count = 0

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        nonlocal calls_count
        calls_count += 1
        return '{"action": "scan", "target": "10.0.0.5", "priority": 2}'

    client = LlmClient(
        primary_key="key-1",
        call_budget=2,
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    # First 2 calls use budget
    r1 = client.complete_json("sys", "prompt1", SampleActionModel, fallback_action)
    assert r1.label == "live"
    r2 = client.complete_json("sys", "prompt2", SampleActionModel, fallback_action)
    assert r2.label == "live"
    assert calls_count == 2

    # 3rd call exceeds budget -> triggers fallback
    r3 = client.complete_json("sys", "prompt3", SampleActionModel, fallback_action)
    assert r3.label == "rule-based"
    assert r3.data.action == "rule_based_scan"
    assert calls_count == 2  # No remote call made


def test_prompt_hash_caching(test_db_conn: sqlite3.Connection, tmp_path: Any) -> None:
    """Identical prompt returns cached result with label='cached' without hitting backend."""
    calls = 0

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        nonlocal calls
        calls += 1
        return '{"action": "cached_scan", "target": "10.0.0.5", "priority": 4}'

    client = LlmClient(
        primary_key="key-1",
        cache_dir=tmp_path / "llm_cache",
        db_conn=test_db_conn,
        raw_completion_fn=mock_backend,
    )

    # Call 1
    r1 = client.complete_json("sys", "same_prompt", SampleActionModel, fallback_action)
    assert r1.label == "live"
    assert calls == 1

    # Call 2 with identical prompt & schema -> cache hit
    r2 = client.complete_json("sys", "same_prompt", SampleActionModel, fallback_action)
    assert r2.label == "cached"
    assert r2.data.action == "cached_scan"
    assert calls == 1  # Backend was not called again


def test_llm_provider_none_deterministic_fallback(
    test_db_conn: sqlite3.Connection,
) -> None:
    """When provider is 'none', immediately returns rule-based fallback."""
    client = LlmClient(provider="none", db_conn=test_db_conn)
    resp = client.complete_json("sys", "test", SampleActionModel, fallback_action)
    assert resp.label == "rule-based"
    assert resp.data.action == "rule_based_scan"
