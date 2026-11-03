"""Tests for Natural Language Intake and Scope Verification (Task A11).

Validates:
- Extraction of targets, objectives, and constraints from natural language
- Scope validation of extracted targets via PolicyGate / ScopeRegistry
- Out-of-scope targets are refused with an audited/visible reason
- Ambiguous requests generate a clarifying question
- Fallback regex parsing when LLM provider is 'none' or unavailable
"""

from datetime import UTC, datetime, timedelta

import pytest

from cipher_lens.planner.intake import (
    fallback_parse_intake,
    parse_intake,
)
from cipher_lens.planner.llm import LlmClient
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry


@pytest.fixture
def scope_registry() -> ScopeRegistry:
    reg = ScopeRegistry()
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-lab-01",
        name="Staging Lab Scope",
        targets=["10.0.0.0/24", "lab.local"],
        exclusions=["10.0.0.254"],
        allowed_ports=[80, 443, 8080],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
        authorization_reference="AUTH-LAB-2026",
    )
    reg.register(scope)
    return reg


@pytest.fixture
def policy_gate(scope_registry: ScopeRegistry) -> PolicyGate:
    return PolicyGate(registry=scope_registry)


def test_fallback_parse_intake_extracts_ips_and_domains() -> None:
    text = "Please perform security assessment on 10.0.0.5 and lab.local for OWASP Top 10 vulnerabilities."
    req = fallback_parse_intake(text)

    assert "10.0.0.5" in req.targets
    assert "lab.local" in req.targets
    assert req.depth == "standard"
    assert req.is_ambiguous is False


def test_fallback_parse_intake_empty_request_marks_ambiguous() -> None:
    text = "Run a scan please"
    req = fallback_parse_intake(text)
    assert req.is_ambiguous is True
    assert req.clarifying_question is not None


def test_parse_intake_with_mock_llm(
    scope_registry: ScopeRegistry, policy_gate: PolicyGate
) -> None:
    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        return """{
            "targets": ["10.0.0.5"],
            "objectives": ["Identify open ports and discover web flaws"],
            "depth": "standard",
            "constraints": ["Rate limit 5 req/s"],
            "is_ambiguous": false,
            "clarifying_question": null
        }"""

    client = LlmClient(
        primary_key="mock-key",
        raw_completion_fn=mock_backend,
    )

    req, refused = parse_intake(
        user_request="Assess 10.0.0.5",
        llm_client=client,
        gate=policy_gate,
    )

    assert req.targets == ["10.0.0.5"]
    assert len(refused) == 0
    assert req.objectives == ["Identify open ports and discover web flaws"]


def test_parse_intake_refuses_out_of_scope_target(
    scope_registry: ScopeRegistry, policy_gate: PolicyGate
) -> None:
    """Master Plan §9: Targets outside registered scope produce request_refused with reason."""

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        return """{
            "targets": ["10.0.0.5", "8.8.8.8", "10.0.0.254"],
            "objectives": ["Full penetration test"],
            "depth": "thorough",
            "constraints": [],
            "is_ambiguous": false,
            "clarifying_question": null
        }"""

    client = LlmClient(
        primary_key="mock-key",
        raw_completion_fn=mock_backend,
    )

    req, refused = parse_intake(
        user_request="Scan 10.0.0.5, 8.8.8.8 and 10.0.0.254",
        llm_client=client,
        gate=policy_gate,
    )

    # 10.0.0.5 is in-scope
    assert "10.0.0.5" in req.targets

    # 8.8.8.8 is outside CIDR scope; 10.0.0.254 is an explicit exclusion
    assert "8.8.8.8" not in req.targets
    assert "10.0.0.254" not in req.targets

    # Refused list must contain both targets with human-readable rationale
    refused_str = " ".join(refused)
    assert "8.8.8.8" in refused_str
    assert "10.0.0.254" in refused_str

