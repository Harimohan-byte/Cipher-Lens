"""SQLite-backed LLM call tracing (AGENTS.md Rule 7, Task A10)."""

import sqlite3
from datetime import UTC, datetime


def write_llm_trace(
    conn: sqlite3.Connection | None,
    provider: str,
    model: str,
    prompt_hash: str,
    input_summary: str,
    output: str,
    label: str,
    outcome: str,
    assessment_id: str | None = None,
    tokens_prompt: int | None = None,
    tokens_completion: int | None = None,
    latency_ms: int | None = None,
) -> None:
    """Records an LLM call trace event into SQLite.

    Every LLM call (live, cached, retry, or rule-based fallback) must write a trace.
    """
    if conn is None:
        return

    now = datetime.now(UTC).isoformat()
    stmt = """
    INSERT INTO llm_traces (
        ts, assessment_id, provider, model, prompt_hash,
        input_summary, output, label, tokens_prompt,
        tokens_completion, latency_ms, outcome
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    conn.execute(
        stmt,
        (
            now,
            assessment_id,
            provider,
            model,
            prompt_hash,
            input_summary[:500],
            output[:4000],
            label,
            tokens_prompt,
            tokens_completion,
            latency_ms,
            outcome,
        ),
    )
