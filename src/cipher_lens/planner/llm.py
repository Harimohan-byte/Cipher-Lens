"""LLM provider interface, dual-key failover, structured validation, and throttling (Task A10).

Follows:
- AGENTS.md Rule 5: Validate LLM output with Pydantic (retry once, then fallback).
- AGENTS.md Rule 7: Every LLM call writes a trace event.
- AGENTS.md Rule 9: Secrets configured via environment variables.
- AGENTS.md Rule 13: Never silently fall back to fake data; fallbacks labeled as rule-based.
- Master Plan A10 & §4.2: Dual-key failover, tiered-model routing, prompt-hash caching.
"""

import json
import logging
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from cipher_lens.planner.cache import PromptCache
from cipher_lens.planner.sanitize import sanitize_prompt
from cipher_lens.planner.trace import write_llm_trace

logger = logging.getLogger(__name__)


@dataclass
class LlmResponse[T: BaseModel]:
    """Container for validated LLM completion output and traceability metadata."""

    data: T
    label: Literal["live", "cached", "rule-based"]
    provider: str
    model: str
    latency_ms: int = 0
    attempts: int = 1

    @property
    def source(self) -> Literal["live", "cached", "rule-based"]:
        return self.label


class LlmClient:
    """Enterprise LLM client with dual-key failover, validation retry, and caching."""

    def __init__(
        self,
        provider: str | None = None,
        primary_key: str | None = None,
        primary_model: str | None = None,
        secondary_key: str | None = None,
        secondary_model: str | None = None,
        call_budget: int | None = None,
        cache_dir: Path | str | None = None,
        db_conn: sqlite3.Connection | None = None,
        raw_completion_fn: Callable[[str, str, str], str] | None = None,
    ) -> None:
        self.provider = provider or os.environ.get("LLM_PROVIDER", "gemini").lower()
        self.primary_key = (
            primary_key
            or os.environ.get("GEMINI_API_KEY_PRIMARY")
            or os.environ.get("GEMINI_API_KEY")
        )
        self.primary_model = (
            primary_model
            or os.environ.get("GEMINI_MODEL_PRIMARY")
            or os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
        )
        self.secondary_key = secondary_key or os.environ.get("GEMINI_API_KEY_SECONDARY")
        self.secondary_model = (
            secondary_model
            or os.environ.get("GEMINI_MODEL_SECONDARY", "gemini-3.5-flash-lite")
        )

        env_budget = os.environ.get("LLM_CALL_BUDGET")
        self.call_budget = call_budget or (int(env_budget) if env_budget else 30)

        cache_path = cache_dir or os.environ.get("LLM_CACHE_DIR")
        self.cache = PromptCache(cache_path)
        self.db_conn = db_conn
        self.raw_completion_fn = raw_completion_fn
        self._call_count = 0

    def _execute_raw(
        self, prompt: str, model: str, api_key: str
    ) -> tuple[str, int]:
        """Calls backend with latency tracking."""
        start = time.perf_counter()
        if self.raw_completion_fn:
            result = self.raw_completion_fn(prompt, model, api_key)
        else:
            result = self._call_google_genai(prompt, model, api_key)
        latency_ms = int((time.perf_counter() - start) * 1000)
        return result, latency_ms

    def _call_google_genai(self, prompt: str, model: str, api_key: str) -> str:
        """Invokes official google-genai client requesting structured JSON."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
        )
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=config,
        )
        return response.text or "{}"

    def complete_json[T: BaseModel](
        self,
        system_instruction: str,
        user_prompt: str,
        schema: type[T],
        fallback_factory: Callable[[], T] | None = None,
        assessment_id: str | None = None,
    ) -> LlmResponse[T]:
        """Completes a structured JSON query with validation, retry, and failover.

        Invariants:
        1. Sanitize prompt; cap length; wrap tool output.
        2. Check prompt-hash cache -> if hit, label='cached'.
        3. Check call budget -> if exceeded, label='rule-based'.
        4. Validate with Pydantic -> on failure, retry ONCE with error feedback.
        5. If primary encounters 429/ResourceExhausted, fail over to secondary key.
        6. Every execution writes a trace row into SQLite.
        """
        clean_system = sanitize_prompt(system_instruction)
        clean_user = sanitize_prompt(user_prompt)
        prompt_hash = self.cache.compute_hash(
            clean_system, clean_user, schema.__name__
        )

        # 1. Deterministic Rule-Based Provider Bypass
        if self.provider == "none":
            if fallback_factory is not None:
                data = fallback_factory()
                write_llm_trace(
                    conn=self.db_conn,
                    provider="none",
                    model="deterministic",
                    prompt_hash=prompt_hash,
                    input_summary=clean_user,
                    output=data.model_dump_json(),
                    label="rule-based",
                    outcome="fallback",
                    assessment_id=assessment_id,
                )
                return LlmResponse(
                    data=data,
                    label="rule-based",
                    provider="none",
                    model="deterministic",
                )
            raise ValueError("Provider is 'none' and no fallback_factory provided")

        # 2. Check Prompt Cache
        cached_str = self.cache.get(prompt_hash)
        if cached_str is not None:
            try:
                data = schema.model_validate_json(cached_str)
                write_llm_trace(
                    conn=self.db_conn,
                    provider=self.provider,
                    model=self.primary_model,
                    prompt_hash=prompt_hash,
                    input_summary=clean_user,
                    output=cached_str,
                    label="cached",
                    outcome="cache_hit",
                    assessment_id=assessment_id,
                )
                return LlmResponse(
                    data=data,
                    label="cached",
                    provider=self.provider,
                    model=self.primary_model,
                )
            except (ValidationError, json.JSONDecodeError):
                pass

        # 3. Check Call Budget
        if self._call_count >= self.call_budget:
            logger.warning(
                "LLM call budget exhausted (%d/%d)",
                self._call_count,
                self.call_budget,
            )
            if fallback_factory is not None:
                data = fallback_factory()
                write_llm_trace(
                    conn=self.db_conn,
                    provider=self.provider,
                    model=self.primary_model,
                    prompt_hash=prompt_hash,
                    input_summary=clean_user,
                    output=data.model_dump_json(),
                    label="rule-based",
                    outcome="budget_exhausted",
                    assessment_id=assessment_id,
                )
                return LlmResponse(
                    data=data,
                    label="rule-based",
                    provider=self.provider,
                    model=self.primary_model,
                )
            raise RuntimeError("LLM call budget exhausted")

        # 4. Check API Key
        if not self.primary_key:
            logger.info("No Gemini API key available; using rule-based fallback.")
            if fallback_factory is not None:
                data = fallback_factory()
                write_llm_trace(
                    conn=self.db_conn,
                    provider="none",
                    model="deterministic",
                    prompt_hash=prompt_hash,
                    input_summary=clean_user,
                    output=data.model_dump_json(),
                    label="rule-based",
                    outcome="no_key_fallback",
                    assessment_id=assessment_id,
                )
                return LlmResponse(
                    data=data,
                    label="rule-based",
                    provider="none",
                    model="deterministic",
                )
            raise ValueError(
                "No Gemini API key configured and no fallback_factory provided"
            )

        full_prompt = (
            f"System Instructions:\n{clean_system}\n\nTask Query:\n{clean_user}"
        )

        # Helper to execute with rate-limit failover
        def execute_with_failover(
            p_text: str,
        ) -> tuple[str, str, int]:
            used_model = self.primary_model
            try:
                self._call_count += 1
                res, lat = self._execute_raw(
                    p_text, self.primary_model, self.primary_key  # type: ignore[arg-type]
                )
                return res, used_model, lat
            except Exception as exc:
                err_str = str(exc)
                is_rate_limit = (
                    "429" in err_str
                    or "ResourceExhausted" in err_str
                    or "quota" in err_str.lower()
                )
                if is_rate_limit and self.secondary_key:
                    logger.warning(
                        "Primary key rate-limited; failing over to secondary key (%s)",
                        self.secondary_model,
                    )
                    used_model = self.secondary_model
                    self._call_count += 1
                    res, lat = self._execute_raw(
                        p_text, self.secondary_model, self.secondary_key
                    )
                    return res, used_model, lat
                raise

        # 5. First Attempt
        try:
            raw_text, used_model, latency = execute_with_failover(full_prompt)
            data = schema.model_validate_json(raw_text)
            self.cache.set(prompt_hash, raw_text)
            write_llm_trace(
                conn=self.db_conn,
                provider=self.provider,
                model=used_model,
                prompt_hash=prompt_hash,
                input_summary=clean_user,
                output=raw_text,
                label="live",
                outcome="success",
                latency_ms=latency,
                assessment_id=assessment_id,
            )
            return LlmResponse(
                data=data,
                label="live",
                provider=self.provider,
                model=used_model,
                latency_ms=latency,
                attempts=1,
            )
        except (ValidationError, json.JSONDecodeError) as val_err:
            # 6. Retry Once with Validation Feedback (Rule 5)
            logger.warning(
                "Pydantic validation failed on LLM output: %s. Retrying once with error feedback.",
                val_err,
            )
            write_llm_trace(
                conn=self.db_conn,
                provider=self.provider,
                model=self.primary_model,
                prompt_hash=prompt_hash,
                input_summary=clean_user,
                output=str(val_err),
                label="live",
                outcome="validation_retry",
                assessment_id=assessment_id,
            )
            retry_prompt = (
                f"{full_prompt}\n\n"
                f"[Validation error in previous response: {val_err}. "
                f"Please correct the output to strictly conform to the expected JSON schema.]"
            )
            try:
                retry_text, used_model2, latency2 = execute_with_failover(
                    retry_prompt
                )
                data = schema.model_validate_json(retry_text)
                self.cache.set(prompt_hash, retry_text)
                write_llm_trace(
                    conn=self.db_conn,
                    provider=self.provider,
                    model=used_model2,
                    prompt_hash=prompt_hash,
                    input_summary=retry_prompt,
                    output=retry_text,
                    label="live",
                    outcome="retry_success",
                    latency_ms=latency2,
                    assessment_id=assessment_id,
                )
                return LlmResponse(
                    data=data,
                    label="live",
                    provider=self.provider,
                    model=used_model2,
                    latency_ms=latency2,
                    attempts=2,
                )
            except Exception as retry_err:
                logger.error(
                    "Retry also failed schema validation: %s. Triggering rule-based fallback.",
                    retry_err,
                )
        except Exception as exc:
            logger.error("LLM backend error: %s. Triggering fallback.", exc)

        # 7. Fallback to Rule-Based Factory
        if fallback_factory is not None:
            data = fallback_factory()
            write_llm_trace(
                conn=self.db_conn,
                provider="fallback",
                model="deterministic",
                prompt_hash=prompt_hash,
                input_summary=clean_user,
                output=data.model_dump_json(),
                label="rule-based",
                outcome="fallback",
                assessment_id=assessment_id,
            )
            return LlmResponse(
                data=data,
                label="rule-based",
                provider="fallback",
                model="deterministic",
            )

        raise RuntimeError("LLM query failed and no fallback_factory was provided")
