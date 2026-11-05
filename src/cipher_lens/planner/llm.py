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
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from cipher_lens.config import get_settings
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


def _clean_schema_for_gemini(schema: Any) -> Any:
    """Sanitizes JSON schema for Gemini Developer API (non-Vertex AI).

    In Gemini Developer API mode (client.vertexai=False), google.genai's client-side
    transformer (_raise_for_unsupported_mldev_properties) raises ValueError if
    'additionalProperties' or 'additional_properties' is present anywhere in the schema.
    Stripping these keys allows structured JSON generation to succeed seamlessly with
    Google AI Studio Developer API keys.
    """
    if schema is None:
        return None

    if isinstance(schema, type) and issubclass(schema, BaseModel):
        raw_schema = schema.model_json_schema()
    elif isinstance(schema, BaseModel):
        raw_schema = schema.model_json_schema()
    elif isinstance(schema, dict):
        raw_schema = dict(schema)
    else:
        return schema

    def _strip_additional_props(val: Any) -> Any:
        if isinstance(val, dict):
            return {
                k: _strip_additional_props(v)
                for k, v in val.items()
                if k not in ("additionalProperties", "additional_properties")
            }
        if isinstance(val, list):
            return [_strip_additional_props(item) for item in val]
        return val

    return _strip_additional_props(raw_schema)


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
        max_output_tokens: int | None = None,
        cache_dir: Path | str | None = None,
        db_conn: sqlite3.Connection | None = None,
        raw_completion_fn: Callable[[str, str, str], str] | None = None,
    ) -> None:
        settings = get_settings()
        # DECISION: provider="mock" is constructor-only for unit tests.
        # At runtime, provider defaults from Settings (which disallows "mock" in env vars).
        if provider is not None:
            prov = provider.lower().strip()
            if prov not in ("gemini", "none", "offline", "mock"):
                raise ValueError(f"Invalid provider: {provider}")
            self.provider = prov
        else:
            self.provider = settings.llm_provider

        if self.provider == "mock" and raw_completion_fn is None:
            raise ValueError("Provider is 'mock' but no raw_completion_fn was provided.")

        self.primary_key = primary_key or settings.gemini_api_key
        self.primary_model = primary_model or settings.gemini_model
        self.secondary_key = secondary_key or settings.gemini_api_key_secondary
        self.secondary_model = secondary_model or settings.gemini_model_secondary
        self.call_budget = call_budget or settings.llm_call_budget
        self.max_output_tokens = max_output_tokens or settings.llm_max_output_tokens

        cache_path = cache_dir or settings.llm_cache_dir
        self.cache = PromptCache(cache_path)
        self.db_conn = db_conn
        self.raw_completion_fn = raw_completion_fn
        self._call_count = 0
        self._genai_client: Any = None

    def _get_genai_client(self, api_key: str) -> Any:
        """Returns reusable google-genai client instance (ERR-10)."""
        if self._genai_client is None:
            from google import genai
            self._genai_client = genai.Client(api_key=api_key)
        return self._genai_client

    def _get_call_count(self) -> int:
        """Returns total call count for today from SQLite or in-memory count (ERR-25)."""
        if self.db_conn is not None:
            try:
                period_key = datetime.now(UTC).strftime("%Y-%m-%d")
                cursor = self.db_conn.cursor()
                cursor.execute(
                    "SELECT call_count FROM llm_budget WHERE period_key = ?",
                    (period_key,),
                )
                row = cursor.fetchone()
                if row is not None:
                    return int(row[0])
            except Exception:
                pass
        return self._call_count

    def _increment_call_count(self) -> int:
        """Increments and persists the call count in SQLite and in-memory (ERR-25)."""
        self._call_count += 1
        if self.db_conn is not None:
            try:
                period_key = datetime.now(UTC).strftime("%Y-%m-%d")
                now_str = datetime.now(UTC).isoformat()
                cursor = self.db_conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO llm_budget (period_key, call_count, updated_at)
                    VALUES (?, 1, ?)
                    ON CONFLICT(period_key) DO UPDATE SET
                    call_count = call_count + 1,
                    updated_at = excluded.updated_at
                    """,
                    (period_key, now_str),
                )
                self.db_conn.commit()
            except Exception as exc:
                logger.debug("Failed to persist call budget to SQLite: %s", exc)
        return self._call_count

    def _execute_raw(
        self,
        prompt: str,
        model: str,
        api_key: str,
        user_prompt: str | None = None,
        system_instruction: str | None = None,
        schema: Any = None,
    ) -> tuple[str, int]:
        """Calls backend with latency tracking."""
        start = time.perf_counter()
        if self.raw_completion_fn:
            result = self.raw_completion_fn(prompt, model, api_key)
        else:
            result = self._call_google_genai(
                user_prompt=user_prompt or prompt,
                model=model,
                api_key=api_key,
                system_instruction=system_instruction,
                schema=schema,
            )
        latency_ms = int((time.perf_counter() - start) * 1000)
        return result, latency_ms

    def _call_google_genai(
        self,
        user_prompt: str,
        model: str,
        api_key: str,
        system_instruction: str | None = None,
        schema: Any = None,
    ) -> str:
        """Invokes official google-genai client requesting structured JSON (ERR-10)."""
        from google.genai import types

        client = self._get_genai_client(api_key)
        kwargs: dict[str, Any] = {
            "response_mime_type": "application/json",
            "max_output_tokens": self.max_output_tokens,
        }
        if system_instruction is not None:
            kwargs["system_instruction"] = system_instruction
        if schema is not None:
            kwargs["response_schema"] = _clean_schema_for_gemini(schema)

        config = types.GenerateContentConfig(**kwargs)
        response = client.models.generate_content(
            model=model,
            contents=user_prompt,
            config=config,
        )

        # Validate finish reason: treat non-STOP (e.g. MAX_TOKENS, SAFETY) as error (ERR-10)
        if response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            finish_str = str(finish_reason).upper()
            if (
                finish_reason is not None
                and "STOP" not in finish_str
                and finish_str != "FINISH_REASON_UNSPECIFIED"
            ):
                raise ValueError(
                    f"LLM output incomplete or blocked by safety filter: finish_reason={finish_reason}"
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
        if self.provider in ("none", "offline"):
            if fallback_factory is not None:
                data = fallback_factory()
                write_llm_trace(
                    conn=self.db_conn,
                    provider=self.provider,
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

        # 3. Check Call Budget (ERR-25)
        current_calls = self._get_call_count()
        if current_calls >= self.call_budget:
            logger.warning(
                "LLM call budget exhausted (%d/%d)",
                current_calls,
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

        # Helper to execute with single-key exponential backoff retry and secondary key failover
        def execute_with_retry(
            p_text: str,
            u_text: str,
            s_text: str,
        ) -> tuple[str, str, int]:
            attempts_plan: list[tuple[str, str, str]] = [
                (self.primary_key, self.primary_model, "primary"),
            ]
            if self.secondary_key and self.secondary_key.strip() != (self.primary_key or "").strip():
                attempts_plan.append((self.secondary_key, self.secondary_model, "secondary"))
            elif self.secondary_model and self.secondary_model != self.primary_model:
                attempts_plan.append((self.primary_key, self.secondary_model, "primary_secondary_model"))

            # If gemini-3.5-flash is not yet in attempts_plan, add it as high-availability capacity failover
            if "gemini-3.5-flash" not in [m for _, m, _ in attempts_plan]:
                attempts_plan.append((self.primary_key, "gemini-3.5-flash", "high_availability_fallback"))

            last_exc: Exception | None = None
            for current_key, current_model, key_label in attempts_plan:
                max_retries = 1
                delay = 1.0

                for attempt in range(max_retries + 1):
                    try:
                        self._increment_call_count()
                        res, lat = self._execute_raw(
                            prompt=p_text,
                            model=current_model,
                            api_key=current_key,
                            user_prompt=u_text,
                            system_instruction=s_text,
                            schema=schema,  # type: ignore[arg-type]
                        )
                        return res, current_model, lat
                    except Exception as exc:
                        last_exc = exc
                        is_transient = False
                        try:
                            from google.genai import errors
                            if isinstance(exc, errors.APIError) and exc.code in (429, 500, 503):
                                is_transient = True
                        except ImportError:
                            pass

                        if not is_transient:
                            err_str = str(exc)
                            if any(tok in err_str for tok in ("429", "500", "503", "ResourceExhausted", "quota", "UNAVAILABLE", "high demand")):
                                is_transient = True

                        if is_transient and attempt < max_retries:
                            logger.warning(
                                "Gemini API transient issue (%s) on %s model %s. Retrying in %.1fs (attempt %d/%d)...",
                                exc,
                                key_label,
                                current_model,
                                delay,
                                attempt + 1,
                                max_retries,
                            )
                            time.sleep(delay)
                            delay *= 2.0
                            continue

                        logger.warning(
                            "Attempt failed on %s (%s): %s. Moving to next failover candidate if available.",
                            key_label,
                            current_model,
                            exc,
                        )
                        break

            raise last_exc or RuntimeError("Exhausted all attempts in execute_with_retry")

        # 5. First Attempt
        try:
            raw_text, used_model, latency = execute_with_retry(
                p_text=full_prompt,
                u_text=clean_user,
                s_text=clean_system,
            )
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
            retry_user = (
                f"{clean_user}\n\n"
                f"[Validation error in previous response: {val_err}. "
                f"Please correct the output to strictly conform to the expected JSON schema.]"
            )
            retry_prompt = (
                f"{full_prompt}\n\n"
                f"[Validation error in previous response: {val_err}. "
                f"Please correct the output to strictly conform to the expected JSON schema.]"
            )
            try:
                retry_text, used_model2, latency2 = execute_with_retry(
                    p_text=retry_prompt,
                    u_text=retry_user,
                    s_text=clean_system,
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
