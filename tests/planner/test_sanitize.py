"""Tests for Prompt Sanitizer and Guardrails (Task A10).

Validates:
- Redaction of Bearer tokens, API keys, passwords, session cookies, private keys
- Wrapping tool output in <tool_output> delimiters (AGENTS.md Rule 5)
- Safe truncation of oversized inputs
- Safety break-it checks ensuring secrets never leak to LLM prompts
"""

import pytest

from cipher_lens.planner.sanitize import (
    redact_secrets,
    sanitize_prompt,
    wrap_tool_output,
)


def test_redact_bearer_tokens() -> None:
    raw = "Request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
    clean = redact_secrets(raw)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in clean
    assert "[REDACTED_TOKEN]" in clean


def test_redact_api_keys() -> None:
    raw = "Scanning target with apiKey=AIzaSyA1234567890abcdef and X-ZAP-API-Key: zap_secret_key_999"
    clean = redact_secrets(raw)
    assert "AIzaSyA1234567890abcdef" not in clean
    assert "zap_secret_key_999" not in clean
    assert "[REDACTED_API_KEY]" in clean


def test_redact_passwords() -> None:
    raw = "Login attempt password=SuperSecretPassword123! and pass: MyAdminPass456"
    clean = redact_secrets(raw)
    assert "SuperSecretPassword123!" not in clean
    assert "MyAdminPass456" not in clean
    assert "[REDACTED_PASSWORD]" in clean


def test_redact_cookies() -> None:
    raw = "Headers: Cookie: PHPSESSID=384759283749283; JSESSIONID=ABCD1234EFGH; user=admin"
    clean = redact_secrets(raw)
    assert "PHPSESSID=384759283749283" not in clean
    assert "JSESSIONID=ABCD1234EFGH" not in clean
    assert "[REDACTED_COOKIE]" in clean


def test_redact_private_keys() -> None:
    raw = """Server banner:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1v8...
-----END RSA PRIVATE KEY-----
SSH-2.0-OpenSSH_8.2p1"""
    clean = redact_secrets(raw)
    assert "MIIEowIBAAKCAQEA0Y1v8" not in clean
    assert "[REDACTED_PRIVATE_KEY]" in clean
    assert "SSH-2.0-OpenSSH_8.2p1" in clean


def test_wrap_tool_output() -> None:
    raw_tool_text = "PORT   STATE SERVICE\n80/tcp open  http Apache 2.4.49"
    wrapped = wrap_tool_output(raw_tool_text)
    assert wrapped.startswith("<tool_output>\n")
    assert wrapped.endswith("\n</tool_output>")
    assert "80/tcp open  http Apache 2.4.49" in wrapped


def test_truncate_long_text() -> None:
    huge_text = "A" * 5000
    sanitized = sanitize_prompt(huge_text, max_length=1000)
    assert len(sanitized) <= 1200
    assert "[TRUNCATED" in sanitized


def test_safety_break_it_sanitizer_removes_secrets() -> None:
    """Safety break-it check: Fails if sensitive auth credentials remain in the text."""
    secret = "secret_auth_token_9999"
    payload = f"GET /api/data HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n"
    sanitized = sanitize_prompt(payload)
    if secret in sanitized:
        pytest.fail("Safety violation: Unredacted secret leaked into sanitized prompt!")
