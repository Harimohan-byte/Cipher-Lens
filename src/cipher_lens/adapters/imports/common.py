"""Common types and helper utilities for import-only adapters."""

import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field

from cipher_lens.models.findings import RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.policy.scope import Scope

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d{1,6}", re.IGNORECASE)


class ImportResult(BaseModel):
    """Result of parsing an imported scan report file."""

    findings: list[RawFinding] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def is_target_in_scope(target: str, scope: Scope | None) -> bool:
    """Deterministic scope check for imported hosts/IPs.

    Returns True if no scope provided (open check) or if target matches
    allowed_targets and does not match exclusions.
    """
    if scope is None:
        return True

    clean = target.strip().lower()
    # Strip protocol if present
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    # Strip path/query if present
    clean = clean.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # Strip port if present
    if ":" in clean and not clean.endswith("]"):  # Not raw IPv6 without port
        clean = clean.split(":", 1)[0]
    clean = clean.strip("[]")

    # Check exclusions first (AGENTS.md Rule 2 / PolicyGate invariant: exclusions beat allows)
    for ex in scope.exclusions:
        ex_clean = ex.strip().lower()
        if "/" in ex_clean:
            try:
                net = ipaddress.ip_network(ex_clean, strict=False)
                tgt_ip = ipaddress.ip_address(clean)
                if tgt_ip in net:
                    return False
            except ValueError:
                pass
        elif clean == ex_clean:
            return False

    # Check allowed_targets
    for al in scope.allowed_targets:
        al_clean = al.strip().lower()
        if "/" in al_clean:
            try:
                net = ipaddress.ip_network(al_clean, strict=False)
                tgt_ip = ipaddress.ip_address(clean)
                if tgt_ip in net:
                    return True
            except ValueError:
                pass
        elif clean == al_clean:
            return True

    return False


def redact_sensitive_text(text: str) -> str:
    """Redacts passwords, tokens, cookies, and authorization headers from text (AGENTS.md Rule 9)."""
    redacted = re.sub(
        r"(Authorization:\s*(?:Bearer|Basic)\s+)[^\r\n]+",
        r"\1<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(Cookie:\s*)[^\r\n]+",
        r"\1<redacted>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(Set-Cookie:\s*)[^\r\n]+",
        r"\1<redacted>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(password|token|secret|api[_-]?key)=([^\s&;]+)",
        r"\1=<redacted>",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted

