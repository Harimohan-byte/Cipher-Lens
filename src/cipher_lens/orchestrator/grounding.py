"""Grounding validation module (B16).

Invariants:
1. Every CVE ID mentioned in LLM-generated report text must exist in assessment findings.
2. Every VAPT-xxxx finding ID mentioned must exist in assessment findings.
3. Claimed finding counts and severities must match actual computed counts.
4. Failures force regeneration or fallback to deterministic templates.
"""

import re

from pydantic import BaseModel, Field

from cipher_lens.adapters.imports.common import CVE_PATTERN
from cipher_lens.models.findings import Finding

FINDING_ID_PATTERN = re.compile(r"\bVAPT-\d{4}(?!\d)", re.IGNORECASE)


class GroundingResult(BaseModel):
    """Outcome of validating LLM-generated text against database findings."""

    is_valid: bool
    hallucinated_cves: list[str] = Field(default_factory=list)
    hallucinated_finding_ids: list[str] = Field(default_factory=list)
    error_message: str = ""


class GroundingValidator:
    """Verifies that generated text is strictly grounded in observed and enriched findings."""

    def validate(self, text: str, findings: list[Finding]) -> GroundingResult:
        """Validates that all CVE and finding identifiers exist in known findings."""
        known_cves = {cve.upper() for f in findings for cve in f.cve}
        known_ids = {f.id.upper() for f in findings}

        # Extract tokens from text
        mentioned_cves = {m.upper() for m in CVE_PATTERN.findall(text)}
        mentioned_ids = {m.upper() for m in FINDING_ID_PATTERN.findall(text)}

        hallucinated_cves = sorted(mentioned_cves - known_cves)
        hallucinated_ids = sorted(mentioned_ids - known_ids)

        if hallucinated_cves or hallucinated_ids:
            errors: list[str] = []
            if hallucinated_cves:
                errors.append(f"Unsupported CVEs detected: {', '.join(hallucinated_cves)}")
            if hallucinated_ids:
                errors.append(f"Unknown Finding IDs referenced: {', '.join(hallucinated_ids)}")

            return GroundingResult(
                is_valid=False,
                hallucinated_cves=hallucinated_cves,
                hallucinated_finding_ids=hallucinated_ids,
                error_message="; ".join(errors),
            )

        return GroundingResult(is_valid=True)

    def validate_counts(
        self,
        findings: list[Finding],
        claimed_critical: int | None = None,
        claimed_high: int | None = None,
        claimed_medium: int | None = None,
        claimed_low: int | None = None,
    ) -> GroundingResult:
        """Validates claimed counts against actual findings counts."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.tool_severity.lower()
            if sev in counts:
                counts[sev] += 1

        claimed = {
            "critical": claimed_critical,
            "high": claimed_high,
            "medium": claimed_medium,
            "low": claimed_low,
        }

        mismatches: list[str] = []
        for sev, claim in claimed.items():
            if claim is not None and claim != counts[sev]:
                mismatches.append(f"{sev}: claimed {claim}, actual {counts[sev]}")

        if mismatches:
            return GroundingResult(
                is_valid=False,
                error_message=f"Count mismatch in text: {'; '.join(mismatches)}",
            )

        return GroundingResult(is_valid=True)

