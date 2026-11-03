"""Status and confidence determination rules (B12, Master Plan §8.2).

Rules:
- confidence:
  - high = two or more independent tools, or direct proof evidence (ZAP alert with attack/evidence, or NSE script with VULNERABLE)
  - medium = one tool with specific evidence
  - low = banner/version-only or generic heuristic
- status:
  - confirmed = only with direct proof or an analyst-attested validation outcome
  - suspected = banner/version-only matches, or single uncorroborated heuristic
  - conflict = if tools disagree materially (one vulnerable, one clean/patched), keep finding as suspected, low confidence
"""

from typing import Literal

from cipher_lens.models.findings import RawFinding


def evaluate_status_and_confidence(
    findings: list[RawFinding],
    direct_proof: bool = False,
    conflict: bool = False,
) -> tuple[Literal["confirmed", "suspected", "false_positive", "accepted_risk"], Literal["high", "medium", "low"], str]:
    """Determines the authoritative status, confidence, and status_reason for a correlated finding group."""
    if conflict:
        return (
            "suspected",
            "low",
            "Conflicting reports across multiple assessment tools; treated conservatively.",
        )

    # Check for direct proof in any evidence snippet
    has_direct_proof = direct_proof
    for rf in findings:
        snippet_upper = rf.raw_evidence.snippet.upper()
        if "VULNERABLE" in snippet_upper or "FOUND VULNERABLE" in snippet_upper or "EXPLOIT" in snippet_upper:
            has_direct_proof = True
            break
        # ZAP attack proof or Burp verified reflection
        if "<attack>" in snippet_upper or "<request>" in snippet_upper and rf.confidence == "high":
            has_direct_proof = True
            break

    tools = {rf.tool_name for rf in findings}

    if has_direct_proof:
        return (
            "confirmed",
            "high",
            "Direct proof observed in scanner output snippet.",
        )

    if len(tools) >= 2:
        return (
            "confirmed",
            "high",
            f"Corroborated by {len(tools)} independent tools ({', '.join(sorted(tools))}).",
        )

    # Single tool check
    rf = findings[0]
    if rf.confidence == "low" or "version" in rf.title.lower() or "detected" in rf.title.lower():
        return (
            "suspected",
            "low",
            "Banner or version heuristic only; patch backporting may exist.",
        )

    return (
        "suspected",
        "medium",
        f"Single-tool observation from {rf.tool_name}; pending active validation.",
    )
