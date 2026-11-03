"""Natural language intake parsing and scope verification (Task A11).

Invariants:
- AGENTS.md Rule 2: Every action goes through policy authorization. Out-of-scope targets are refused.
- AGENTS.md Rule 5: LLM output is untrusted input, validated with Pydantic with fallback to regex.
- Master Plan §9: Targets outside registered scope produce request_refused with reason.
"""

import ipaddress
import re

from cipher_lens.planner.llm import LlmClient
from cipher_lens.planner.models import AssessmentRequest
from cipher_lens.policy.gate import PolicyGate

_INTAKE_SYSTEM_PROMPT = """You are the intake parser for an authorized cybersecurity assessment assistant.
Extract the target hosts/IPs, testing objectives, desired depth, and constraints from the user's request.
Return JSON matching the AssessmentRequest schema only.
If the user specifies no clear target host, IP, or network range, set is_ambiguous=true and provide a helpful clarifying question.
Never invent targets, ports, or authorization references not present in the user request."""

_IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?\b"
)
_DOMAIN_REGEX = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)
_EXCLUDED_EXTENSIONS = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".pdf", ".html", ".sh"}


def fallback_parse_intake(text: str) -> AssessmentRequest:
    """Deterministic regex extraction of assessment targets and parameters when LLM is unavailable."""
    targets: list[str] = []

    # 1. Extract valid IPv4 / CIDRs
    for match in _IP_REGEX.findall(text):
        try:
            base_ip = match.split("/")[0]
            ipaddress.ip_address(base_ip)
            if match not in targets:
                targets.append(match)
        except ValueError:
            continue

    # 2. Extract domain names / hostnames
    for match in _DOMAIN_REGEX.findall(text):
        lower = match.lower()
        if any(lower.endswith(ext) for ext in _EXCLUDED_EXTENSIONS):
            continue
        # Avoid re-adding IP addresses matched as numbers.numbers
        if _IP_REGEX.fullmatch(match):
            continue
        if match not in targets:
            targets.append(match)

    # 3. Determine depth
    lower_text = text.lower()
    if any(k in lower_text for k in ("quick", "fast", "light", "brief")):
        depth = "quick"
    elif any(k in lower_text for k in ("thorough", "deep", "full", "comprehensive", "extensive")):
        depth = "thorough"
    else:
        depth = "standard"

    # 4. Objectives extraction
    objectives: list[str] = []
    if "owasp" in lower_text:
        objectives.append("OWASP Top 10 security assessment")
    if "vulnerabilit" in lower_text:
        objectives.append("Vulnerability discovery and service auditing")
    if "port" in lower_text:
        objectives.append("Network port discovery")
    if not objectives:
        objectives.append("General security assessment and service discovery")

    # 5. Check ambiguity
    if not targets:
        return AssessmentRequest(
            targets=[],
            objectives=objectives,
            depth=depth,
            constraints=[],
            is_ambiguous=True,
            clarifying_question="Please specify target IP addresses, CIDR ranges, or domain names to assess.",
        )

    return AssessmentRequest(
        targets=targets,
        objectives=objectives,
        depth=depth,
        constraints=[],
        is_ambiguous=False,
        clarifying_question=None,
    )


def parse_intake(
    user_request: str,
    llm_client: LlmClient | None = None,
    gate: PolicyGate | None = None,
    assessment_id: str | None = None,
) -> tuple[AssessmentRequest, list[str]]:
    """Parses user intake into structured AssessmentRequest and authorizes targets with PolicyGate."""
    req: AssessmentRequest | None = None

    if llm_client is not None and getattr(llm_client, "provider", None) != "none":
        try:
            response = llm_client.complete_json(
                system_instruction=_INTAKE_SYSTEM_PROMPT,
                user_prompt=user_request,
                schema=AssessmentRequest,
                fallback_factory=lambda: fallback_parse_intake(user_request),
                assessment_id=assessment_id,
            )
            req = response.data
        except Exception:
            req = fallback_parse_intake(user_request)
    else:
        req = fallback_parse_intake(user_request)

    refused: list[str] = []
    if gate is not None:
        authorized_targets: list[str] = []
        for target in req.targets:
            decision = gate.is_target_in_scope(target)
            if decision.allowed:
                authorized_targets.append(target)
            else:
                reason_msg = f"Target '{target}' refused: {decision.reason}"
                refused.append(reason_msg)
                if gate.audit_log:
                    gate.audit_log.append(
                        actor="intake",
                        event_type="scope_refusal",
                        payload={"target": target, "reason": decision.reason, "rule_id": decision.rule_id},
                        assessment_id=assessment_id,
                    )
        req.targets = authorized_targets

    return req, refused
