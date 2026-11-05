"""Deterministic rule-based fallback planner (Task A11, Master Plan §9).

Provides offline planning and fallback when LLM quota is exhausted or provider is 'none'.
Progression state machine:
1. Nmap discovery first (ports and services)
2. Open web port -> Nikto and ZAP spider/passive scan
3. Nothing new remaining -> stop=True with stop_reason
"""

from cipher_lens.models.plan import ActionClass
from cipher_lens.planner.models import PlanProposal, ProposedStep, StateSummary

_WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9443}


def rule_based_plan(state: StateSummary) -> PlanProposal:
    """Produces a deterministic, policy-compliant plan based on current state observations."""
    allowed_tools = {t.lower() for t in state.allowed_tools}
    done = set(state.done_steps)
    steps: list[ProposedStep] = []

    # Phase 1: Initial network discovery with Nmap
    nmap_key = f"nmap:{state.scope_target}:discovery"
    if "nmap" in allowed_tools and nmap_key not in done:
        ports_str = ",".join(str(p) for p in sorted(state.allowed_ports)) if state.allowed_ports else "80,443"
        steps.append(
            ProposedStep(
                step_id="step-rule-nmap-1",
                tool="nmap",
                target=state.scope_target,
                params={"ports": ports_str},
                rationale="Initial network service discovery and port scan",
                triggered_by=["scope"],
                expected_outcome="Enumerate open ports and identify active services",
                nist_phase="discovery",
                action_class=ActionClass.DISCOVERY,
                idempotency_key=nmap_key,
            )
        )
        return PlanProposal(
            steps=steps,
            inferences=[],
            stop=False,
            stop_reason=None,
            planner_source="rule-based",
        )

    # Phase 2: Web application scanning for discovered open web ports
    discovered_web_ports: list[tuple[int, str]] = []
    for obs in state.observations:
        port = obs.asset.port or (obs.data.get("port") if isinstance(obs.data, dict) else None)
        service = (obs.asset.service or (obs.data.get("service") if isinstance(obs.data, dict) else "")).lower()
        ev_id = obs.raw_evidence.id if obs.raw_evidence and obs.raw_evidence.id in state.evidence_ids else "scope"

        if port and (port in _WEB_PORTS or "http" in service):
            try:
                p_int = int(port)
                discovered_web_ports.append((p_int, ev_id))
            except (ValueError, TypeError):
                continue

    for f in state.findings:
        port = f.asset.port
        service = (f.asset.service or "").lower()
        ev_id = f.evidence[0].id if f.evidence and f.evidence[0].id in state.evidence_ids else "scope"
        if port and (port in _WEB_PORTS or "http" in service):
            try:
                p_int = int(port)
                discovered_web_ports.append((p_int, ev_id))
            except (ValueError, TypeError):
                continue

    # Deduplicate discovered web ports
    seen_ports: set[int] = set()
    for port, ev_id in discovered_web_ports:
        if port in seen_ports:
            continue
        seen_ports.add(port)

        nikto_key = f"nikto:{state.scope_target}:{port}:scan"
        if "nikto" in allowed_tools and nikto_key not in done:
            steps.append(
                ProposedStep(
                    step_id=f"step-rule-nikto-{port}",
                    tool="nikto",
                    target=state.scope_target,
                    params={"port": port},
                    rationale=f"Web server vulnerability scan on port {port}",
                    triggered_by=[ev_id],
                    expected_outcome="Detect web server misconfigurations and outdated components",
                    nist_phase="scan",
                    action_class=ActionClass.SCAN,
                    idempotency_key=nikto_key,
                )
            )

        zap_key = f"zap:{state.scope_target}:{port}:scan"
        if "zap" in allowed_tools and zap_key not in done:
            steps.append(
                ProposedStep(
                    step_id=f"step-rule-zap-{port}",
                    tool="zap",
                    target=state.scope_target,
                    params={"port": port, "mode": "spider"},
                    rationale=f"Web application baseline spider and passive scan on port {port}",
                    triggered_by=[ev_id],
                    expected_outcome="Map application structure and discover passive security issues",
                    nist_phase="scan",
                    action_class=ActionClass.SCAN,
                    idempotency_key=zap_key,
                )
            )

    if steps:
        return PlanProposal(
            steps=steps,
            inferences=[],
            stop=False,
            stop_reason=None,
            planner_source="rule-based",
        )

    # Phase 3: All planned phases completed
    return PlanProposal(
        steps=[],
        inferences=[],
        stop=True,
        stop_reason="All assessment phases completed.",
        planner_source="rule-based",
    )
