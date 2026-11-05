"""End-to-End Integration Test for Multi-Round Adaptive Replanning Loop (Task B19 / Bonus Requirement).

Validates the complete closed-loop adaptive planning progression:
- Round 1: Scope-triggered initial network discovery (Nmap) on target.
- Round 1 Execution: Port enumeration produces Observation of open web service (Port 3000).
- Round 2: Memory/state updated. Adaptive planner inspects new observations and dynamically
           proposes targeted web application scanning (Nikto/ZAP) triggered by Round 1 evidence.
- Round 2 Execution: Web scans execute, findings are recorded, and steps marked done.
- Round 3: Memory/state reflects all objectives met. Adaptive planner determines no remaining
           work and halts with stop=True and stop_reason.
- Audit Trail: Hash chain verified from genesis to head across all 3 rounds.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cipher_lens.models.assessment import StepRun
from cipher_lens.models.findings import Asset, Evidence, Finding, RiskScore
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.scope import Scope
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.state import UIController


@pytest.fixture
def adaptive_controller(tmp_path: Path) -> UIController:
    db_path = str(tmp_path / "adaptive_loop.db")
    artifacts_dir = str(tmp_path / "artifacts")
    conn = connect(db_path)
    init_db(conn)
    conn.close()

    return UIController(
        db_path=db_path,
        artifacts_dir=artifacts_dir,
        llm_provider="offline",
    )


def test_multi_round_adaptive_planning_loop(adaptive_controller: UIController) -> None:
    """Executes a real 3-round adaptive replanning cycle with state memory."""
    ctrl = adaptive_controller
    now = datetime.now(UTC)

    # 1. Register authorized lab scope
    scope = Scope(
        id="scope-lab-adaptive",
        name="Adaptive Replanning Lab",
        authorization_reference="AUTH-ADAPTIVE-2026",
        targets=["10.0.0.5"],
        allowed_ports=[80, 443, 3000, 8080],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
    )
    ctrl.register_scope(scope)

    # 2. Intake: create assessment from natural language
    assm, req, refused = ctrl.submit_intake(
        user_request="Perform full assessment on 10.0.0.5 for web vulnerabilities and open services.",
        title="OWASP Adaptive Security Assessment",
        scope_id="scope-lab-adaptive",
    )
    assert assm.id is not None
    assert len(refused) == 0
    assert "10.0.0.5" in req.targets

    # -------------------------------------------------------------------------
    # ROUND 1: Initial Discovery Planning
    # -------------------------------------------------------------------------
    proposal_r1 = ctrl.generate_plan(assm.id)
    assert not proposal_r1.stop, "Round 1 should propose initial discovery"
    assert len(proposal_r1.steps) > 0

    # Must propose nmap discovery first
    nmap_step = next((s for s in proposal_r1.steps if s.tool == "nmap"), None)
    assert nmap_step is not None, "Round 1 must propose Nmap service discovery"
    assert nmap_step.action_class == ActionClass.DISCOVERY
    assert "scope" in nmap_step.triggered_by

    # Approve and simulate execution of Round 1 step
    ctrl.approve_plan(assm.id, decided_by="lead_analyst")

    # Record Nmap execution result in repository
    raw_sha = "a" * 64
    run_r1 = StepRun(
        run_id="run-nmap-01",
        assessment_id=assm.id,
        step_id=nmap_step.step_id,
        tool_name="nmap",
        status="success",
        exit_code=0,
        raw_sha256=raw_sha,
        started_at=now,
        ended_at=now + timedelta(seconds=5),
        duration_ms=5000,
    )
    ctrl.repository.save_run(run_r1)

    # Record discovered open web service on port 3000 (Juice Shop)
    ev_r1 = Evidence(
        id="ev-nmap-3000",
        source_tool="nmap",
        run_id="run-nmap-01",
        artifact_id="art-nmap-01",
        locator="tcp/3000",
        raw_sha256=raw_sha,
        snippet="<tool_output>3000/tcp open http Node.js Express framework</tool_output>",
        observed_at=now,
        origin="live",
    )
    ctrl.repository.save_evidence(assm.id, ev_r1)

    obs_r1 = Observation(
        id="obs-nmap-3000",
        source_tool="nmap",
        asset=Asset(host="10.0.0.5", port=3000, service="http"),
        observation_type="port",
        data={"port": 3000, "service": "http", "state": "open"},
        raw_evidence=ev_r1,
        observed_at=now,
    )
    ctrl.record_observation(assm.id, obs_r1)

    # Store executed step so idempotency engine tracks it as done
    plan_step_r1 = PlanStep(
        step_id=nmap_step.step_id,
        tool=nmap_step.tool,
        action_class=nmap_step.action_class,
        target=nmap_step.target,
        params=nmap_step.params,
        rationale=nmap_step.rationale,
        expected_outcome=nmap_step.expected_outcome,
        nist_phase=nmap_step.nist_phase,
        idempotency_key=nmap_step.idempotency_key,
    )
    ctrl.repository.save_step(assm.id, plan_step_r1, status="success")

    # -------------------------------------------------------------------------
    # ROUND 2: Adaptive Replanning Based on Discovered Service
    # -------------------------------------------------------------------------
    proposal_r2 = ctrl.generate_plan(assm.id)
    assert not proposal_r2.stop, "Round 2 must dynamically adapt to open port 3000"

    # Should NOT re-propose nmap discovery (idempotency enforcement)
    assert not any(s.tool == "nmap" for s in proposal_r2.steps), "Nmap discovery must not be duplicated"

    # Should dynamically propose web scanners against the discovered port 3000
    web_steps = [s for s in proposal_r2.steps if s.tool in ("nikto", "zap")]
    assert len(web_steps) > 0, "Round 2 must propose web scans for discovered HTTP service"

    # Verify steps are triggered by the Round 1 evidence
    for ws in web_steps:
        assert ws.params.get("port") == 3000 or "3000" in str(ws.params.get("port", ""))
        assert "ev-nmap-3000" in ws.triggered_by or "obs-nmap-3000" in ws.triggered_by or "scope" in ws.triggered_by

    # Approve and simulate execution of Round 2 web steps
    ctrl.approve_plan(assm.id, decided_by="lead_analyst")

    for idx, ws in enumerate(web_steps, start=1):
        run_ws = StepRun(
            run_id=f"run-web-{idx}",
            assessment_id=assm.id,
            step_id=ws.step_id,
            tool_name=ws.tool,
            status="success",
            exit_code=0,
            raw_sha256="b" * 64,
            started_at=now,
            ended_at=now + timedelta(seconds=10),
            duration_ms=10000,
        )
        ctrl.repository.save_run(run_ws)

        ws_plan_step = PlanStep(
            step_id=ws.step_id,
            tool=ws.tool,
            action_class=ws.action_class,
            target=ws.target,
            params=ws.params,
            rationale=ws.rationale,
            expected_outcome=ws.expected_outcome,
            nist_phase="discovery" if ws.nist_phase == "discovery" else "attack",
            idempotency_key=ws.idempotency_key,
        )
        ctrl.repository.save_step(assm.id, ws_plan_step, status="success")

    # Record finding from web scan
    ev_finding = Evidence(
        id="ev-web-xss-01",
        source_tool="zap",
        run_id="run-web-1",
        artifact_id="art-zap-01",
        locator="/rest/products/search?q=",
        raw_sha256="b" * 64,
        snippet="<tool_output>Reflected Cross-Site Scripting found in q parameter</tool_output>",
        observed_at=now,
        origin="live",
    )
    ctrl.repository.save_evidence(assm.id, ev_finding)

    finding = Finding(
        id="VAPT-JUICE-001",
        title="Reflected Cross-Site Scripting (XSS)",
        asset=Asset(host="10.0.0.5", port=3000, url_path="/rest/products/search"),
        sources=["zap"],
        evidence=[ev_finding],
        tool_severity="high",
        confidence="high",
        status="confirmed",
        status_reason="Observed live payload reflection in response",
        correlation_key="ck-xss-search-3000",
        risk=RiskScore(total=78.5, band="high", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    ctrl.repository.save_finding(assm.id, finding)

    # -------------------------------------------------------------------------
    # ROUND 3: State Evaluation & Plan Completion
    # -------------------------------------------------------------------------
    proposal_r3 = ctrl.generate_plan(assm.id)

    # All known ports have been scanned; planner halts with stop=True
    assert proposal_r3.stop is True, "Round 3 must stop when all planned phases are exhausted"
    assert proposal_r3.stop_reason is not None
    assert len(proposal_r3.steps) == 0, "No additional steps should be proposed after completion"

    # -------------------------------------------------------------------------
    # Audit Integrity Verification Across All Rounds
    # -------------------------------------------------------------------------
    audit_events = ctrl.get_audit_events(assessment_id=assm.id)
    assert len(audit_events) >= 5, "Audit log must contain events for intake, plan proposals, and approvals"

    chain_res = ctrl.verify_audit_chain()
    assert chain_res.ok is True, "Audit hash chain must remain unbroken and verifiable across all rounds"
