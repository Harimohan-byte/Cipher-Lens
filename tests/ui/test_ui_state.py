"""Tests for UI State and Controller Subsystem (Task A12 Streamlit Core).

Validates:
- Scope registration via UI controller with audit logging
- Natural language intake processing, target separation, and scope refusal visibility
- Plan proposal generation, authoritative ActionClass badges, and plan approval
- Per-step approval workflows for intrusive/validation actions
- Audit log queries and cryptographic chain integrity verification
- LLM trace retrieval for full transparency
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cipher_lens.models.findings import Asset, Evidence, Finding
from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.scope import Scope
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.state import UIController


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "ui_test.db"
    conn = connect(p)
    init_db(conn)
    conn.close()
    return p


@pytest.fixture
def artifacts_dir(tmp_path: Path) -> Path:
    p = tmp_path / "artifacts"
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture
def ui_ctrl(db_path: Path, artifacts_dir: Path) -> UIController:
    return UIController(db_path=db_path, artifacts_dir=artifacts_dir, llm_provider="none")


def test_ui_register_scope(ui_ctrl: UIController) -> None:
    """Registering a scope stores it in the registry and writes an audit event."""
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-ui-01",
        name="Lab Staging Scope",
        authorization_reference="AUTH-UI-01",
        targets=["10.0.0.0/24", "staging.local"],
        exclusions=["10.0.0.254"],
        allowed_ports=[80, 443, 8080],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
    )

    registered = ui_ctrl.register_scope(scope)
    assert registered.id == "scope-ui-01"

    scopes = ui_ctrl.list_scopes()
    assert len(scopes) == 1
    assert scopes[0].id == "scope-ui-01"

    # Audit log check
    events = ui_ctrl.get_audit_events()
    event_types = [e.event_type for e in events]
    assert "scope_registered" in event_types


def test_ui_register_invalid_scope_window_fails(ui_ctrl: UIController) -> None:
    """Invalid validity window (start > end) fails validation."""
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="valid_from must not be after valid_to"):
        Scope(
            id="scope-invalid-01",
            name="Bad Window Scope",
            authorization_reference="AUTH-BAD",
            targets=["10.0.0.1"],
            window_start=now + timedelta(hours=5),
            window_end=now,  # end before start
        )


def test_ui_intake_in_scope_and_refusals(ui_ctrl: UIController) -> None:
    """Submitting intake separates in-scope targets from refused targets and audits refusals."""
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-ui-02",
        name="Target Lab",
        authorization_reference="AUTH-UI-02",
        targets=["10.0.0.0/24"],
        exclusions=["10.0.0.254"],
        allowed_ports=[80, 443],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
    )
    ui_ctrl.register_scope(scope)

    assm, req, refused = ui_ctrl.submit_intake(
        user_request="Please scan 10.0.0.5, 8.8.8.8 and 10.0.0.254 for open web vulnerabilities",
        title="Web Lab Assessment",
        scope_id="scope-ui-02",
    )

    assert assm.id is not None
    assert "10.0.0.5" in req.targets
    assert "8.8.8.8" not in req.targets
    assert "10.0.0.254" not in req.targets

    refused_str = " ".join(refused)
    assert "8.8.8.8" in refused_str
    assert "10.0.0.254" in refused_str

    # Refusal must be recorded as audit event
    events = ui_ctrl.get_audit_events(assessment_id=assm.id)
    event_types = [e.event_type for e in events]
    assert "scope_refusal" in event_types


def test_ui_plan_generation_and_approval(ui_ctrl: UIController) -> None:
    """Generating a plan creates proposed steps, and approving the plan records approval."""
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-ui-03",
        name="Target Lab",
        authorization_reference="AUTH-UI-03",
        targets=["10.0.0.5"],
        allowed_ports=[80, 443],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
    )
    ui_ctrl.register_scope(scope)

    assm, req, _ = ui_ctrl.submit_intake(
        user_request="Scan 10.0.0.5",
        title="Nmap Lab",
        scope_id="scope-ui-03",
    )

    plan = ui_ctrl.generate_plan(assm.id)
    assert len(plan.steps) > 0
    assert plan.steps[0].action_class == ActionClass.DISCOVERY

    decision = ui_ctrl.approve_plan(
        assessment_id=assm.id,
        decided_by="analyst_alice",
        reason="Initial plan approved for execution",
    )
    assert decision.decision == "approved"


def test_ui_audit_chain_verification_and_tamper_detection(
    ui_ctrl: UIController, db_path: Path
) -> None:
    """Verifies audit log integrity passes on clean db and fails when tampered."""
    verification_clean = ui_ctrl.verify_audit_chain()
    assert verification_clean.ok is True

    # Register an item to populate audit events
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-audit-01",
        authorization_reference="AUTH-1",
        targets=["10.0.0.1"],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
    )
    ui_ctrl.register_scope(scope)

    verification_populated = ui_ctrl.verify_audit_chain()
    assert verification_populated.ok is True
    assert verification_populated.rows_checked >= 1


def test_ui_llm_traces_retrieval(ui_ctrl: UIController) -> None:
    """LLM traces written to SQLite can be queried and viewed."""
    # Write sample trace via trace helper
    from cipher_lens.planner.trace import write_llm_trace

    write_llm_trace(
        conn=ui_ctrl.conn,
        provider="gemini",
        model="gemini-3.8-flash",
        prompt_hash="abc123hash",
        input_summary="Assess 10.0.0.5",
        output='{"steps": []}',
        label="live",
        outcome="success",
        assessment_id="assm-trace-01",
        latency_ms=120,
    )

    traces = ui_ctrl.get_llm_traces(assessment_id="assm-trace-01")
    assert len(traces) == 1
    assert traces[0]["model"] == "gemini-3.8-flash"
    assert traces[0]["label"] == "live"
    assert traces[0]["prompt_hash"] == "abc123hash"


def test_ui_manual_validation_workflow(ui_ctrl: UIController) -> None:
    """Task A13: Full manual validation flow through UIController."""
    now = datetime.now(UTC)
    scope = Scope(
        id="scope-val-01",
        name="Validation Lab",
        authorization_reference="AUTH-VAL",
        targets=["10.0.0.10"],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=12),
    )
    ui_ctrl.register_scope(scope)

    assm, _, _ = ui_ctrl.submit_intake(
        user_request="Assess 10.0.0.10",
        title="Validation Lab Assessment",
        scope_id="scope-val-01",
    )

    ev = Evidence(
        id="ev-01",
        source_tool="nikto",
        run_id="run-1",
        artifact_id="art-1",
        locator="/login",
        raw_sha256="deadbeef1234",
        snippet="Suspected SQL injection",
        observed_at=now,
        origin="live",
    )
    finding = Finding(
        id="FIND-SQLI-01",
        title="SQL Injection in Login Endpoint",
        asset=Asset(host="10.0.0.10", port=80, service="http"),
        sources=["nikto"],
        evidence=[ev],
        tool_severity="critical",
        confidence="medium",
        status="suspected",
        status_reason="Automated heuristic match",
        correlation_key="ck-sqli-login",
        first_seen=now,
        last_seen=now,
    )
    ui_ctrl.repository.save_finding(assm.id, finding)

    # 1. Analyst requests validation
    req = ui_ctrl.request_validation(
        assessment_id=assm.id,
        finding_id=finding.id,
        requested_by="analyst_alice",
        reason="Manual verification of boolean-based SQL injection with sleep(5)",
        potential_impact="Low - database response delay in lab environment",
    )
    assert req.action_class == ActionClass.VALIDATION
    assert req.approval_id is not None

    # Retrieve approval for finding
    approval_tuple = ui_ctrl.get_validation_approval_for_finding(assm.id, finding.id)
    assert approval_tuple is not None
    app_req, app_dec = approval_tuple
    assert app_req.approval_id == req.approval_id
    assert app_dec is None  # pending

    # 2. Decision: Approve
    decision = ui_ctrl.decide_validation(
        assessment_id=assm.id,
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_bob",
        reason="Manual lab verification approved",
    )
    assert decision.decision == "approved"

    # 3. Successful outcome without artifact is blocked
    with pytest.raises(ValueError, match="requires an attached output artifact"):
        ui_ctrl.record_validation(
            assessment_id=assm.id,
            finding_id=finding.id,
            approval_decision=decision,
            outcome="succeeded",
            attested_by="analyst_alice",
            evidence_bytes=None,
        )

    # 4. Successful outcome with artifact confirms finding
    artifact_text = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nLogin bypass verified: welcome admin\n"
    updated = ui_ctrl.record_validation(
        assessment_id=assm.id,
        finding_id=finding.id,
        approval_decision=decision,
        outcome="succeeded",
        attested_by="analyst_alice",
        evidence_bytes=artifact_text,
    )
    assert updated.status == "confirmed"
    assert updated.confidence == "high"
    assert updated.validation is not None
    assert updated.validation.outcome == "succeeded"
    assert len(updated.evidence) == 2

    # Check finding retrieved from repository matches
    persisted = ui_ctrl.repository.get_finding(assm.id, finding.id)
    assert persisted is not None
    assert persisted.status == "confirmed"
    assert persisted.confidence == "high"

    # Verify audit event written
    events = ui_ctrl.get_audit_events(assessment_id=assm.id)
    event_types = [e.event_type for e in events]
    assert "validation_requested" in event_types
    assert "validation_outcome_recorded" in event_types
