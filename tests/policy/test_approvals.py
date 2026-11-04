"""Tests for human-in-the-loop approvals model and state machine enforcement."""

import sqlite3
from pathlib import Path

import pytest

from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.approvals import (
    ApprovalManager,
    ApprovalRejectedError,
    ApprovalRequiredError,
    requires_per_step_approval,
    requires_plan_approval,
)
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(tmp_path / "test_approvals.db")
    init_db(conn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def audit_log(db_conn: sqlite3.Connection) -> AuditLog:
    return AuditLog(db_conn)


@pytest.fixture
def approval_manager(audit_log: AuditLog) -> ApprovalManager:
    return ApprovalManager(audit_log=audit_log)


@pytest.fixture
def intrusive_step() -> PlanStep:
    return PlanStep(
        step_id="step-zap-active-01",
        tool="zap",
        action_class=ActionClass.INTRUSIVE,
        target="http://192.168.1.10:8080/",
        rationale="Active SQL injection scan against login form",
        expected_outcome="Detect injectable parameters",
        nist_phase="attack",
    )


@pytest.fixture
def validation_step() -> PlanStep:
    return PlanStep(
        step_id="step-metasploit-manual-01",
        tool="manual_validation",
        action_class=ActionClass.VALIDATION,
        target="192.168.1.10",
        rationale="Manual validation of CVE-2023-1234",
        expected_outcome="Confirm exploitability safely in lab",
        nist_phase="attack",
    )


@pytest.fixture
def discovery_step() -> PlanStep:
    return PlanStep(
        step_id="step-nmap-disc-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target="192.168.1.10",
        rationale="Host and port discovery",
        expected_outcome="Open ports list",
        nist_phase="discovery",
    )


def test_action_class_tier_categorization():
    """Verify tier mapping: INTRUSIVE and VALIDATION require per-step; others require plan approval."""
    assert requires_per_step_approval(ActionClass.INTRUSIVE) is True
    assert requires_per_step_approval(ActionClass.VALIDATION) is True
    assert requires_per_step_approval(ActionClass.DISCOVERY) is False
    assert requires_per_step_approval(ActionClass.SCAN) is False
    assert requires_per_step_approval(ActionClass.IMPORT) is False

    assert requires_plan_approval(ActionClass.DISCOVERY) is True
    assert requires_plan_approval(ActionClass.SCAN) is True
    assert requires_plan_approval(ActionClass.IMPORT) is True
    assert requires_plan_approval(ActionClass.INTRUSIVE) is False
    assert requires_plan_approval(ActionClass.VALIDATION) is False


def test_unapproved_intrusive_step_raises_approval_required(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """Break-it safety check: an unapproved INTRUSIVE step must NEVER pass require()."""
    with pytest.raises(ApprovalRequiredError, match="requires human per-step approval"):
        approval_manager.require(intrusive_step, assessment_id="asmt-001")


def test_unapproved_validation_step_raises_approval_required(
    approval_manager: ApprovalManager, validation_step: PlanStep
):
    """Break-it safety check: manual VALIDATION step requires explicit approval."""
    with pytest.raises(ApprovalRequiredError, match="requires human per-step approval"):
        approval_manager.require(validation_step, assessment_id="asmt-001")


def test_unapproved_plan_step_raises_approval_required(
    approval_manager: ApprovalManager, discovery_step: PlanStep
):
    """Discovery/Scan steps require plan approval for the assessment."""
    with pytest.raises(ApprovalRequiredError, match="requires plan approval"):
        approval_manager.require(discovery_step, assessment_id="asmt-001")


def test_plan_approval_flow(
    approval_manager: ApprovalManager, discovery_step: PlanStep, db_conn: sqlite3.Connection
):
    """Plan approval permits DISCOVERY step and audits the plan approval decision."""
    approval_manager.approve_plan(
        assessment_id="asmt-001",
        decided_by="lead-analyst",
        reason="Target within lab rules of engagement",
    )

    # Now require() passes without raising
    approval_manager.require(discovery_step, assessment_id="asmt-001")

    # Verify audit trail
    cur = db_conn.cursor()
    cur.execute("SELECT actor, event_type, payload FROM audit_log WHERE event_type = 'plan_approved'")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "lead-analyst"
    assert "asmt-001" in row[2]


def test_per_step_approval_granted(
    approval_manager: ApprovalManager, intrusive_step: PlanStep, db_conn: sqlite3.Connection
):
    """Requesting and approving per-step approval allows INTRUSIVE step to execute."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    assert req.status == "pending"

    # Before decision, require() still raises
    with pytest.raises(ApprovalRequiredError):
        approval_manager.require(intrusive_step, assessment_id="asmt-001")

    # Decide approval
    dec = approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="security-lead",
        reason="Active SQLi payload authorized on test environment",
    )
    assert dec.decision == "approved"

    # require() now succeeds
    approval_manager.require(intrusive_step, assessment_id="asmt-001")

    # Verify audit events
    cur = db_conn.cursor()
    cur.execute("SELECT event_type FROM audit_log ORDER BY id ASC")
    event_types = [r[0] for r in cur.fetchall()]
    assert "approval_requested" in event_types
    assert "approval_approved" in event_types


def test_per_step_approval_rejected(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """A rejected per-step approval raises ApprovalRejectedError."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    approval_manager.decide(
        approval_id=req.approval_id,
        decision="rejected",
        decided_by="security-lead",
        reason="Active scan might disrupt demo lab service",
    )

    with pytest.raises(ApprovalRejectedError, match="rejected"):
        approval_manager.require(intrusive_step, assessment_id="asmt-001")


def test_rejected_decision_is_final(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """Safety rule: Decisions are final; once rejected, it stays rejected and cannot be modified."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    approval_manager.decide(
        approval_id=req.approval_id,
        decision="rejected",
        decided_by="lead",
        reason="Denied",
    )

    # Attempting to change decision from rejected to approved must fail
    with pytest.raises(ValueError, match=r"is final .* and cannot be modified"):
        approval_manager.decide(
            approval_id=req.approval_id,
            decision="approved",
            decided_by="lead",
            reason="Changed mind",
        )


def test_approval_decision_is_idempotent(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """Re-submitting the exact same decision is idempotent and does not error."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    dec1 = approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead",
        reason="Approved",
    )
    dec2 = approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead",
        reason="Approved",
    )
    assert dec1.approval_id == dec2.approval_id
    assert dec1.decision == dec2.decision


def test_approval_binding_to_assessment_id(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """CodeRabbit fix 1a: Approval in asmt-001 must not authorize the same step_id in asmt-002."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead",
        reason="Approved for asmt-001",
    )

    # Valid for asmt-001
    approval_manager.require(intrusive_step, assessment_id="asmt-001")

    # MUST fail for asmt-002
    with pytest.raises(ApprovalRequiredError, match="no approval requested for assessment 'asmt-002'"):
        approval_manager.require(intrusive_step, assessment_id="asmt-002")


def test_approval_content_tampering_detected(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """CodeRabbit fix 1b: Mutating step parameters after approval invalidates the approval."""
    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead",
        reason="Approved for original target",
    )

    # Modified target on the same step_id
    tampered_step = intrusive_step.model_copy(update={"target": "http://evil.com/attack"})
    with pytest.raises(ApprovalRequiredError, match="differs from the approved request"):
        approval_manager.require(tampered_step, assessment_id="asmt-001")


def test_unclassified_action_class_fails_closed(approval_manager: ApprovalManager):
    """CodeRabbit fix 2: An unclassified action class must fail closed and raise ApprovalRequiredError."""
    from unittest.mock import MagicMock

    mock_step = MagicMock(spec=PlanStep)
    mock_step.step_id = "step-unknown-01"
    mock_step.action_class = "unclassified_action"

    with pytest.raises(ApprovalRequiredError, match="unclassified action class"):
        approval_manager.require(mock_step, assessment_id="asmt-001")


def test_separation_of_duties_prevents_self_approval(
    audit_log: AuditLog, intrusive_step: PlanStep
):
    """Break-it test: Requesters cannot approve their own requests (ERR-20)."""
    from cipher_lens.config import Settings
    from cipher_lens.policy.approvals import ApprovalError

    strict_mgr = ApprovalManager(
        audit_log=audit_log,
        settings=Settings(allow_self_approval=False),
    )
    req = strict_mgr.request_approval(
        intrusive_step,
        assessment_id="asmt-001",
        requested_by="alice",
    )

    # Alice trying to approve her own request must fail
    with pytest.raises(ApprovalError, match="Separation of duties violation"):
        strict_mgr.decide(
            approval_id=req.approval_id,
            decision="approved",
            decided_by="alice",
            reason="I self-authorize this scan",
        )


def test_separation_of_duties_allowed_when_flag_enabled(
    audit_log: AuditLog, intrusive_step: PlanStep
):
    """Self-approval is permitted when ALLOW_SELF_APPROVAL=true."""
    from cipher_lens.config import Settings

    permissive_mgr = ApprovalManager(
        audit_log=audit_log,
        settings=Settings(allow_self_approval=True),
    )
    req = permissive_mgr.request_approval(
        intrusive_step,
        assessment_id="asmt-001",
        requested_by="alice",
    )

    dec = permissive_mgr.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="alice",
        reason="Permitted in standalone test mode",
    )
    assert dec.decision == "approved"


def test_approval_expiration_blocks_execution(
    approval_manager: ApprovalManager, intrusive_step: PlanStep
):
    """Break-it test: Expired approvals are rejected at runtime."""
    from datetime import UTC, datetime, timedelta

    req = approval_manager.request_approval(intrusive_step, assessment_id="asmt-001")
    past_time = datetime.now(UTC) - timedelta(minutes=5)

    approval_manager.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead",
        reason="Approved but expired",
        expires_at=past_time,
    )

    with pytest.raises(ApprovalRequiredError, match="expired"):
        approval_manager.require(intrusive_step, assessment_id="asmt-001")


