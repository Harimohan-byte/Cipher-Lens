"""Tests for Human-in-the-Loop Manual Validation Flow (Task A13).

Validates:
- Analyst requests validation with reason and potential impact
- Pending approval gate: approve or deny
- Denied validation request cannot proceed to record outcome
- Successful validation strictly requires an attached evidence artifact (hashed with SHA-256)
- Successful validation transitions finding status to 'confirmed' and confidence to 'high'
- Failed validation transitions finding status to 'false_positive'
- Audit trail records validation lifecycle events
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipher_lens.models.findings import Asset, Evidence, Finding
from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.approvals import ApprovalManager
from cipher_lens.policy.validation import (
    decide_validation_request,
    record_validation_outcome,
    request_validation,
)
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db


@pytest.fixture
def test_db(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(tmp_path / "test_val.db")
    init_db(conn)
    return conn


@pytest.fixture
def audit_log(test_db: sqlite3.Connection) -> AuditLog:
    return AuditLog(conn=test_db)


@pytest.fixture
def approval_manager(audit_log: AuditLog) -> ApprovalManager:
    return ApprovalManager(audit_log=audit_log)


@pytest.fixture
def artifact_store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(base_dir=tmp_path / "artifacts")


@pytest.fixture
def sample_finding() -> Finding:
    ev = Evidence(
        id="ev-obs-01",
        source_tool="nikto",
        run_id="run-nikto-1",
        artifact_id="art-nikto-1",
        locator="/uri[1]",
        raw_sha256="abc123sha",
        snippet="Apache 2.4.49 path traversal suspected",
        observed_at=datetime.now(UTC),
        origin="live",
    )
    return Finding(
        id="VAPT-0042",
        title="Apache HTTP Path Traversal",
        asset=Asset(host="10.0.0.5", port=80, service="http"),
        sources=["nikto"],
        evidence=[ev],
        tool_severity="high",
        confidence="medium",
        status="suspected",
        status_reason="Single tool heuristic match",
        correlation_key="ck-apache-41773",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )


def test_request_validation_creates_pending_approval(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    audit_log: AuditLog,
) -> None:
    """Requesting validation creates a VALIDATION action class approval request and audits it."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Verify whether path traversal payload /cgi-bin/.%2e/ reaches etc/passwd in lab",
        potential_impact="Read-only file disclosure test in authorized lab",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    assert req.approval_id is not None
    assert req.action_class == ActionClass.VALIDATION
    assert req.tool == "manual_validation"
    assert req.target == "10.0.0.5"

    events = audit_log.query(assessment_id="asm-001", event_type="validation_requested")
    assert len(events) == 1
    assert events[0].payload["finding_id"] == "VAPT-0042"


def test_denied_validation_request_blocks_outcome_recording(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> None:
    """Denied validation request cannot proceed to record outcome (Master Plan §7 A13)."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Test command injection in lab",
        potential_impact="Service disturbance possible",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    # Deny request
    decision = decide_validation_request(
        approval_id=req.approval_id,
        decision="rejected",
        decided_by="lead_bob",
        reason="Lab environment is not isolated enough for intrusive testing",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )
    assert decision.decision == "rejected"

    # Attempting to record outcome on denied request must be blocked
    with pytest.raises(PermissionError, match="denied or unapproved"):
        record_validation_outcome(
            finding=sample_finding,
            approval_decision=decision,
            outcome="succeeded",
            attested_by="analyst_alice",
            evidence_bytes=b"root:x:0:0:root:/root:/bin/bash\n",
            artifact_store=artifact_store,
            audit_log=audit_log,
            assessment_id="asm-001",
        )


def test_successful_validation_requires_attached_artifact(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> None:
    """Master Plan §7 A13: a finding becomes confirmed only on an analyst-attested success with an attached artifact."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Verify path traversal",
        potential_impact="Read-only",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    decision = decide_validation_request(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_bob",
        reason="Approved for manual lab execution",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    # Succeeded outcome without attached artifact is rejected
    with pytest.raises(ValueError, match="requires an attached output artifact"):
        record_validation_outcome(
            finding=sample_finding,
            approval_decision=decision,
            outcome="succeeded",
            attested_by="analyst_alice",
            evidence_bytes=None,  # Missing artifact
            artifact_store=artifact_store,
            audit_log=audit_log,
            assessment_id="asm-001",
        )


def test_successful_validation_transitions_finding_to_confirmed(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> None:
    """Analyst-attested success with attached artifact makes finding confirmed and adds evidence."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Verify path traversal",
        potential_impact="Read-only",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    decision = decide_validation_request(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_bob",
        reason="Approved for manual lab execution",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    artifact_content = b"HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\n"
    updated = record_validation_outcome(
        finding=sample_finding,
        approval_decision=decision,
        outcome="succeeded",
        attested_by="analyst_alice",
        evidence_bytes=artifact_content,
        artifact_store=artifact_store,
        audit_log=audit_log,
        assessment_id="asm-001",
    )

    assert updated.status == "confirmed"
    assert updated.confidence == "high"
    assert updated.validation is not None
    assert updated.validation.outcome == "succeeded"
    assert updated.validation.attested_by == "analyst_alice"
    assert updated.validation.evidence_artifact_id is not None

    # Verifies evidence was added with cryptographic hash
    assert len(updated.evidence) == 2
    new_ev = updated.evidence[-1]
    assert new_ev.source_tool == "manual_validation"
    assert len(new_ev.raw_sha256) == 64

    # Verifies audit event was recorded
    events = audit_log.query(assessment_id="asm-001", event_type="validation_outcome_recorded")
    assert len(events) == 1
    assert events[0].payload["finding_id"] == "VAPT-0042"
    assert events[0].payload["outcome"] == "succeeded"


def test_failed_validation_transitions_finding_to_false_positive(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> None:
    """Manual validation failure marks the finding as false_positive."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Verify version heuristic",
        potential_impact="None",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    decision = decide_validation_request(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_bob",
        reason="Approved",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    updated = record_validation_outcome(
        finding=sample_finding,
        approval_decision=decision,
        outcome="failed",
        attested_by="analyst_alice",
        evidence_bytes=b"HTTP/1.1 400 Bad Request\r\n",
        artifact_store=artifact_store,
        audit_log=audit_log,
        assessment_id="asm-001",
    )

    assert updated.status == "false_positive"
    assert updated.validation is not None
    assert updated.validation.outcome == "failed"
    assert "false positive" in updated.status_reason.lower()


def test_inconclusive_validation_keeps_finding_as_suspected(
    sample_finding: Finding,
    approval_manager: ApprovalManager,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> None:
    """Inconclusive validation outcome keeps finding status as suspected."""
    req = request_validation(
        finding=sample_finding,
        requested_by="analyst_alice",
        reason="Verify exploitability",
        potential_impact="Low",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    decision = decide_validation_request(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_bob",
        reason="Approved",
        approval_manager=approval_manager,
        assessment_id="asm-001",
    )

    updated = record_validation_outcome(
        finding=sample_finding,
        approval_decision=decision,
        outcome="inconclusive",
        attested_by="analyst_alice",
        evidence_bytes=b"Connection timed out\n",
        artifact_store=artifact_store,
        audit_log=audit_log,
        assessment_id="asm-001",
    )

    assert updated.status == "suspected"
    assert updated.validation is not None
    assert updated.validation.outcome == "inconclusive"
    assert "inconclusive" in updated.status_reason.lower()
