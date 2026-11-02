"""Tests for AssessmentRepository (Task A8 - Persistence Layer).

Validates:
- Assessment lifecycle and status transitions
- PlanStep persistence, status updates, and idempotency key queries
- StepRun recording and querying
- Finding and Evidence persistence with 100% field fidelity
- Approvals persistence (request and decision)
- Resume-from-DB support and crash recovery (reset_interrupted_steps)
- Foreign key enforcement
"""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.assessment import (
    Assessment,
    AssessmentStatus,
    StepRun,
)
from cipher_lens.models.findings import (
    Asset,
    CvssInfo,
    Evidence,
    FactorValue,
    Finding,
    Inference,
    RiskScore,
    ValidationRecord,
)
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.store.db import init_db
from cipher_lens.store.repository import AssessmentRepository


@pytest.fixture
def repo() -> AssessmentRepository:
    """Create an isolated in-memory SQLite connection with full schema."""
    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=True)
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    return AssessmentRepository(conn=conn)


def make_sample_assessment(assessment_id: str = "asm-001") -> Assessment:
    now = datetime.now(UTC)
    return Assessment(
        id=assessment_id,
        title="Test Lab Assessment",
        target="10.0.0.5",
        scope_id="scope-001",
        status=AssessmentStatus.CREATED,
        created_at=now,
        updated_at=now,
        metadata={"environment": "lab", "analyst": "person_a"},
    )


def make_sample_step(step_id: str = "step-01", target: str = "10.0.0.5") -> PlanStep:
    return PlanStep(
        step_id=step_id,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target=target,
        params={"ports": "80,443", "timing": 3},
        rationale="Initial service discovery",
        triggered_by=["scope_rule"],
        expected_outcome="Open ports discovered",
        nist_phase="discovery",
        idempotency_key=f"idem-{step_id}",
    )


def make_sample_evidence(ev_id: str = "ev-001", run_id: str = "run-001") -> Evidence:
    return Evidence(
        id=ev_id,
        source_tool="nmap",
        run_id=run_id,
        artifact_id="art-nmap-001",
        locator="/nmaprun/host/ports/port[1]",
        raw_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        snippet="80/tcp open http Apache httpd 2.4.49",
        observed_at=datetime.now(UTC),
        origin="sample",
    )


def make_sample_finding(finding_id: str = "VAPT-0001", ev_id: str = "ev-001") -> Finding:
    now = datetime.now(UTC)
    evidence = make_sample_evidence(ev_id=ev_id)
    return Finding(
        id=finding_id,
        title="Apache HTTP Server Path Traversal",
        asset=Asset(
            host="10.0.0.5",
            ip="10.0.0.5",
            port=80,
            protocol="tcp",
            service="http",
            url_path="/cgi-bin/",
        ),
        sources=["nmap"],
        evidence=[evidence],
        inferences=[
            Inference(
                id="inf-001",
                text="Path traversal could allow arbitrary file disclosure",
                provider="gemini",
                label="live",
                based_on=[evidence.id],
                created_at=now,
            )
        ],
        cve=["CVE-2021-41773"],
        cwe=["CWE-22"],
        cvss=CvssInfo(
            score=7.5,
            version="3.1",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            source="nvd",
        ),
        tool_severity="high",
        confidence="high",
        status="confirmed",
        status_reason="Path traversal confirmed via NSE response",
        limitations=[],
        risk=RiskScore(
            total=82.5,
            band="High",
            factors={
                "severity": FactorValue(value=0.75, source="cvss"),
                "exploitability": FactorValue(value=1.0, source="cisa_kev"),
            },
            weights_version="1.0",
        ),
        validation=ValidationRecord(
            approval_id="appr-001",
            outcome="succeeded",
            attested_by="analyst_1",
            evidence_artifact_id="art-val-001",
            recorded_at=now,
        ),
        correlation_key="key-apache-80-cve-2021-41773",
        related_ids=[],
        first_seen=now,
        last_seen=now,
    )


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_assessment_lifecycle(repo: AssessmentRepository) -> None:
    asm = make_sample_assessment("asm-test-1")
    created = repo.create_assessment(asm)
    assert created.id == "asm-test-1"

    fetched = repo.get_assessment("asm-test-1")
    assert fetched is not None
    assert fetched.id == "asm-test-1"
    assert fetched.target == "10.0.0.5"
    assert fetched.status == AssessmentStatus.CREATED

    # Update status
    repo.update_assessment_status("asm-test-1", AssessmentStatus.IN_PROGRESS)
    updated = repo.get_assessment("asm-test-1")
    assert updated is not None
    assert updated.status == AssessmentStatus.IN_PROGRESS

    # Listing by status
    in_prog = repo.list_assessments(status=AssessmentStatus.IN_PROGRESS)
    assert len(in_prog) == 1
    assert in_prog[0].id == "asm-test-1"

    completed = repo.list_assessments(status=AssessmentStatus.COMPLETED)
    assert len(completed) == 0

    # Resumable query includes created and in_progress
    resumable = repo.get_resumable_assessments()
    assert len(resumable) == 1
    assert resumable[0].id == "asm-test-1"


def test_plan_step_persistence_and_queries(repo: AssessmentRepository) -> None:
    asm = make_sample_assessment("asm-step-test")
    repo.create_assessment(asm)

    step1 = make_sample_step("step-01")
    step2 = make_sample_step("step-02")
    step2.tool = "nikto"
    step2.nist_phase = "discovery"
    step2.idempotency_key = "idem-nikto-80"

    repo.save_step("asm-step-test", step1, status="pending")
    repo.save_step("asm-step-test", step2, status="running")

    # Get single step
    result = repo.get_step("asm-step-test", "step-01")
    assert result is not None
    s, status = result
    assert s.step_id == "step-01"
    assert status == "pending"

    # Query by idempotency key
    idem_result = repo.get_step_by_idempotency_key("asm-step-test", "idem-nikto-80")
    assert idem_result is not None
    assert idem_result[0].step_id == "step-02"

    # Query steps by status
    running_steps = repo.get_steps("asm-step-test", status="running")
    assert len(running_steps) == 1
    assert running_steps[0][0].step_id == "step-02"

    # Update step status
    repo.update_step_status("asm-step-test", "step-01", "completed")
    updated = repo.get_step("asm-step-test", "step-01")
    assert updated is not None
    assert updated[1] == "completed"


def test_step_run_persistence(repo: AssessmentRepository) -> None:
    asm = make_sample_assessment("asm-run-test")
    repo.create_assessment(asm)
    step = make_sample_step("step-01")
    repo.save_step("asm-run-test", step)

    now = datetime.now(UTC)
    run = StepRun(
        run_id="run-001",
        assessment_id="asm-run-test",
        step_id="step-01",
        tool_name="nmap",
        status="success",
        exit_code=0,
        stdout_artifact_id="art-stdout-001",
        stderr_artifact_id=None,
        raw_sha256="abc123sha",
        started_at=now,
        ended_at=now + timedelta(seconds=5),
        duration_ms=5000,
        error_message=None,
    )

    saved = repo.save_run(run)
    assert saved.run_id == "run-001"

    fetched = repo.get_run("run-001")
    assert fetched is not None
    assert fetched.status == "success"
    assert fetched.exit_code == 0
    assert fetched.duration_ms == 5000

    runs = repo.list_runs("asm-run-test", step_id="step-01")
    assert len(runs) == 1
    assert runs[0].run_id == "run-001"


def test_finding_and_evidence_fidelity(repo: AssessmentRepository) -> None:
    asm = make_sample_assessment("asm-find-test")
    repo.create_assessment(asm)

    finding = make_sample_finding("VAPT-0001", ev_id="ev-001")
    repo.save_finding("asm-find-test", finding)

    fetched = repo.get_finding("asm-find-test", "VAPT-0001")
    assert fetched is not None
    assert fetched.id == "VAPT-0001"
    assert fetched.title == finding.title
    assert fetched.asset.host == "10.0.0.5"
    assert fetched.asset.port == 80
    assert fetched.cve == ["CVE-2021-41773"]
    assert fetched.cvss is not None
    assert fetched.cvss.score == 7.5
    assert fetched.risk is not None
    assert fetched.risk.total == 82.5
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].snippet == finding.evidence[0].snippet
    assert len(fetched.inferences) == 1
    assert fetched.inferences[0].provider == "gemini"
    assert fetched.validation is not None
    assert fetched.validation.outcome == "succeeded"

    # Query by correlation key
    by_corr = repo.get_finding_by_correlation_key(
        "asm-find-test", "key-apache-80-cve-2021-41773"
    )
    assert by_corr is not None
    assert by_corr.id == "VAPT-0001"

    # Evidence standalone table
    ev = make_sample_evidence("ev-standalone-1")
    repo.save_evidence("asm-find-test", ev, finding_id="VAPT-0001")
    ev_list = repo.list_evidence("asm-find-test", finding_id="VAPT-0001")
    assert len(ev_list) == 1
    assert ev_list[0].id == "ev-standalone-1"


def test_approvals_persistence(repo: AssessmentRepository) -> None:
    asm = make_sample_assessment("asm-appr-test")
    repo.create_assessment(asm)
    step = make_sample_step("step-intrusive")
    step.action_class = ActionClass.INTRUSIVE
    repo.save_step("asm-appr-test", step)

    now = datetime.now(UTC)
    req = ApprovalRequest(
        approval_id="appr-101",
        assessment_id="asm-appr-test",
        step_id="step-intrusive",
        action_class=ActionClass.INTRUSIVE,
        tool="zap",
        target="10.0.0.5",
        rationale="Active SQL injection probe",
        requested_at=now,
        status="pending",
    )
    repo.save_approval_request(req)

    item = repo.get_approval("appr-101")
    assert item is not None
    saved_req, decision = item
    assert saved_req.approval_id == "appr-101"
    assert saved_req.status == "pending"
    assert decision is None

    # Human decides to approve
    dec = ApprovalDecision(
        approval_id="appr-101",
        decision="approved",
        decided_by="lead_auditor",
        reason="Target is in sandbox authorized range",
        decided_at=now + timedelta(minutes=2),
        notes="Proceed with rate limit 2 req/s",
    )
    repo.record_approval_decision(dec)

    item_after = repo.get_approval("appr-101")
    assert item_after is not None
    req_after, dec_after = item_after
    assert req_after.status == "approved"
    assert dec_after is not None
    assert dec_after.decision == "approved"
    assert dec_after.decided_by == "lead_auditor"


def test_resume_assessment_state_recovery(repo: AssessmentRepository) -> None:
    """Verifies crash recovery: interrupted 'running' steps reset to 'pending',

    and full state is reconstructed from DB.
    """
    asm = make_sample_assessment("asm-crash-test")
    asm.status = AssessmentStatus.IN_PROGRESS
    repo.create_assessment(asm)

    step1 = make_sample_step("step-done")
    step2 = make_sample_step("step-interrupted")
    step3 = make_sample_step("step-unstarted")

    repo.save_step("asm-crash-test", step1, status="completed")
    repo.save_step("asm-crash-test", step2, status="running")  # was running when crashed
    repo.save_step("asm-crash-test", step3, status="pending")

    # Reset interrupted steps simulates reboot/recovery hook
    reset_count = repo.reset_interrupted_steps("asm-crash-test")
    assert reset_count == 1

    # Now step2 should be pending
    resumed = repo.resume_assessment("asm-crash-test")
    assert resumed.assessment.id == "asm-crash-test"
    assert len(resumed.completed_steps) == 1
    assert resumed.completed_steps[0].step_id == "step-done"

    # Pending steps should now contain both step-interrupted and step-unstarted
    pending_ids = [s.step_id for s in resumed.pending_steps]
    assert "step-interrupted" in pending_ids
    assert "step-unstarted" in pending_ids


def test_foreign_key_enforcement(repo: AssessmentRepository) -> None:
    step = make_sample_step("step-orphan")
    with pytest.raises(sqlite3.IntegrityError):
        repo.save_step("non-existent-assessment", step)
