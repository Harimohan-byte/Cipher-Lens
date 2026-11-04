"""Tests for Risk Scorer (B14), Orchestrator Engine (B15), and Grounding Validator (B16).

Test matrix requirements:
- B14 Risk Scorer:
  - Monotonicity: higher CVSS -> higher risk score.
  - KEV-boost: CISA KEV presence elevates exploitability to 1.0.
  - Missing-data transparency: missing CVSS/KEV/scope tags marked with explanation and documented fallback.
  - Reproducible breakdown: factor dict holds value, source, and description.
- B15 Orchestrator Engine:
  - Plan -> policy check -> plan approval -> execute approved steps -> ingest (parse -> normalize -> enrich -> correlate -> score).
  - Intrusive/Validation steps wait in awaiting_approval.
  - Idempotency key skips repeated tool execution.
  - Tool failure records failure and continues assessment without crash.
  - Emits events for UI tracking.
- B16 Grounding Validator:
  - Verified CVE tokens must exist in DB findings.
  - Planted fake CVE fails grounding validation.
  - Finding count and severities must match DB counts.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.enrichment.service import CveEnrichment
from cipher_lens.models.findings import Asset, CvssInfo, Evidence, Finding
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.orchestrator.engine import OrchestrationEngine
from cipher_lens.orchestrator.events import EventBus
from cipher_lens.orchestrator.grounding import GroundingValidator
from cipher_lens.orchestrator.runner import ToolRunner
from cipher_lens.policy.approvals import ApprovalManager
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db
from cipher_lens.store.repository import AssessmentRepository

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "risk.yaml"


@pytest.fixture
def risk_scorer():
    return RiskScorer.load(CONFIG_PATH)


@pytest.fixture
def sample_finding():
    ev = Evidence(
        id="ev_test_risk_01",
        source_tool="nmap",
        run_id="run-01",
        artifact_id="art-01",
        locator="/item",
        raw_sha256="a" * 64,
        snippet="vuln",
        observed_at=datetime.now(UTC),
        origin="sample",
    )
    return Finding(
        id="VAPT-0001",
        title="Apache HTTP Path Traversal",
        asset=Asset(host="lab-target.local", ip="10.0.0.5", port=80),
        sources=["nmap"],
        evidence=[ev],
        inferences=[],
        cve=["CVE-2021-41773"],
        cwe=["CWE-22"],
        cvss=CvssInfo(score=7.5, version="3.1", vector="CVSS:3.1/AV:N/AC:L", source="nvd"),
        tool_severity="high",
        confidence="high",
        status="confirmed",
        status_reason="Direct proof",
        limitations=[],
        risk=None,
        validation=None,
        correlation_key="test-key",
        related_ids=[],
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# B14: Risk Scorer Tests
# ---------------------------------------------------------------------------


def test_risk_scorer_monotonicity(risk_scorer, sample_finding):
    """Monotonicity: Higher CVSS scores yield higher overall risk scores."""
    f_low = sample_finding.model_copy(update={"cvss": CvssInfo(score=3.0, version="3.1", source="nvd")})
    f_high = sample_finding.model_copy(update={"cvss": CvssInfo(score=9.5, version="3.1", source="nvd")})

    score_low = risk_scorer.score_finding(f_low)
    score_high = risk_scorer.score_finding(f_high)

    assert score_high.total > score_low.total
    assert score_high.factors["severity"].value > score_low.factors["severity"].value


def test_risk_scorer_kev_boost(risk_scorer, sample_finding):
    """CISA KEV membership boosts exploitability factor to 1.0."""
    enrichment_no_kev = CveEnrichment(cve_id="CVE-2021-41773", cisa_kev=False, epss_percentile=0.45)
    enrichment_kev = CveEnrichment(cve_id="CVE-2021-41773", cisa_kev=True, epss_percentile=0.45)

    score_normal = risk_scorer.score_finding(sample_finding, enrichment=enrichment_no_kev)
    score_kev = risk_scorer.score_finding(sample_finding, enrichment=enrichment_kev)

    assert score_kev.factors["exploitability"].value == 1.0
    assert "cisa kev" in score_kev.factors["exploitability"].description.lower()
    assert score_kev.total > score_normal.total


def test_risk_scorer_missing_data_transparency(risk_scorer, sample_finding):
    """Missing CVSS, scope tags, or KEV data fall back cleanly with documented sources."""
    f_missing = sample_finding.model_copy(update={"cvss": None})
    score = risk_scorer.score_finding(f_missing, enrichment=None, scope_tags={})

    assert score.factors["severity"].source == "tool band"
    assert score.factors["exploitability"].source == "unavailable"
    assert score.factors["exposure"].source == "default"
    assert score.factors["asset_criticality"].source == "default"
    assert score.total > 0.0
    assert score.band in ("critical", "high", "medium", "low", "informational")


@pytest.mark.asyncio
async def test_orchestrator_engine_flow_and_idempotency(tmp_path):
    """End-to-end engine flow: step execution, duplicate skipping, and event emission."""
    db_file = tmp_path / "test_engine.db"
    conn = connect(db_file)
    init_db(conn)

    repo = AssessmentRepository(conn)
    scope = Scope(
        id="scope-engine-01",
        owner="Security",
        authorization_reference="AUTH-ENG-01",
        allowed_targets=["10.0.0.5"],
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
    )
    registry = ScopeRegistry()
    registry.register(scope)

    audit = AuditLog(conn=conn)
    gate = PolicyGate(registry=registry, audit_log=audit)
    approvals = ApprovalManager(audit_log=audit)
    artifacts = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(
        artifact_store=artifacts,
        audit_log=audit,
        policy_gate=gate,
        approval_manager=approvals,
    )

    from cipher_lens.adapters.nmap import NmapAdapter
    from cipher_lens.models.assessment import Assessment, AssessmentStatus

    assm = Assessment(
        id="assm-eng-01",
        title="Engine Test",
        target="10.0.0.5",
        scope_id="scope-engine-01",
        status=AssessmentStatus.PLANNING,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    repo.create_assessment(assm)

    event_log = []
    bus = EventBus()
    bus.subscribe(lambda e: event_log.append(e))

    engine = OrchestrationEngine(
        repository=repo,
        scope_registry=registry,
        policy_gate=gate,
        approval_manager=approvals,
        artifact_store=artifacts,
        runner=runner,
        adapters={"nmap": NmapAdapter()},
        event_bus=bus,
    )

    step = PlanStep(
        step_id="step-eng-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target="10.0.0.5",
        params={"target": "10.0.0.5", "profile": "discovery"},
        rationale="Discovery",
        expected_outcome="ports",
        nist_phase="discovery",
    )

    # Approve plan so DISCOVERY action class can run
    approvals.approve_plan(assessment_id="assm-eng-01", decided_by="analyst", reason="Plan review passed")

    # Mock runner execution
    from unittest.mock import AsyncMock

    from cipher_lens.adapters.base import ExecutionResult
    mock_res = ExecutionResult(
        status="succeeded",
        stdout="mock stdout",
        stderr="",
        exit_code=0,
        duration_seconds=1.2,
        artifact_id="art-nmap-1",
    )
    runner.run = AsyncMock(return_value=mock_res)

    # 1. Execute first time -> succeeds
    res1 = await engine.execute_step("assm-eng-01", step)
    assert res1.status == "succeeded"

    # 2. Execute duplicate step with same params -> skipped_duplicate
    res2 = await engine.execute_step("assm-eng-01", step)
    assert res2.status == "succeeded"
    assert "[skipped duplicate]" in res2.stdout

    # Verify events were emitted
    event_types = [e.event_type for e in event_log]
    assert "step_started" in event_types
    assert "step_finished" in event_types
    assert "step_skipped_duplicate" in event_types


@pytest.mark.asyncio
async def test_engine_wires_rate_limiter_from_scope(tmp_path):
    """Break-it test: OrchestrationEngine wires RateLimiter to ToolRunner from Scope (ERR-19)."""
    db_file = tmp_path / "test_rate_wire.db"
    conn = connect(db_file)
    init_db(conn)

    repo = AssessmentRepository(conn)
    scope = Scope(
        id="scope-rate-wire",
        owner="Security",
        authorization_reference="AUTH-RATE-WIRE",
        allowed_targets=["10.0.0.5"],
        rate_limit=7,
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
    )
    registry = ScopeRegistry()
    registry.register(scope)

    audit = AuditLog(conn=conn)
    gate = PolicyGate(registry=registry, audit_log=audit)
    approvals = ApprovalManager(audit_log=audit)
    approvals.approve_plan(assessment_id="assm-rate-01", decided_by="admin", reason="ok")
    artifacts = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(
        artifact_store=artifacts,
        audit_log=audit,
        policy_gate=gate,
        approval_manager=approvals,
    )
    assert runner.rate_limiter is None

    from cipher_lens.adapters.nmap import NmapAdapter
    from cipher_lens.models.assessment import Assessment, AssessmentStatus

    assm = Assessment(
        id="assm-rate-01",
        title="Rate Test",
        target="10.0.0.5",
        scope_id="scope-rate-wire",
        status=AssessmentStatus.PLANNING,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    repo.create_assessment(assm)

    engine = OrchestrationEngine(
        repository=repo,
        scope_registry=registry,
        policy_gate=gate,
        approval_manager=approvals,
        artifact_store=artifacts,
        runner=runner,
        adapters={"nmap": NmapAdapter()},
    )

    from unittest.mock import AsyncMock

    from cipher_lens.adapters.base import ExecutionResult
    runner.run = AsyncMock(
        return_value=ExecutionResult(
            status="succeeded",
            stdout="ok",
            stderr="",
            exit_code=0,
            duration_seconds=0.1,
        )
    )

    step = PlanStep(
        step_id="step-rate-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target="10.0.0.5",
        params={"target": "10.0.0.5", "profile": "discovery"},
        rationale="Discovery",
        expected_outcome="ports",
        nist_phase="discovery",
    )

    await engine.execute_step("assm-rate-01", step)
    assert runner.rate_limiter is not None
    assert runner.rate_limiter.rate_limit == 7



def test_grounding_validator_passes_valid_text():
    """GroundingValidator verifies that referenced CVEs and finding IDs exist in database findings."""
    findings = [
        Finding(
            id="VAPT-0001",
            title="Sample",
            asset=Asset(host="lab-target.local"),
            sources=["nmap"],
            evidence=[
                Evidence(
                    id="ev_01",
                    source_tool="nmap",
                    run_id="run-1",
                    artifact_id="art-1",
                    locator="/item",
                    raw_sha256="0" * 64,
                    snippet="x",
                    observed_at=datetime.now(UTC),
                    origin="sample",
                )
            ],
            cve=["CVE-2021-41773"],
            cwe=[],
            tool_severity="high",
            confidence="high",
            status="confirmed",
            status_reason="ok",
            correlation_key="k1",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
    ]
    validator = GroundingValidator()
    text = "In finding VAPT-0001, we identified CVE-2021-41773 affecting the web service."

    result = validator.validate(text, findings)
    assert result.is_valid is True
    assert result.hallucinated_cves == []
    assert result.hallucinated_finding_ids == []


def test_grounding_validator_rejects_hallucinated_cve():
    """Planted fake CVE fails the grounding validator (Safety Rule 3 & Task B16)."""
    findings = []
    validator = GroundingValidator()
    text = "We discovered a critical vulnerability CVE-2024-999999 in the target system."

    result = validator.validate(text, findings)
    assert result.is_valid is False
    assert "CVE-2024-999999" in result.hallucinated_cves
    assert "unsupported cve" in result.error_message.lower() or "hallucinated" in result.error_message.lower()


def test_grounding_validator_boundary_check():
    """Checks that finding IDs with different lengths like VAPT-00012 fail validation when not in known_ids."""
    findings = [
        Finding(
            id="VAPT-0001",
            title="Sample 1",
            asset=Asset(host="10.0.0.5"),
            sources=["nmap"],
            evidence=[
                Evidence(
                    id="ev_01",
                    source_tool="nmap",
                    run_id="run-1",
                    artifact_id="art-1",
                    locator="/item",
                    raw_sha256="0" * 64,
                    snippet="x",
                    observed_at=datetime.now(UTC),
                    origin="sample",
                )
            ],
            cve=[],
            cwe=[],
            tool_severity="high",
            confidence="high",
            status="confirmed",
            status_reason="ok",
            correlation_key="k1",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
    ]
    validator = GroundingValidator()
    # VAPT-00012 is extracted and rejected because it does not match known VAPT-0001
    text = "Referencing VAPT-00012 in report"
    res = validator.validate(text, findings)
    assert res.is_valid is False
    assert "VAPT-00012" in res.hallucinated_finding_ids


def test_grounding_validator_checks_counts():
    """Validates claimed counts against actual findings counts."""
    findings = [
        Finding(
            id="VAPT-0001",
            title="Sample 1",
            asset=Asset(host="10.0.0.5"),
            sources=["nmap"],
            evidence=[
                Evidence(
                    id="ev_01",
                    source_tool="nmap",
                    run_id="run-1",
                    artifact_id="art-1",
                    locator="/item",
                    raw_sha256="0" * 64,
                    snippet="x",
                    observed_at=datetime.now(UTC),
                    origin="sample",
                )
            ],
            cve=[],
            cwe=[],
            tool_severity="critical",
            confidence="high",
            status="confirmed",
            status_reason="ok",
            correlation_key="k1",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
    ]
    validator = GroundingValidator()
    # Claiming 5 critical vulnerabilities when only 1 exists
    res = validator.validate_counts(claimed_critical=5, findings=findings)
    assert res.is_valid is False
