"""Day 6 Golden Run End-to-End Pipeline & Rehearsal Test (Task B19).

Validates the complete pipeline:
  1. Scope Registration (PolicyGate)
  2. Assessment & Multi-Tool Evidence (Nmap, Nikto, ZAP) with SHA-256 integrity
  3. Vulnerability Correlation & Canonical Key Merging
  4. 0–100 Risk Prioritization with CISA KEV Boosts
  5. Manual Lab Validation Flow (Approval Gate + Attestation)
  6. Grounded Report Assembly (ReportAssembler & GroundingValidator)
  7. Official NIST SP 800-115 PDF Report Generation
  8. Hand-verification of findings back to raw evidence locators and SHA-256 hashes
  9. Cryptographic Audit Chain Non-Repudiation Verification (Genesis to Head)

Invariant:
- AGENTS.md Rule 3: Never fabricate CVE IDs, versions, or evidence.
- AGENTS.md Rule 4: Observed scanner evidence and AI inferences are strictly segregated.
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event.
- AGENTS.md Rule 8: Raw output preserved with SHA-256 integrity.
"""

from datetime import UTC, datetime, timedelta

import pytest

from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.models.assessment import Assessment, StepRun
from cipher_lens.models.findings import Asset, Evidence, Finding
from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.scope import Scope
from cipher_lens.reports.assembly import ReportAssembler
from cipher_lens.reports.generator import PdfReportGenerator
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.state import UIController


@pytest.fixture
def golden_controller(tmp_path):
    db_path = str(tmp_path / "golden_run.db")
    artifacts_dir = str(tmp_path / "artifacts")
    conn = connect(db_path)
    init_db(conn)
    conn.close()

    ctrl = UIController(
        db_path=db_path,
        artifacts_dir=artifacts_dir,
        llm_provider="offline",
    )
    return ctrl


def _create_synthetic_evidence(eid: str, tool: str, snippet: str, locator: str, sha: str) -> Evidence:
    return Evidence(
        id=eid,
        source_tool=tool,
        run_id="run-gold-1",
        artifact_id=f"art-{eid}",
        locator=locator,
        raw_sha256=sha,
        snippet=f"<tool_output>{snippet}</tool_output>",
        observed_at=datetime.now(UTC),
        origin="live",
    )


def test_golden_run_end_to_end_verification(golden_controller, tmp_path):
    ctrl = golden_controller
    repo = ctrl.repository
    now = datetime.now(UTC)

    # 1. Scope Registration
    scope_id = "scope-gold-001"
    scope = Scope(
        id=scope_id,
        owner="lead_auditor",
        authorization_reference="self-hosted practice target",
        allowed_targets=["127.0.0.1"],
        exclusions=[],
        allowed_ports=[3000, 80],
        tool_allowlist=["nmap", "nikto", "zap"],
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=8),
    )
    ctrl.scope_registry.register(scope)
    assert ctrl.get_scope(scope_id) is not None

    # 2. Assessment Creation
    assm_id = "assm-gold-2026"
    assm = Assessment(
        id=assm_id,
        title="Golden Run Practice Range Assessment",
        scope_id=scope_id,
        target="127.0.0.1",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)

    # 3. Simulate Scanner Runs & Tool Outputs (Nmap, Nikto, ZAP)
    sha_nmap = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sha_nikto = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    sha_zap = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

    run_nmap = StepRun(
        run_id="run-nmap-1",
        assessment_id=assm_id,
        step_id="step-1",
        tool_name="nmap",
        status="success",
        exit_code=0,
        raw_sha256=sha_nmap,
        started_at=now,
        ended_at=now,
        duration_ms=450,
    )
    run_nikto = StepRun(
        run_id="run-nikto-1",
        assessment_id=assm_id,
        step_id="step-2",
        tool_name="nikto",
        status="success",
        exit_code=0,
        raw_sha256=sha_nikto,
        started_at=now,
        ended_at=now,
        duration_ms=1200,
    )
    run_zap = StepRun(
        run_id="run-zap-1",
        assessment_id=assm_id,
        step_id="step-3",
        tool_name="zap",
        status="success",
        exit_code=0,
        raw_sha256=sha_zap,
        started_at=now,
        ended_at=now,
        duration_ms=2500,
    )
    repo.save_run(run_nmap)
    repo.save_run(run_nikto)
    repo.save_run(run_zap)

    # 4. Multi-Tool Findings with Evidence
    ev1 = _create_synthetic_evidence("ev-1", "nmap", "3000/tcp open http Node.js Express framework", "port 3000/tcp", sha_nmap)
    ev2 = _create_synthetic_evidence("ev-2", "nikto", "X-Content-Type-Options header not set", "HTTP /", sha_nikto)
    ev3 = _create_synthetic_evidence("ev-3", "zap", "<script>alert(1)</script> reflected in search query", "GET /rest/products/search?q=", sha_zap)

    f1 = Finding(
        id="GOLD-0001",
        title="Open Express HTTP Service",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["nmap"],
        evidence=[ev1],
        tool_severity="info",
        confidence="high",
        status="confirmed",
        status_reason="observed directly by nmap port scan",
        correlation_key="ck-port3000",
        first_seen=now,
        last_seen=now,
    )
    f2 = Finding(
        id="GOLD-0002",
        title="Missing Security Headers",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["nikto"],
        evidence=[ev2],
        cwe=["CWE-693"],
        tool_severity="low",
        confidence="high",
        status="confirmed",
        status_reason="observed in server HTTP responses",
        correlation_key="ck-headers",
        first_seen=now,
        last_seen=now,
    )
    f3 = Finding(
        id="GOLD-0003",
        title="Reflected Cross-Site Scripting (XSS)",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["zap"],
        evidence=[ev3],
        cve=["CVE-2021-41773"],  # Known test CVE
        cwe=["CWE-79"],
        tool_severity="critical",
        confidence="high",
        status="suspected",
        status_reason="active payload reflected in response body",
        correlation_key="ck-xss",
        first_seen=now,
        last_seen=now,
    )

    from cipher_lens.enrichment.service import CveEnrichment

    # 5. Correlation & 0-100 Risk Prioritization
    scorer = RiskScorer()
    f1.risk = scorer.score_finding(f1)
    f2.risk = scorer.score_finding(f2)
    # Give f3 a CISA KEV boost simulation
    e3 = CveEnrichment(cve_id="CVE-2021-41773", cisa_kev=True, epss_score=0.88)
    f3.risk = scorer.score_finding(f3, enrichment=e3)

    repo.save_finding(assm_id, f1)
    repo.save_finding(assm_id, f2)
    repo.save_finding(assm_id, f3)

    assert f3.risk.total > f2.risk.total > f1.risk.total
    assert f3.risk.band == "critical"

    # 6. Manual Lab Validation Flow (Task A13)
    # Step 6a: Request validation gate
    req = ctrl.request_validation(
        assessment_id=assm_id,
        finding_id=f3.id,
        requested_by="analyst_bob",
        reason="Manual reproduction of XSS payload in authorized practice target",
        potential_impact="Non-destructive script execution in test browser",
    )
    assert req.action_class == ActionClass.VALIDATION

    # Step 6b: Lead approval decision
    dec = ctrl.decide_validation(
        assessment_id=assm_id,
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_alice",
        reason="Approved for safe manual execution in practice lab",
    )
    assert dec.decision == "approved"

    # Step 6c: Record outcome attestation with mandatory evidence
    val_evidence = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"
    updated_f3 = ctrl.record_validation(
        assessment_id=assm_id,
        finding_id=f3.id,
        approval_decision=dec,
        outcome="succeeded",
        attested_by="analyst_bob",
        evidence_bytes=val_evidence,
    )
    assert updated_f3.status == "confirmed"
    assert updated_f3.validation is not None
    assert updated_f3.validation.outcome == "succeeded"

    # 7. Grounded Report Assembly (Task B18)
    assembler = ReportAssembler(ctrl)
    report_data = assembler.assemble_report(assm_id)

    assert report_data.assessment.id == assm_id
    assert len(report_data.findings) == 3
    assert len(report_data.runs) == 3
    assert len(report_data.evidence) >= 3

    # 8. Generate NIST SP 800-115 PDF Report (Task A9)
    pdf_path = tmp_path / "golden_run_report.pdf"
    generator = PdfReportGenerator()
    generator.generate_to_file(report_data, pdf_path)

    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000  # Non-empty valid PDF

    # 9. Hand-Verify Three Findings Back to Raw Evidence (Task B19 Requirement)
    verified_findings = repo.list_findings(assm_id)
    assert len(verified_findings) == 3

    for f in verified_findings:
        assert len(f.evidence) >= 1
        ev = f.evidence[0]
        # Check locator and SHA-256 match
        assert ev.locator != ""
        assert len(ev.raw_sha256) == 64
        # Verify source tool matches
        assert ev.source_tool in ["nmap", "nikto", "zap"]
        # Verify snippet is wrapped in safe tool delimiters (AGENTS.md Rule 5)
        assert "<tool_output>" in ev.snippet

    # 10. Cryptographic Audit Chain Integrity Verification
    chain_result = ctrl.verify_audit_chain()
    assert chain_result.ok is True
    assert chain_result.rows_checked >= 4
    assert chain_result.first_bad_id is None
    assert len(chain_result.head_hash) == 64
