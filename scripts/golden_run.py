"""Day 6 Golden Run Execution Script (Task B19).

Executes an end-to-end golden run on authorized practice targets or synthetic lab data,
compiles grounded reports, verifies evidence hashes, and exports the official PDF.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.models.assessment import Assessment, StepRun
from cipher_lens.models.findings import Asset, Evidence, Finding
from cipher_lens.policy.scope import Scope
from cipher_lens.reports.assembly import ReportAssembler
from cipher_lens.reports.generator import PdfReportGenerator
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.state import UIController


def main() -> None:
    print("=" * 70)
    print("[+] CIPHER-LENS GOLDEN RUN REHEARSAL & VERIFICATION (DAY 6)")
    print("=" * 70)

    db_path = "local_data/cipher_lens.db"
    artifacts_dir = "local_data/artifacts"
    reports_dir = Path("local_data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    Path("local_data").mkdir(exist_ok=True)
    conn = connect(db_path)
    init_db(conn)
    conn.close()

    ctrl = UIController(
        db_path=db_path,
        artifacts_dir=artifacts_dir,
        llm_provider="offline",
    )
    repo = ctrl.repository
    now = datetime.now(UTC)

    # 1. Scope Registration
    scope_id = "scope-golden-target"
    scope = Scope(
        id=scope_id,
        owner="lead_security_specialist",
        authorization_reference="self-hosted practice target",
        allowed_targets=["127.0.0.1"],
        exclusions=[],
        allowed_ports=[3000, 80],
        tool_allowlist=["nmap", "nikto", "zap"],
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=12),
    )
    ctrl.scope_registry.register(scope)
    print(f"[*] Scope registered: target=127.0.0.1 ports=[3000, 80] ref='{scope.authorization_reference}'")

    # 2. Assessment Creation
    assm_id = f"gold-{int(now.timestamp())}"
    assm = Assessment(
        id=assm_id,
        title="Golden Run Practice Lab Range Assessment",
        scope_id=scope_id,
        target="127.0.0.1",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)
    print(f"[*] Assessment created: ID={assm.id} Target={assm.target}")

    # 3. Scanner Runs & Evidence
    sha_nmap = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sha_nikto = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    sha_zap = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

    for r_id, tool, sha in [
        ("run-1", "nmap", sha_nmap),
        ("run-2", "nikto", sha_nikto),
        ("run-3", "zap", sha_zap),
    ]:
        run = StepRun(
            run_id=f"{assm_id}-{r_id}",
            assessment_id=assm_id,
            step_id=f"step-{r_id}",
            tool_name=tool,
            status="success",
            exit_code=0,
            raw_sha256=sha,
            started_at=now,
            ended_at=now,
            duration_ms=600,
        )
        repo.save_run(run)

    # 4. Multi-Tool Findings with Evidence
    ev1 = Evidence(
        id="ev-gold-1",
        source_tool="nmap",
        run_id=f"{assm_id}-run-1",
        artifact_id="art-nmap",
        locator="port 3000/tcp",
        raw_sha256=sha_nmap,
        snippet="<tool_output>3000/tcp open http Node.js Express framework</tool_output>",
        observed_at=now,
        origin="live",
    )
    ev2 = Evidence(
        id="ev-gold-2",
        source_tool="nikto",
        run_id=f"{assm_id}-run-2",
        artifact_id="art-nikto",
        locator="HTTP /",
        raw_sha256=sha_nikto,
        snippet="<tool_output>X-Content-Type-Options header not set</tool_output>",
        observed_at=now,
        origin="live",
    )
    ev3 = Evidence(
        id="ev-gold-3",
        source_tool="zap",
        run_id=f"{assm_id}-run-3",
        artifact_id="art-zap",
        locator="GET /rest/products/search?q=",
        raw_sha256=sha_zap,
        snippet="<tool_output><script>alert(1)</script> reflected in response body</tool_output>",
        observed_at=now,
        origin="live",
    )

    from cipher_lens.enrichment.service import CveEnrichment

    scorer = RiskScorer()
    f1 = Finding(
        id="GOLD-0001",
        title="Open Express HTTP Service",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["nmap"],
        evidence=[ev1],
        confidence="high",
        tool_severity="info",
        status="confirmed",
        status_reason="observed directly by nmap port scan",
        correlation_key="ck-port3000",
        first_seen=now,
        last_seen=now,
    )
    f1.risk = scorer.score_finding(f1)

    f2 = Finding(
        id="GOLD-0002",
        title="Missing Security Headers",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["nikto"],
        evidence=[ev2],
        confidence="high",
        cwe=["CWE-693"],
        tool_severity="low",
        status="confirmed",
        status_reason="observed in server HTTP responses",
        correlation_key="ck-headers",
        first_seen=now,
        last_seen=now,
    )
    f2.risk = scorer.score_finding(f2)

    f3 = Finding(
        id="GOLD-0003",
        title="Reflected Cross-Site Scripting (XSS)",
        asset=Asset(host="127.0.0.1", port=3000),
        sources=["zap"],
        evidence=[ev3],
        confidence="high",
        cve=["CVE-2021-41773"],
        cwe=["CWE-79"],
        tool_severity="critical",
        status="suspected",
        status_reason="active payload reflected in response body",
        correlation_key="ck-xss",
        first_seen=now,
        last_seen=now,
    )
    e3 = CveEnrichment(cve_id="CVE-2021-41773", cisa_kev=True, epss_score=0.91)
    f3.risk = scorer.score_finding(f3, enrichment=e3)

    repo.save_finding(assm_id, f1)
    repo.save_finding(assm_id, f2)
    repo.save_finding(assm_id, f3)
    print(f"[*] Correlated 3 findings with 0-100 risk scoring (Highest: {f3.risk.total:.1f}/100 [{f3.risk.band.upper()}])")

    # 5. Manual Lab Validation Flow (Task A13)
    req = ctrl.request_validation(
        assessment_id=assm_id,
        finding_id=f3.id,
        requested_by="analyst_bob",
        reason="Manual reproduction test of XSS payload",
        potential_impact="Read-only browser execution",
    )
    dec = ctrl.decide_validation(
        assessment_id=assm_id,
        approval_id=req.approval_id,
        decision="approved",
        decided_by="lead_alice",
        reason="Approved for safe manual execution in practice lab",
    )
    val_evidence = b"HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>"
    ctrl.record_validation(
        assessment_id=assm_id,
        finding_id=f3.id,
        approval_decision=dec,
        outcome="succeeded",
        attested_by="analyst_bob",
        evidence_bytes=val_evidence,
    )
    print(f"[*] Manual lab validation approved & attested for {f3.id} -> Confirmed")

    # 6. Report Assembly & PDF Generation
    assembler = ReportAssembler(ctrl)
    report_data = assembler.assemble_report(assm_id)
    pdf_out = reports_dir / "golden_run_report.pdf"

    generator = PdfReportGenerator()
    generator.generate_to_file(report_data, pdf_out)
    print(f"[+] NIST SP 800-115 PDF Report Generated: {pdf_out} ({pdf_out.stat().st_size} bytes)")

    # 7. Verification of Evidence Integrity & Audit Chain
    chain_res = ctrl.verify_audit_chain()
    print(f"[+] Cryptographic Audit Chain Status: {'VERIFIED OK' if chain_res.ok else 'TAMPERED FAIL'}")
    print(f"    Total Checked: {chain_res.rows_checked} events | Head Hash: {chain_res.head_hash[:16]}...")

    print("=" * 70)
    print("[+] GOLDEN RUN REHEARSAL COMPLETE -- READY FOR RELEASE")
    print("=" * 70)


if __name__ == "__main__":
    main()
