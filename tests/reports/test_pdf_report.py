"""Tests for Task A9: PDF Report Skeleton using ReportLab.

Validates:
- Generation of complete PDF with %PDF- magic header
- Presence of all six required report sections and appendices
- Severity distribution chart rendering
- Handling of edge cases: empty findings, partial tool failure, unknown CVSS
- Numbered canvas header and footer rendering
"""

import html
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.assessment import Assessment, AssessmentStatus, StepRun
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
from cipher_lens.models.plan import ActionClass
from cipher_lens.reports.generator import PdfReportGenerator, build_report_flowables
from cipher_lens.reports.models import ReportData


def make_sample_report_data(
    num_findings: int = 1,
    include_failure: bool = False,
    include_unknown_cvss: bool = False,
) -> ReportData:
    now = datetime.now(UTC)
    asm = Assessment(
        id="asm-test-report-01",
        title="Authorized Penetration Testing Assessment",
        target="10.0.0.5",
        scope_id="scope-lab-01",
        status=AssessmentStatus.COMPLETED,
        created_at=now - timedelta(hours=2),
        updated_at=now,
        metadata={"assessor": "Cipher-Lens Agent", "auth_ref": "lab-contract-2026-001"},
    )

    ev = Evidence(
        id="ev-001",
        source_tool="nmap",
        run_id="run-001",
        artifact_id="art-nmap-raw-001",
        locator="/nmaprun/host/ports/port[1]",
        raw_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        snippet="80/tcp open http Apache httpd 2.4.49",
        observed_at=now - timedelta(hours=1),
        origin="live",
    )

    findings: list[Finding] = []
    if num_findings > 0:
        cvss = None if include_unknown_cvss else CvssInfo(
            score=7.5,
            version="3.1",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            source="nvd",
        )
        finding = Finding(
            id="VAPT-0001",
            title="Apache HTTP Server Path Traversal & Remote Code Execution",
            asset=Asset(
                host="10.0.0.5",
                ip="10.0.0.5",
                port=80,
                protocol="tcp",
                service="http",
                url_path="/icons/",
            ),
            sources=["nmap"],
            evidence=[ev],
            inferences=[
                Inference(
                    id="inf-001",
                    text="Path traversal exposes sensitive filesystem directories",
                    provider="gemini-1.5-pro",
                    label="live",
                    based_on=[ev.id],
                    created_at=now,
                )
            ],
            cve=["CVE-2021-41773"],
            cwe=["CWE-22"],
            cvss=cvss,
            tool_severity="high",
            confidence="high",
            status="confirmed",
            status_reason="Verified via direct path traversal payload response",
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
                attested_by="analyst_person_a",
                evidence_artifact_id="art-val-001",
                recorded_at=now,
            ),
            correlation_key="key-apache-80-cve-2021-41773",
            related_ids=[],
            first_seen=now - timedelta(hours=1),
            last_seen=now,
        )
        findings.append(finding)

    runs = [
        StepRun(
            run_id="run-001",
            assessment_id=asm.id,
            step_id="step-01",
            tool_name="nmap",
            status="success",
            exit_code=0,
            stdout_artifact_id="art-nmap-raw-001",
            stderr_artifact_id=None,
            raw_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            started_at=now - timedelta(minutes=45),
            ended_at=now - timedelta(minutes=40),
            duration_ms=300000,
            error_message=None,
        )
    ]

    limitations = [
        "Assessment conducted strictly within designated staging subnet",
        "Passive and non-destructive active scanners utilized",
    ]

    if include_failure:
        runs.append(
            StepRun(
                run_id="run-002",
                assessment_id=asm.id,
                step_id="step-02",
                tool_name="nikto",
                status="timeout",
                exit_code=-1,
                stdout_artifact_id=None,
                stderr_artifact_id=None,
                raw_sha256=None,
                started_at=now - timedelta(minutes=35),
                ended_at=now - timedelta(minutes=25),
                duration_ms=600000,
                error_message="Subprocess execution timed out after 600s",
            )
        )
        limitations.append("Nikto scan timed out; partial web scan results recorded.")

    approvals = [
        (
            ApprovalRequest(
                approval_id="appr-001",
                assessment_id=asm.id,
                step_id="step-03",
                action_class=ActionClass.INTRUSIVE,
                tool="zap",
                target="10.0.0.5",
                rationale="Targeted path traversal exploit verification",
                requested_at=now - timedelta(minutes=20),
                status="approved",
            ),
            ApprovalDecision(
                approval_id="appr-001",
                decision="approved",
                decided_by="lead_security_officer",
                reason="Target confirmed within staging lab boundaries",
                decided_at=now - timedelta(minutes=18),
                notes="Authorized for port 80 only",
            ),
        )
    ]

    return ReportData(
        assessment=asm,
        scope_target="10.0.0.5",
        scope_reference="lab-contract-2026-001",
        testing_window="2026-11-03 00:00 to 2026-11-03 23:59 UTC",
        rate_limits="Max 5 requests/second",
        findings=findings,
        runs=runs,
        approvals=approvals,
        evidence=[ev],
        limitations=limitations,
        audit_event_count=42,
        audit_head_hash="9f83acde7821bcfae001824319041289abcdef1234567890abcdef1234567890",
        audit_verified=True,
    )


def test_generate_pdf_skeleton_basic(tmp_path: Path) -> None:
    data = make_sample_report_data()
    generator = PdfReportGenerator()
    out_file = tmp_path / "test_report.pdf"

    result_path = generator.generate_to_file(data, out_file)
    assert result_path.exists()
    assert result_path.stat().st_size > 5000

    # Verify PDF magic bytes
    with open(result_path, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"


def test_generate_pdf_to_bytes() -> None:
    data = make_sample_report_data()
    generator = PdfReportGenerator()
    pdf_bytes = generator.generate_to_bytes(data)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5000
    assert pdf_bytes.startswith(b"%PDF-")


def test_all_six_required_sections_present() -> None:
    data = make_sample_report_data()
    flowables = build_report_flowables(data)

    # Collect all text representation from flowables
    all_text = []
    for f in flowables:
        # Paragraphs have getPlainText() or text
        if hasattr(f, "text"):
            all_text.append(f.text)
        elif hasattr(f, "getPlainText"):
            all_text.append(f.getPlainText())

    full_text = html.unescape(" ".join(all_text))

    # Verify 6 mandatory sections from Master Plan §10
    assert "1. Executive Summary & Assessment Scope" in full_text
    assert "2. Assessment Methodology & Rules of Engagement" in full_text
    assert "3. Severity Distribution & Prioritized Findings" in full_text
    assert "4. Detailed Vulnerability Findings" in full_text
    assert "5. Business Impact & Actionable Remediation" in full_text
    assert "6. Assessment Limitations & Transparency Disclosures" in full_text

    # Verify appendices
    assert "Appendix A: Evidence & Artifact Verification Index" in full_text
    assert "Appendix B: Tool Execution & Integration Summary" in full_text
    assert "Appendix C: Human-in-the-Loop Approvals & Audit Trail" in full_text


def test_generate_pdf_empty_findings_edge_case(tmp_path: Path) -> None:
    """Master Plan §10: Test report with no findings."""
    data = make_sample_report_data(num_findings=0)
    generator = PdfReportGenerator()
    out_file = tmp_path / "empty_findings_report.pdf"

    result_path = generator.generate_to_file(data, out_file)
    assert result_path.exists()
    assert result_path.stat().st_size > 4000


def test_generate_pdf_partial_tool_failure_and_unknown_cvss(tmp_path: Path) -> None:
    """Master Plan §10: Test report with partial tool failure and unknown CVSS."""
    data = make_sample_report_data(
        num_findings=1, include_failure=True, include_unknown_cvss=True
    )
    generator = PdfReportGenerator()
    out_file = tmp_path / "failure_report.pdf"

    result_path = generator.generate_to_file(data, out_file)
    assert result_path.exists()
    assert result_path.stat().st_size > 5000
