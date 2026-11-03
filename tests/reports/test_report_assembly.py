"""Tests for Report Assembly and Grounded Executive Summary (Task B18)."""

from datetime import UTC, datetime

import pytest

from cipher_lens.models.assessment import Assessment, StepRun
from cipher_lens.models.findings import Asset, Evidence, Finding, RiskScore
from cipher_lens.reports.assembly import ReportAssembler
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.state import UIController


@pytest.fixture
def test_controller(tmp_path):
    db_path = str(tmp_path / "test_report.db")
    conn = connect(db_path)
    init_db(conn)
    conn.close()

    ctrl = UIController(db_path=db_path, artifacts_dir=str(tmp_path / "artifacts"), llm_provider="offline")
    return ctrl


def _make_evidence(eid: str, tool: str, sha: str = "abc123sha") -> Evidence:
    return Evidence(
        id=eid,
        source_tool=tool,
        run_id="run-1",
        artifact_id="art-1",
        locator="port 80",
        raw_sha256=sha,
        snippet="<tool_output>Apache 2.4.49 vulnerable</tool_output>",
        observed_at=datetime.now(UTC),
        origin="live",
    )


def test_report_assembler_populates_real_data(test_controller):
    ctrl = test_controller
    repo = ctrl.repository
    now = datetime.now(UTC)

    # Setup assessment
    assm = Assessment(
        id="assm-100",
        title="Production Web Audit",
        scope_id="scope-100",
        target="192.168.1.50",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)

    # Add findings
    f1 = Finding(
        id="VAPT-0001",
        title="Path Traversal in Apache",
        asset=Asset(host="192.168.1.50", port=80),
        sources=["nmap", "burp"],
        evidence=[_make_evidence("e1", "nmap", "sha256-nmap"), _make_evidence("e2", "burp", "sha256-burp")],
        tool_severity="critical",
        confidence="high",
        status="confirmed",
        status_reason="cross-tool validated",
        correlation_key="ck1",
        risk=RiskScore(total=92.0, band="critical", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    f2 = Finding(
        id="VAPT-0002",
        title="Informational Banner",
        asset=Asset(host="192.168.1.50", port=80),
        sources=["nikto"],
        evidence=[_make_evidence("e3", "nikto", "sha256-nikto")],
        tool_severity="info",
        confidence="low",
        status="false_positive",
        status_reason="Triaged as false positive: verified firewall drop rule",
        correlation_key="ck2",
        risk=RiskScore(total=10.0, band="info", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    repo.save_finding("assm-100", f1)
    repo.save_finding("assm-100", f2)

    # Add tool runs
    run = StepRun(
        run_id="run-1",
        assessment_id="assm-100",
        step_id="step-1",
        tool_name="nmap",
        status="success",
        exit_code=0,
        raw_sha256="sha256-nmap",
        started_at=now,
        ended_at=now,
        duration_ms=500,
    )
    repo.save_run(run)

    # Assemble report
    assembler = ReportAssembler(ctrl)
    report_data = assembler.assemble_report("assm-100")

    assert report_data.assessment.id == "assm-100"
    assert len(report_data.findings) == 2
    assert len(report_data.runs) == 1

    # Verify Evidence Index entries match SHA-256 hashes (AGENTS.md Rule 8)
    evidence_shas = {ev.raw_sha256 for ev in report_data.evidence}
    assert "sha256-nmap" in evidence_shas
    assert "sha256-burp" in evidence_shas
    assert "sha256-nikto" in evidence_shas

    # Verify limitations contain required transparency labels (AGENTS.md Rule 13)
    assert any("authorized" in lim.lower() for lim in report_data.limitations)


def test_grounded_executive_summary_fallback_on_unsupported_id(test_controller):
    ctrl = test_controller
    repo = ctrl.repository
    now = datetime.now(UTC)

    assm = Assessment(
        id="assm-200",
        title="Test Target Assessment",
        scope_id="scope-200",
        target="10.0.0.1",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)

    f1 = Finding(
        id="VAPT-0001",
        title="SSH Weak Key Exchange",
        asset=Asset(host="10.0.0.1", port=22),
        sources=["nmap"],
        evidence=[_make_evidence("e1", "nmap")],
        tool_severity="medium",
        confidence="high",
        status="confirmed",
        status_reason="observed",
        correlation_key="ck-ssh",
        risk=RiskScore(total=45.0, band="medium", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    repo.save_finding("assm-200", f1)

    assembler = ReportAssembler(ctrl)
    summary = assembler.generate_executive_summary("assm-200")

    # In offline mode or with validator, should produce a grounded deterministic summary
    assert "VAPT-0001" in summary
    assert "VAPT-9999" not in summary  # No fabricated/hallucinated findings (AGENTS.md Rule 3)
