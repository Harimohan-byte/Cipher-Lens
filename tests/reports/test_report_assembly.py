"""Tests for Report Assembly and Grounded Executive Summary (Task B18).

Safety tests:
- test_executive_summary_no_hallucinated_ids: summary references only real finding IDs (AGENTS.md Rule 3)
- test_evidence_index_matches_sha256_hashes: evidence index must carry SHA-256 hashes (Rule 8)
- test_limitations_labeled: limitations list must be present and reference authorization bounds (Rule 13)
"""

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
    return UIController(
        db_path=db_path,
        artifacts_dir=str(tmp_path / "artifacts"),
        llm_provider="offline",
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _make_evidence(eid: str, tool: str, sha: str) -> Evidence:
    return Evidence(
        id=eid,
        source_tool=tool,
        run_id="run-1",
        artifact_id="art-1",
        locator="port 80",
        raw_sha256=sha,
        snippet="<tool_output>example output</tool_output>",
        observed_at=_now(),
        origin="live",
    )


def _make_finding(
    fid: str,
    assessment_id: str,
    severity: str,
    status: str,
    shas: list[str],
    tools: list[str] | None = None,
) -> Finding:
    if tools is None:
        tools = ["nmap"]
    now = _now()
    evidence = [_make_evidence(f"{fid}-e{i}", t, sha) for i, (t, sha) in enumerate(zip(tools, shas, strict=False))]
    return Finding(
        id=fid,
        title=f"Finding {fid}",
        asset=Asset(host="192.168.1.50", port=80),
        sources=tools,
        evidence=evidence,
        tool_severity=severity,
        confidence="high",
        status=status,
        status_reason="observed",
        correlation_key=f"ck-{fid}",
        risk=RiskScore(total=80.0, band=severity, factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )


@pytest.fixture
def populated_controller(test_controller):
    ctrl = test_controller
    repo = ctrl.repository
    now = _now()

    assm = Assessment(
        id="assm-100",
        title="Production Web Audit",
        scope_id="scope-100",
        target="192.168.1.50",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)

    f1 = _make_finding(
        "VAPT-0001", "assm-100", "critical", "confirmed",
        shas=["sha256-nmap", "sha256-burp"],
        tools=["nmap", "burp"],
    )
    f2 = _make_finding(
        "VAPT-0002", "assm-100", "info", "false_positive",
        shas=["sha256-nikto"],
        tools=["nikto"],
    )
    repo.save_finding("assm-100", f1)
    repo.save_finding("assm-100", f2)

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
    return ctrl


def test_report_assembler_populates_real_data(populated_controller):
    assembler = ReportAssembler(populated_controller)
    report_data = assembler.assemble_report("assm-100")

    assert report_data.assessment.id == "assm-100"
    assert len(report_data.findings) == 2
    assert len(report_data.runs) == 1


def test_evidence_index_matches_sha256_hashes(populated_controller):
    """AGENTS.md Rule 8: evidence index entries must carry correct SHA-256 hashes."""
    assembler = ReportAssembler(populated_controller)
    report_data = assembler.assemble_report("assm-100")

    evidence_shas = {ev.raw_sha256 for ev in report_data.evidence}
    assert "sha256-nmap" in evidence_shas
    assert "sha256-burp" in evidence_shas
    assert "sha256-nikto" in evidence_shas


def test_limitations_labeled(populated_controller):
    """AGENTS.md Rule 13: limitations must be non-empty and reference authorized bounds."""
    assembler = ReportAssembler(populated_controller)
    report_data = assembler.assemble_report("assm-100")

    assert len(report_data.limitations) > 0
    combined = " ".join(report_data.limitations).lower()
    assert "authorized" in combined


def test_executive_summary_no_hallucinated_ids(populated_controller):
    """AGENTS.md Rule 3: executive summary must not reference non-existent finding IDs."""
    assembler = ReportAssembler(populated_controller)
    summary = assembler.generate_executive_summary("assm-100")

    # Must contain real finding ID
    assert "VAPT-0001" in summary
    # Must NOT reference a fabricated finding ID (AGENTS.md Rule 3)
    assert "VAPT-9999" not in summary
    assert "VAPT-8888" not in summary


def test_executive_summary_is_deterministic_fallback(populated_controller):
    """Summary must be clearly labeled as deterministic/fallback (AGENTS.md Rule 13)."""
    assembler = ReportAssembler(populated_controller)
    summary = assembler.generate_executive_summary("assm-100")

    # Deterministic fallback label must be present
    assert "DETERMINISTIC FALLBACK" in summary


def test_executive_summary_calls_llm_when_available(populated_controller):
    """LLM client is invoked when available and sets AI-grounded label (AGENTS.md Rule 5)."""
    from cipher_lens.planner.llm import LlmClient

    called = []

    def mock_backend(prompt: str, model: str, api_key: str) -> str:
        called.append(prompt)
        return '{"summary": "Security testing identified confirmed finding VAPT-0001 with high confidence."}'

    mock_llm = LlmClient(
        provider="mock",
        primary_key="k1",
        primary_model="gemini-3.5-flash-lite",
        raw_completion_fn=mock_backend,
    )
    populated_controller.llm_client = mock_llm

    assembler = ReportAssembler(populated_controller)
    summary = assembler.generate_executive_summary("assm-100")

    assert len(called) == 1
    assert "AI-GENERATED · EVIDENCE-GROUNDED" in summary
    assert "VAPT-0001" in summary

    report_data = assembler.assemble_report("assm-100")
    assert report_data.executive_summary_badge == "[AI-GENERATED · EVIDENCE-GROUNDED]"
    assert "VAPT-0001" in report_data.executive_summary
    assert "[DETERMINISTIC FALLBACK" not in report_data.executive_summary

