"""Tests for Findings UI view and triage actions (Task B17)."""

from datetime import UTC, datetime

import pytest

from cipher_lens.models.assessment import Assessment
from cipher_lens.models.findings import Asset, Evidence, Finding, RiskScore
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.findings import apply_triage_decision, filter_and_sort_findings
from cipher_lens.ui.state import UIController


@pytest.fixture
def test_controller(tmp_path):
    db_path = str(tmp_path / "test_ui.db")
    conn = connect(db_path)
    init_db(conn)
    conn.close()

    ctrl = UIController(db_path=db_path, artifacts_dir=str(tmp_path / "artifacts"), llm_provider="offline")
    return ctrl


def _make_evidence(eid: str, tool: str, snippet: str = "snippet") -> Evidence:
    return Evidence(
        id=eid,
        source_tool=tool,
        run_id="run-1",
        artifact_id="art-1",
        locator="line 10",
        raw_sha256="abc123sha",
        snippet=snippet,
        observed_at=datetime.now(UTC),
        origin="live",
    )


def test_filter_and_sort_findings():
    now = datetime.now(UTC)
    f1 = Finding(
        id="f1",
        title="Open Port 22",
        asset=Asset(host="10.0.0.1", port=22),
        sources=["nmap"],
        evidence=[_make_evidence("e1", "nmap", "open")],
        tool_severity="low",
        confidence="medium",
        status="suspected",
        status_reason="single scanner observation",
        correlation_key="ck1",
        risk=RiskScore(total=30.0, band="low", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    f2 = Finding(
        id="f2",
        title="SQL Injection",
        asset=Asset(host="10.0.0.1", port=80),
        sources=["burp"],
        evidence=[_make_evidence("e2", "burp", "sqli error")],
        tool_severity="critical",
        confidence="high",
        status="confirmed",
        status_reason="direct active response",
        correlation_key="ck2",
        risk=RiskScore(total=95.0, band="critical", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    f3 = Finding(
        id="f3",
        title="Deprecated TLS",
        asset=Asset(host="10.0.0.2", port=443),
        sources=["nikto"],
        evidence=[_make_evidence("e3", "nikto", "tls 1.0")],
        tool_severity="medium",
        confidence="low",
        status="false_positive",
        status_reason="analyst review",
        correlation_key="ck3",
        risk=RiskScore(total=55.0, band="medium", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )

    findings = [f1, f2, f3]

    # Default sort by risk score descending
    sorted_res = filter_and_sort_findings(findings, sort_by="risk_desc")
    assert [f.id for f in sorted_res] == ["f2", "f3", "f1"]

    # Filter by severity
    crit_only = filter_and_sort_findings(findings, severity_filter=["critical"])
    assert [f.id for f in crit_only] == ["f2"]

    # Filter by status
    confirmed_only = filter_and_sort_findings(findings, status_filter=["confirmed"])
    assert [f.id for f in confirmed_only] == ["f2"]

    # Filter by tool
    nmap_only = filter_and_sort_findings(findings, tool_filter=["nmap"])
    assert [f.id for f in nmap_only] == ["f1"]


def test_apply_triage_decision_writes_audit(test_controller):
    ctrl = test_controller
    repo = ctrl.repository

    now = datetime.now(UTC)
    assm = Assessment(id="a1", title="Test Assessment", scope_id="s1", target="10.0.0.1", created_at=now, updated_at=now)
    repo.create_assessment(assm)

    now = datetime.now(UTC)
    f = Finding(
        id="VAPT-0001",
        title="Test Finding",
        asset=Asset(host="10.0.0.1"),
        sources=["nmap"],
        evidence=[_make_evidence("e1", "nmap")],
        tool_severity="high",
        confidence="medium",
        status="suspected",
        status_reason="unconfirmed",
        correlation_key="ck-test",
        risk=RiskScore(total=75.0, band="high", factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )
    repo.save_finding("a1", f)

    # Apply triage decision: Mark False Positive
    success = apply_triage_decision(
        ctrl=ctrl,
        assessment_id="a1",
        finding_id="VAPT-0001",
        new_status="false_positive",
        rationale="Verified firewall drop rule, port is closed to internal networks.",
        actor="lead-analyst",
    )
    assert success is True

    # Verify status changed in repo
    updated = repo.get_finding("a1", "VAPT-0001")
    assert updated.status == "false_positive"
    assert "Verified firewall drop rule" in updated.status_reason

    # Verify audit event written (AGENTS.md Rule 7)
    events = ctrl.get_audit_events("a1")
    triage_events = [e for e in events if e.event_type == "finding_triaged"]
    assert len(triage_events) == 1
    ev = triage_events[0]
    assert ev.payload["finding_id"] == "VAPT-0001"
    assert ev.payload["new_status"] == "false_positive"
    assert ev.payload["rationale"] == "Verified firewall drop rule, port is closed to internal networks."
    assert ev.actor == "lead-analyst"
