"""Tests for Findings UI view, filter/sort logic, and triage actions (Task B17).

Safety tests:
- test_triage_requires_rationale: triage rejected without rationale (AGENTS.md Rule 7)
- test_triage_writes_audit_event: every triage state change writes a hash-chained audit event
- test_filter_and_sort_findings: filter/sort logic correctness
"""

from datetime import UTC, datetime

import pytest

from cipher_lens.models.assessment import Assessment
from cipher_lens.models.findings import Asset, Evidence, Finding, RiskScore
from cipher_lens.store.db import connect, init_db
from cipher_lens.ui.findings import apply_triage_decision, filter_and_sort_findings
from cipher_lens.ui.state import UIController


@pytest.fixture
def test_controller(tmp_path):
    db_path = str(tmp_path / "test_findings.db")
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


def _make_evidence(eid: str, tool: str, snippet: str = "snippet", sha: str = "abc123sha") -> Evidence:
    return Evidence(
        id=eid,
        source_tool=tool,
        run_id="run-1",
        artifact_id="art-1",
        locator="line 10",
        raw_sha256=sha,
        snippet=snippet,
        observed_at=_now(),
        origin="live",
    )


def _make_finding(
    fid: str,
    assessment_id: str,
    severity: str,
    status: str,
    tool: str,
    risk_total: float = 50.0,
) -> Finding:
    now = _now()
    return Finding(
        id=fid,
        title=f"Finding {fid}",
        asset=Asset(host="10.0.0.1", port=80),
        sources=[tool],
        evidence=[_make_evidence(f"e-{fid}", tool, sha=f"sha-{fid}")],
        tool_severity=severity,
        confidence="medium",
        status=status,
        status_reason="test",
        correlation_key=f"ck-{fid}",
        risk=RiskScore(total=risk_total, band=severity, factors={}, weights_version="1.0"),
        first_seen=now,
        last_seen=now,
    )


# ── B17 filter / sort tests ─────────────────────────────────────────────────

def test_filter_and_sort_by_risk_desc():
    findings = [
        _make_finding("f1", "a1", "low", "suspected", "nmap", risk_total=30.0),
        _make_finding("f2", "a1", "critical", "confirmed", "burp", risk_total=95.0),
        _make_finding("f3", "a1", "medium", "false_positive", "nikto", risk_total=55.0),
    ]
    result = filter_and_sort_findings(findings, sort_by="risk_desc")
    assert [f.id for f in result] == ["f2", "f3", "f1"]


def test_filter_by_severity():
    findings = [
        _make_finding("f1", "a1", "low", "suspected", "nmap"),
        _make_finding("f2", "a1", "critical", "confirmed", "burp"),
    ]
    result = filter_and_sort_findings(findings, severity_filter=["critical"])
    assert [f.id for f in result] == ["f2"]


def test_filter_by_status():
    findings = [
        _make_finding("f1", "a1", "low", "suspected", "nmap"),
        _make_finding("f2", "a1", "critical", "confirmed", "burp"),
    ]
    result = filter_and_sort_findings(findings, status_filter=["confirmed"])
    assert [f.id for f in result] == ["f2"]


def test_filter_by_tool():
    findings = [
        _make_finding("f1", "a1", "low", "suspected", "nmap"),
        _make_finding("f2", "a1", "critical", "confirmed", "burp"),
    ]
    result = filter_and_sort_findings(findings, tool_filter=["nmap"])
    assert [f.id for f in result] == ["f1"]


def test_empty_filters_return_all():
    findings = [
        _make_finding("f1", "a1", "low", "suspected", "nmap"),
        _make_finding("f2", "a1", "critical", "confirmed", "burp"),
    ]
    result = filter_and_sort_findings(findings)
    assert len(result) == 2


# ── B17 triage safety tests ─────────────────────────────────────────────────

@pytest.fixture
def populated_controller(test_controller, tmp_path):
    ctrl = test_controller
    repo = ctrl.repository
    now = _now()

    assm = Assessment(
        id="a1",
        title="Test Assessment",
        scope_id="s1",
        target="10.0.0.1",
        created_at=now,
        updated_at=now,
    )
    repo.create_assessment(assm)

    f = _make_finding("VAPT-0001", "a1", "high", "suspected", "nmap", risk_total=75.0)
    repo.save_finding("a1", f)
    return ctrl


def test_triage_requires_rationale(populated_controller):
    """Safety: triage with empty rationale must be rejected (AGENTS.md Rule 7)."""
    result = apply_triage_decision(
        ctrl=populated_controller,
        assessment_id="a1",
        finding_id="VAPT-0001",
        new_status="false_positive",
        rationale="",  # Empty — must be rejected
        actor="analyst",
    )
    assert result is False

    # Status must not have changed
    finding = populated_controller.repository.get_finding("a1", "VAPT-0001")
    assert finding.status == "suspected"


def test_triage_writes_audit_event(populated_controller):
    """AGENTS.md Rule 7: every triage state change must write a hash-chained audit event."""
    result = apply_triage_decision(
        ctrl=populated_controller,
        assessment_id="a1",
        finding_id="VAPT-0001",
        new_status="false_positive",
        rationale="Verified by analyst: firewall blocks this port at perimeter.",
        actor="lead-analyst",
    )
    assert result is True

    # Status updated in repository
    updated = populated_controller.repository.get_finding("a1", "VAPT-0001")
    assert updated.status == "false_positive"
    assert "Triaged" in updated.status_reason

    # Hash-chained audit event written (AGENTS.md Rule 7)
    events = populated_controller.get_audit_events("a1")
    triage_events = [e for e in events if e.event_type == "finding_triaged"]
    assert len(triage_events) == 1

    ev = triage_events[0]
    assert ev.payload["finding_id"] == "VAPT-0001"
    assert ev.payload["new_status"] == "false_positive"
    assert ev.payload["old_status"] == "suspected"
    assert ev.payload["rationale"] == "Verified by analyst: firewall blocks this port at perimeter."
    assert ev.actor == "lead-analyst"


def test_triage_accept_risk(populated_controller):
    """Accepted risk triage path also writes audit event."""
    result = apply_triage_decision(
        ctrl=populated_controller,
        assessment_id="a1",
        finding_id="VAPT-0001",
        new_status="accepted_risk",
        rationale="Accepted per business decision: compensating control in place.",
        actor="ciso",
    )
    assert result is True

    updated = populated_controller.repository.get_finding("a1", "VAPT-0001")
    assert updated.status == "accepted_risk"

    events = populated_controller.get_audit_events("a1")
    triage_events = [e for e in events if e.event_type == "finding_triaged"]
    assert any(e.payload["new_status"] == "accepted_risk" for e in triage_events)


def test_triage_audit_failure_rolls_back_status(populated_controller, monkeypatch):
    """AGENTS.md Rule 7: failure to append to audit log must roll back finding status update."""
    def broken_append(*args, **kwargs):
        raise RuntimeError("Simulated audit disk failure")

    monkeypatch.setattr(populated_controller.audit_log, "append", broken_append)

    with pytest.raises(RuntimeError, match="Simulated audit disk failure"):
        apply_triage_decision(
            ctrl=populated_controller,
            assessment_id="a1",
            finding_id="VAPT-0001",
            new_status="false_positive",
            rationale="Analyst rationale",
            actor="analyst",
        )

    # Verification: finding status must remain suspected (not false_positive)
    finding = populated_controller.repository.get_finding("a1", "VAPT-0001")
    assert finding.status == "suspected"
    assert "Triaged" not in finding.status_reason

