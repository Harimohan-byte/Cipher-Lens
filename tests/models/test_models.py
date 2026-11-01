"""Tests for core Pydantic data models and safety contracts."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cipher_lens.models.findings import (
    Asset,
    CvssInfo,
    Evidence,
    FactorValue,
    Finding,
    Inference,
    RiskScore,
)
from cipher_lens.models.plan import ActionClass, PlanStep


def test_action_class_enum():
    """Verify supported ActionClass values."""
    assert ActionClass.IMPORT.value == "import"
    assert ActionClass.DISCOVERY.value == "discovery"
    assert ActionClass.SCAN.value == "scan"
    assert ActionClass.INTRUSIVE.value == "intrusive"
    assert ActionClass.VALIDATION.value == "validation"

    with pytest.raises(ValueError):
        ActionClass("invalid_action")


def test_finding_requires_evidence():
    """Safety rule: A Finding cannot exist without at least one observed Evidence record."""
    asset = Asset(host="10.0.0.1", port=80, protocol="tcp", service="http")
    now = datetime.now(UTC)

    # Attempt to create finding with empty evidence list must fail
    with pytest.raises(ValidationError, match="At least one evidence record is required"):
        Finding(
            id="VAPT-0001",
            title="Open HTTP Port",
            asset=asset,
            sources=["nmap"],
            evidence=[],  # VIOLATION: no evidence
            tool_severity="info",
            confidence="high",
            status="confirmed",
            status_reason="Service detected",
            correlation_key="test-key",
            first_seen=now,
            last_seen=now,
        )


def test_evidence_and_inference_are_strictly_separated():
    """Safety rule 4: Observed evidence and AI inference are separate fields and never mixed."""
    asset = Asset(host="10.0.0.1", port=80, protocol="tcp", service="http")
    now = datetime.now(UTC)

    inference = Inference(
        id="inf-01",
        text="Port 80 may be running Apache.",
        provider="gemini",
        label="rule-based",
        based_on=["ev-01"],
        created_at=now,
    )

    # Placing an Inference into evidence list must fail validation
    with pytest.raises(ValidationError):
        Finding(
            id="VAPT-0001",
            title="Open HTTP Port",
            asset=asset,
            sources=["nmap"],
            evidence=[inference],  # VIOLATION: Inference object inside evidence list
            tool_severity="info",
            confidence="high",
            status="confirmed",
            status_reason="Service detected",
            correlation_key="test-key",
            first_seen=now,
            last_seen=now,
        )


def test_valid_finding_construction():
    """Verify that a properly constructed finding with evidence succeeds and serializes."""
    asset = Asset(host="10.0.0.1", port=80, protocol="tcp", service="http")
    now = datetime.now(UTC)

    ev = Evidence(
        id="ev-01",
        source_tool="nmap",
        run_id="run-001",
        artifact_id="art-nmap-01",
        locator="/nmaprun/host/ports/port[@portid='80']",
        raw_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        snippet="<port protocol='tcp' portid='80'><state state='open'/></port>",
        observed_at=now,
        origin="sample",
    )

    inf = Inference(
        id="inf-01",
        text="Web server detected; check for outdated HTTP software.",
        provider="gemini",
        label="rule-based",
        based_on=["ev-01"],
        created_at=now,
    )

    cvss = CvssInfo(score=5.3, version="3.1", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", source="nvd")

    risk = RiskScore(
        total=53.0,
        band="medium",
        factors={
            "severity": FactorValue(value=0.53, source="nvd", description="CVSS base"),
            "confidence": FactorValue(value=1.0, source="heuristic", description="direct proof"),
        },
        weights_version="1.0",
    )

    finding = Finding(
        id="VAPT-0001",
        title="Cleartext HTTP Service",
        asset=asset,
        sources=["nmap"],
        evidence=[ev],
        inferences=[inf],
        cve=["CVE-2023-1234"],
        cwe=["CWE-319"],
        cvss=cvss,
        tool_severity="medium",
        confidence="high",
        status="confirmed",
        status_reason="Direct port open evidence",
        risk=risk,
        correlation_key="10.0.0.1:80:CWE-319",
        first_seen=now,
        last_seen=now,
    )

    json_data = finding.model_dump_json()
    assert "VAPT-0001" in json_data
    assert "Cleartext HTTP Service" in json_data

    # Test round trip
    restored = Finding.model_validate_json(json_data)
    assert restored.id == finding.id
    assert len(restored.evidence) == 1
    assert restored.evidence[0].raw_sha256 == ev.raw_sha256


def test_plan_step_validation():
    """Verify PlanStep creation and action class enforcement."""
    step = PlanStep(
        step_id="step-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target="192.168.1.1",
        params={"ports": "80,443", "profile": "discovery"},
        rationale="Initial port discovery for asset",
        triggered_by=["scope_registration"],
        expected_outcome="List of open TCP ports",
        nist_phase="discovery",
    )

    assert step.action_class == ActionClass.DISCOVERY
    assert step.tool == "nmap"

    with pytest.raises(ValidationError):
        PlanStep(
            step_id="step-bad",
            tool="unsupported_scanner",  # Unsupported tool
            action_class=ActionClass.SCAN,
            target="192.168.1.1",
            rationale="test",
            expected_outcome="test",
            nist_phase="discovery",
        )
