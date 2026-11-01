"""Tests for Nmap XML parser spike and defusedxml safety invariants."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from defusedxml.common import DefusedXmlException

from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation


@pytest.fixture
def synthetic_nmap_bytes() -> bytes:
    fixture_path = Path("tests/fixtures/nmap_synthetic.xml")
    with open(fixture_path, "rb") as f:
        return f.read()


@pytest.fixture
def sample_evidence(synthetic_nmap_bytes: bytes) -> Evidence:
    return Evidence(
        id="ev_test_01",
        source_tool="nmap",
        run_id="run_001",
        artifact_id="art_test_nmap",
        locator="/nmaprun/host",
        raw_sha256=hashlib.sha256(synthetic_nmap_bytes).hexdigest(),
        snippet="<host>...</host>",
        observed_at=datetime.now(UTC),
        origin="sample",
    )


def test_nmap_golden_parse(synthetic_nmap_bytes: bytes, sample_evidence: Evidence):
    """Verify that synthetic Nmap XML parses into valid Observations and RawFindings."""
    adapter = NmapAdapter()
    results = adapter.parse(synthetic_nmap_bytes, sample_evidence)

    observations = [r for r in results if isinstance(r, Observation)]
    findings = [r for r in results if isinstance(r, RawFinding)]

    # We should have observations for host, ports 80 and 443, services
    assert len(observations) >= 3
    host_obs = next((o for o in observations if o.observation_type == "host"), None)
    assert host_obs is not None
    assert host_obs.asset.ip == "10.0.0.5"
    assert host_obs.asset.host == "lab-target.local"

    port_80_obs = next((o for o in observations if o.asset.port == 80), None)
    assert port_80_obs is not None
    assert port_80_obs.asset.service == "http"

    # We should have at least one finding from the NSE vulnerability script
    assert len(findings) >= 1
    cve_finding = next((f for f in findings if "CVE-2021-41773" in f.cve), None)
    assert cve_finding is not None
    assert cve_finding.asset.port == 80
    assert cve_finding.asset.ip == "10.0.0.5"
    assert cve_finding.asset.host == "lab-target.local"
    assert cve_finding.tool_name == "nmap"
    assert cve_finding.tool_severity == "high"
    assert "41773" in cve_finding.raw_evidence.snippet


def test_nmap_parser_rejects_xxe_entity_expansion(sample_evidence: Evidence):
    """Safety rule 6: Parse all XML with defusedxml to block XXE / entity expansion."""
    malicious_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <nmaprun scanner="nmap">
      <host>
        <address addr="&xxe;" addrtype="ipv4"/>
      </host>
    </nmaprun>
    """
    adapter = NmapAdapter()
    with pytest.raises((DefusedXmlException, ValueError, Exception)):
        adapter.parse(malicious_xml, sample_evidence)
