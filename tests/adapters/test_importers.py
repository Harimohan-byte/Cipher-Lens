"""Tests for B10: Importers (Nessus, OpenVAS, Burp).

Safety Invariants:
1. Parse all XML with defusedxml (AGENTS.md Rule 6).
2. Out-of-scope hosts must be dropped with a warning, never silently ingested (§7 B10).
3. Raw output saved unmodified with SHA-256 and locator metadata.
4. Entities expansion / XXE rejected.
5. All fixtures labeled origin='import' or 'sample'.
"""

from datetime import UTC, datetime
from pathlib import Path

import defusedxml.common
import pytest

from cipher_lens.adapters.imports.burp import BurpImporter
from cipher_lens.adapters.imports.nessus import NessusImporter
from cipher_lens.adapters.imports.openvas import OpenvasImporter
from cipher_lens.models.findings import Evidence
from cipher_lens.policy.scope import Scope

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def sample_scope():
    return Scope(
        id="scope-lab-01",
        owner="Security Team",
        authorization_reference="AUTH-2026-LAB",
        allowed_targets=["10.0.0.5", "lab-target.local"],
        exclusions=["192.168.1.100", "8.8.8.8", "203.0.113.50"],
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
    )


def make_evidence(tool: str) -> Evidence:
    return Evidence(
        id=f"ev_test_{tool}_01",
        source_tool=tool,
        run_id="run_test_01",
        artifact_id="art_test_01",
        locator="/root",
        raw_sha256="0" * 64,
        snippet="",
        observed_at=datetime.now(UTC),
        origin="sample",
    )


def test_nessus_golden_parse_and_scope_filtering(sample_scope):
    """NessusImporter parses valid ReportItems and drops out-of-scope hosts."""
    importer = NessusImporter()
    raw = (FIXTURES_DIR / "nessus_synthetic.nessus").read_bytes()
    ev = make_evidence("nessus")

    res = importer.parse_with_scope(raw, ev, scope=sample_scope)
    findings = res.findings
    warnings = res.warnings

    # 10.0.0.5 is in scope, 192.168.1.100 is excluded/out-of-scope
    assert len(findings) == 1
    assert findings[0].tool_name == "nessus"
    assert findings[0].asset.ip == "10.0.0.5"
    assert "CVE-2021-41773" in findings[0].cve
    assert findings[0].tool_severity in ("high", "medium", "critical", "low")

    # Warning for out-of-scope dropped host
    assert len(warnings) == 1
    assert "192.168.1.100" in warnings[0]


def test_openvas_golden_parse_and_scope_filtering(sample_scope):
    """OpenvasImporter parses results and drops out-of-scope hosts."""
    importer = OpenvasImporter()
    raw = (FIXTURES_DIR / "openvas_synthetic.xml").read_bytes()
    ev = make_evidence("openvas")

    res = importer.parse_with_scope(raw, ev, scope=sample_scope)
    findings = res.findings
    warnings = res.warnings

    assert len(findings) == 1
    assert findings[0].tool_name == "openvas"
    assert findings[0].asset.ip == "10.0.0.5"
    assert "CVE-2021-41773" in findings[0].cve

    # 8.8.8.8 is out-of-scope
    assert len(warnings) == 1
    assert "8.8.8.8" in warnings[0]


def test_burp_golden_parse_redaction_and_scope(sample_scope):
    """BurpImporter drops out of scope issues and redacts Authorization / Cookies from snippets."""
    importer = BurpImporter()
    raw = (FIXTURES_DIR / "burp_synthetic.xml").read_bytes()
    ev = make_evidence("burp")

    res = importer.parse_with_scope(raw, ev, scope=sample_scope)
    findings = res.findings
    warnings = res.warnings

    assert len(findings) == 1
    f = findings[0]
    assert f.tool_name == "burp"
    assert f.asset.host == "lab-target.local" or f.asset.ip == "10.0.0.5"
    assert f.asset.url_path == "/search"

    # Redaction verification (AGENTS.md Rule 9)
    assert "secret-token-12345" not in f.raw_evidence.snippet
    assert "secret-cookie-value" not in f.raw_evidence.snippet
    assert "<redacted>" in f.raw_evidence.snippet

    # 203.0.113.50 is out of scope
    assert len(warnings) >= 1
    assert any("203.0.113.50" in w or "evil-unauthorized.com" in w for w in warnings)


def test_importers_xxe_rejection():
    """All XML importers reject entity expansion attacks."""
    malicious_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

    for importer in [NessusImporter(), OpenvasImporter(), BurpImporter()]:
        with pytest.raises(defusedxml.common.EntitiesForbidden):
            importer.parse(malicious_xml, make_evidence("test"))


def test_importers_reject_live_run():
    """All import-only adapters reject live run() with NotImplementedError."""
    import asyncio

    from cipher_lens.adapters.base import ExecutionContext
    from cipher_lens.models.plan import ActionClass, PlanStep
    from cipher_lens.store.artifacts import ArtifactStore

    step = PlanStep(
        step_id="step-import-01",
        tool="nessus_import",
        action_class=ActionClass.IMPORT,
        target="10.0.0.5",
        params={},
        rationale="import file",
        expected_outcome="imported findings",
        nist_phase="discovery",
    )
    ctx = ExecutionContext(artifact_store=ArtifactStore(Path("local_data/test_art")))

    for imp in [NessusImporter(), OpenvasImporter(), BurpImporter()]:
        with pytest.raises(NotImplementedError, match="import-only"):
            asyncio.run(imp.run(step, ctx))

