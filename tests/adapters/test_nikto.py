"""Tests for Nikto adapter, argv construction, XML parser, and safety invariants.

All XML fixtures in this file are synthetic/sample data.
NEVER use real scan output as fixtures (AGENTS.md Rule 12).
"""

import pathlib
from datetime import UTC, datetime

import defusedxml
import pytest
from pydantic import ValidationError

from cipher_lens.adapters.base import ExecutionContext
from cipher_lens.adapters.nikto import (
    NiktoAdapter,
    NiktoParams,
    build_nikto_argv,
    parse_nikto_xml,
)
from cipher_lens.models.findings import Evidence
from cipher_lens.store.artifacts import ArtifactStore

FIXTURES_DIR = pathlib.Path(__file__).parent.parent / "fixtures"
NIKTO_SYNTHETIC_XML = FIXTURES_DIR / "nikto_synthetic.xml"

# ---------------------------------------------------------------------------
# Argv builder tests (B7)
# ---------------------------------------------------------------------------


def test_build_argv_nikto_minimal():
    """Verify minimal argv for Nikto: -host, -port, -Format xml, -nointeractive, no shell=True."""
    params = NiktoParams(target="10.0.0.5", port=3000)
    argv = build_nikto_argv(params)

    assert argv[0] == "nikto"
    assert "-host" in argv
    assert "10.0.0.5" in argv
    assert "-port" in argv
    assert "3000" in argv
    assert "-Format" in argv
    assert "xml" in argv
    assert "-nointeractive" in argv
    assert "-no404" in argv
    # Safety invariant: argv must be a list, never a string
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)


def test_build_argv_nikto_ssl():
    """Verify SSL flag is appended when ssl=True."""
    params = NiktoParams(target="10.0.0.5", port=443, ssl=True)
    argv = build_nikto_argv(params)
    assert "-ssl" in argv


def test_build_argv_nikto_no_ssl_by_default():
    """Verify -ssl is not present when ssl=False."""
    params = NiktoParams(target="10.0.0.5", port=80)
    argv = build_nikto_argv(params)
    assert "-ssl" not in argv


def test_nikto_disallowed_target_rejected():
    """Safety rule: shell injection in target must be rejected by NiktoParams."""
    with pytest.raises(ValidationError, match="Invalid characters in target"):
        NiktoParams(target="10.0.0.5; rm -rf /", port=80)

    with pytest.raises(ValidationError, match="Invalid characters in target"):
        NiktoParams(target="10.0.0.5 && cat /etc/passwd", port=80)

    with pytest.raises(ValidationError, match="Invalid characters in target"):
        NiktoParams(target="host`id`", port=80)


def test_nikto_target_leading_hyphen_rejected():
    """Break-it check: Flags passed as target must be rejected (ERR-07)."""
    with pytest.raises(ValidationError, match="cannot begin with a hyphen"):
        NiktoParams(target="-vhost", port=80)


def test_nikto_invalid_port_rejected():
    """Port must be in range 1–65535."""
    with pytest.raises(ValidationError):
        NiktoParams(target="10.0.0.5", port=0)

    with pytest.raises(ValidationError):
        NiktoParams(target="10.0.0.5", port=65536)

    with pytest.raises(ValidationError):
        NiktoParams(target="10.0.0.5", port=-1)


# ---------------------------------------------------------------------------
# XML parser tests (B7)
# ---------------------------------------------------------------------------


def _make_evidence() -> Evidence:
    return Evidence(
        id="ev_test_001",
        source_tool="nikto",
        run_id="run_test_001",
        artifact_id="art_test_001",
        locator="/niktoscan",
        raw_sha256="a" * 64,
        snippet="",
        observed_at=datetime.now(UTC),
        origin="sample",  # AGENTS.md Rule 12: fixtures are synthetic/sanitized and labeled
    )


def test_nikto_golden_parse():
    """Golden parse: synthetic fixture produces RawFindings with correct fields."""
    raw = NIKTO_SYNTHETIC_XML.read_bytes()
    evidence = _make_evidence()
    findings = parse_nikto_xml(raw, evidence)

    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"
    for f in findings:
        assert f.tool_name == "nikto"
        assert f.confidence == "medium"  # Nikto alone can never be high-confidence
        assert f.raw_evidence.source_tool == "nikto"
        assert f.raw_evidence.origin == "sample"  # origin='sample' per AGENTS.md Rule 12


def test_nikto_never_confirms():
    """Safety rule: Nikto alone must NEVER yield confidence='high' or status='confirmed'.

    This test fails if the parser starts overclaiming. (AGENTS.md Rule 4)
    """
    raw = NIKTO_SYNTHETIC_XML.read_bytes()
    evidence = _make_evidence()
    findings = parse_nikto_xml(raw, evidence)

    for f in findings:
        assert f.confidence != "high", (
            f"Nikto finding '{f.title}' has confidence='high'; Nikto alone cannot confirm findings"
        )
        # RawFinding has no status field; confirming is done by correlate layer
        assert f.tool_name == "nikto"


def test_nikto_evidence_fields():
    """Each finding must carry artifact_id, locator, hash, tool, timestamp (AGENTS.md Rule 8)."""
    raw = NIKTO_SYNTHETIC_XML.read_bytes()
    evidence = _make_evidence()
    findings = parse_nikto_xml(raw, evidence)

    for f in findings:
        ev = f.raw_evidence
        assert ev.artifact_id == "art_test_001"
        assert ev.locator.startswith("/niktoscan")
        assert ev.raw_sha256 == "a" * 64
        assert ev.source_tool == "nikto"
        assert ev.snippet  # snippet must be non-empty (verbatim from XML)


def test_nikto_xxe_rejection():
    """Security: XML with XXE entity expansion must be rejected by defusedxml."""
    malicious_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<niktoscan>
  <scandetails targetip="10.0.0.5" targetport="80">
    <item id="001" osvdbid="0" method="GET">
      <description>&xxe;</description>
      <uri>/</uri>
    </item>
  </scandetails>
</niktoscan>"""
    evidence = _make_evidence()
    with pytest.raises(defusedxml.common.EntitiesForbidden):
        parse_nikto_xml(malicious_xml, evidence)


def test_nikto_empty_scan_returns_empty():
    """A Nikto scan with no items returns an empty list, not an error."""
    empty_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<niktoscan>
  <scandetails targetip="10.0.0.5" targetport="80">
  </scandetails>
</niktoscan>"""
    evidence = _make_evidence()
    findings = parse_nikto_xml(empty_xml, evidence)
    assert findings == []


# ---------------------------------------------------------------------------
# Healthcheck / binary availability tests (B7)
# ---------------------------------------------------------------------------


def test_nikto_binary_unavailable(monkeypatch):
    """If nikto is not on PATH, healthcheck returns status='unavailable'."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)
    adapter = NiktoAdapter()
    coro = adapter.healthcheck()
    try:
        coro.send(None)
        pytest.fail("Expected StopIteration")
    except StopIteration as exc:
        result = exc.value
    assert result.status == "unavailable"
    assert "not found" in result.message.lower()


def test_nikto_binary_available(monkeypatch):
    """If nikto binary exists, healthcheck returns status='healthy'."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    adapter = NiktoAdapter()
    coro = adapter.healthcheck()
    try:
        coro.send(None)
        pytest.fail("Expected StopIteration")
    except StopIteration as exc:
        result = exc.value
    assert result.status == "healthy"


# ---------------------------------------------------------------------------
# Live run mocked (B7)
# ---------------------------------------------------------------------------


def test_nikto_adapter_run_mocked(tmp_path, monkeypatch):
    """Verify NiktoAdapter.run() uses argv list, saves artifact, returns ExecutionResult."""
    import subprocess

    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    ctx = ExecutionContext(artifact_store=store, rate_limit=None)

    from cipher_lens.models.plan import ActionClass, PlanStep

    step = PlanStep(
        step_id="step-nikto-01",
        tool="nikto",
        action_class=ActionClass.DISCOVERY,
        target="10.0.0.5",
        params={"target": "10.0.0.5", "port": 3000},
        rationale="Web scan",
        expected_outcome="HTTP findings",
        nist_phase="discovery",
    )

    sample_output = NIKTO_SYNTHETIC_XML.read_text(encoding="utf-8")

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert cmd[0] == "nikto"
        assert "-host" in cmd
        assert kwargs.get("shell") is not True  # Invariant: Never use shell=True
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=sample_output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    adapter = NiktoAdapter()
    coro = adapter.run(step, ctx)
    try:
        coro.send(None)
        pytest.fail("Expected StopIteration")
    except StopIteration as exc:
        result = exc.value

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.artifact_id is not None

    raw = store.read_raw(result.artifact_id)
    assert b"lab-target.local" in raw


def test_nikto_adapter_build_argv():
    """Verify NiktoAdapter.build_argv() correctly parses step target and ports."""
    from cipher_lens.models.plan import ActionClass, PlanStep

    adapter = NiktoAdapter()

    # Case 1: Target host with ports in params
    step1 = PlanStep(
        step_id="step-nikto-build-1",
        tool="nikto",
        action_class=ActionClass.DISCOVERY,
        target="127.0.0.1",
        params={"ports": "3000"},
        rationale="Web scan",
        expected_outcome="HTTP findings",
        nist_phase="discovery",
    )
    argv1 = adapter.build_argv(step1)
    assert "-host" in argv1
    assert argv1[argv1.index("-host") + 1] == "127.0.0.1"
    assert "-port" in argv1
    assert argv1[argv1.index("-port") + 1] == "3000"

    # Case 2: URL target with embedded port
    step2 = PlanStep(
        step_id="step-nikto-build-2",
        tool="nikto",
        action_class=ActionClass.DISCOVERY,
        target="http://127.0.0.1:3000",
        params={},
        rationale="Web scan",
        expected_outcome="HTTP findings",
        nist_phase="discovery",
    )
    argv2 = adapter.build_argv(step2)
    assert "-host" in argv2
    assert argv2[argv2.index("-host") + 1] == "127.0.0.1"
    assert "-port" in argv2
    assert argv2[argv2.index("-port") + 1] == "3000"
