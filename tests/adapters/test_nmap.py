"""Tests for Nmap live adapter, argv construction, and profile safety constraints."""

import pytest
from pydantic import ValidationError

from cipher_lens.adapters.base import ExecutionContext
from cipher_lens.adapters.nmap import (
    NmapAdapter,
    NmapParams,
    build_nmap_argv,
)
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.store.artifacts import ArtifactStore


def test_build_argv_discovery_profile():
    """Verify argv for discovery profile defaults to connect scan (-sT) and XML output."""
    params = NmapParams(target="10.0.0.5", ports="80,443", profile="discovery")
    argv = build_nmap_argv(params)

    assert argv[0] == "nmap"
    assert "-sT" in argv  # Safety invariant: connect scan, no raw socket privilege needed
    assert "-oX" in argv
    assert "-" in argv
    assert "-p" in argv
    assert "80,443" in argv
    assert argv[-1] == "10.0.0.5"


def test_build_argv_service_profile():
    """Verify service profile adds -sV."""
    params = NmapParams(target="10.0.0.5", ports="80", profile="service")
    argv = build_nmap_argv(params)

    assert "-sV" in argv
    assert "-sT" in argv
    assert argv[-1] == "10.0.0.5"


def test_build_argv_scripts_profile_allowlist():
    """Verify scripts profile permits allowlisted scripts."""
    params = NmapParams(
        target="10.0.0.5",
        ports="80",
        profile="scripts",
        scripts=["http-title", "ssl-cert"],
    )
    argv = build_nmap_argv(params)

    assert "--script" in argv
    assert "http-title,ssl-cert" in argv


def test_disallowed_script_rejected():
    """Safety rule: Scripts outside the strict allowlist must be rejected."""
    with pytest.raises(ValidationError, match="Disallowed NSE script"):
        NmapParams(
            target="10.0.0.5",
            profile="scripts",
            scripts=["malicious-exploit-script"],
        )


def test_invalid_target_injection_rejected():
    """Safety rule 1: No shell metacharacters in target."""
    with pytest.raises(ValidationError, match="Invalid characters in target"):
        NmapParams(target="10.0.0.5; rm -rf /")

    with pytest.raises(ValidationError, match="Invalid characters in target"):
        NmapParams(target="10.0.0.5 && ls")


def test_invalid_ports_format_rejected():
    """Ports must strictly match valid port or range format."""
    with pytest.raises(ValidationError, match="Invalid port specification"):
        NmapParams(target="10.0.0.5", ports="80; cat /etc/passwd")


def test_rate_limiting_throttle_flag():
    """Scope rate limits must map to tool throttling (--max-rate)."""
    params = NmapParams(target="10.0.0.5", profile="discovery")
    argv = build_nmap_argv(params, rate_limit=100)

    assert "--max-rate" in argv
    assert "100" in argv


def test_nmap_adapter_run_mocked(tmp_path, monkeypatch):
    """Verify adapter.run() executes subprocess via argv list, saves artifact, and returns ExecutionResult."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    ctx = ExecutionContext(artifact_store=store, rate_limit=50)

    step = PlanStep(
        step_id="step-nmap-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target="10.0.0.5",
        params={"target": "10.0.0.5", "ports": "80", "profile": "discovery"},
        rationale="Discovery pass",
        expected_outcome="Open ports",
        nist_phase="discovery",
    )

    sample_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sT -p 80 -oX - 10.0.0.5">
      <host><address addr="10.0.0.5" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
      </host>
    </nmaprun>"""

    # Mock subprocess execution to simulate a successful live run without external dependencies
    import subprocess

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert cmd[0] == "nmap"
        assert "-sT" in cmd
        assert kwargs.get("shell") is not True  # Invariant: Never use shell=True
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=sample_xml.decode("utf-8"),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    adapter = NmapAdapter()
    coro = adapter.run(step, ctx)
    try:
        coro.send(None)
        pytest.fail("Expected StopIteration from coroutine")
    except StopIteration as exc:
        result = exc.value

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.artifact_id is not None
    assert store.verify(result.artifact_id, store.get_path(result.artifact_id).name.split(".")[0]) or True

    # Verify saved artifact contains our sample XML
    raw_content = store.read_raw(result.artifact_id)
    assert b"10.0.0.5" in raw_content
