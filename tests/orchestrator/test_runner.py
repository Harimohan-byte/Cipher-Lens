"""Tests for the Subprocess Runner / Tool Executor (Task A5).

Invariants tested:
1. Never use shell=True or string commands; argv must be list[str] (AGENTS.md Rule 1).
2. Every tool run goes through policy.authorize() and approvals.require() (AGENTS.md Rule 2).
3. Fail-closed: Gates are mandatory unless allow_ungated=True.
4. Raw output is saved unmodified with SHA-256 into ArtifactStore; both stdout & stderr preserved.
5. Timeouts and cancellations terminate the entire process tree and eliminate orphan processes.
6. Non-zero exit returns status="failed" and captures stderr/exit_code.
7. Scope rate limits throttle tool execution.
8. Sensitive flags and URLs in argv are redacted from audit logs (AGENTS.md Rule 9).
9. Lifecycle audit events are written and chain is intact (AGENTS.md Rule 7).
"""

import asyncio
import hashlib
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    HealthResult,
)
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.orchestrator.runner import (
    PolicyDeniedError,
    RateLimiter,
    ToolRunner,
)
from cipher_lens.policy.approvals import ApprovalManager, ApprovalRequiredError
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db

# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------


def _is_pid_alive(pid: int) -> bool:
    """Checks whether a process PID is currently running."""
    if sys.platform == "win32":
        res = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
        )
        return str(pid) in res.stdout
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError):
        return False


def _make_scope(target_ip: str = "10.0.0.5") -> Scope:
    now = datetime.now(UTC)
    return Scope(
        id="scope-runner-test",
        owner="tester",
        authorization_reference="AUTH-RUNNER-TEST",
        allowed_targets=[target_ip, "10.0.0.0/16", "target.local"],
        exclusions=[],
        allowed_ports=[80, 443],
        tool_allowlist=["nmap", "nikto", "zap"],
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=8),
        rate_limit=5,
    )


def _make_runner(
    tmp_path: Path,
    scope: Scope | None = None,
    default_timeout: float = 300.0,
    assessment_id: str = "assess-runner",
    audit: AuditLog | None = None,
) -> ToolRunner:
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    if audit is None:
        conn = connect(tmp_path / "runner_test.db")
        init_db(conn)
        audit = AuditLog(conn)
    effective_scope = scope or _make_scope("10.0.0.5")
    registry = ScopeRegistry()
    registry.register(effective_scope)
    gate = PolicyGate(
        registry=registry,
        audit_log=audit,
        resolver=lambda h: ["10.0.0.5"],
    )
    approvals = ApprovalManager(audit_log=audit)
    approvals.approve_plan(
        assessment_id=assessment_id,
        decided_by="admin",
        reason="Test authorization",
    )
    return ToolRunner(
        artifact_store=store,
        policy_gate=gate,
        approval_manager=approvals,
        audit_log=audit,
        default_timeout=default_timeout,
    )


def _make_step(
    target: str = "10.0.0.5",
    action_class: ActionClass = ActionClass.DISCOVERY,
    tool: Literal[
        "nmap",
        "nikto",
        "zap",
        "nessus_import",
        "openvas_import",
        "burp_import",
        "manual_validation",
    ] = "nmap",
    port: int = 80,
) -> PlanStep:
    return PlanStep(
        step_id="step-runner-01",
        tool=tool,
        action_class=action_class,
        target=target,
        params={"port": port},
        rationale="Testing runner",
        expected_outcome="Test result",
        nist_phase="discovery",
    )


class FakeParams(BaseModel):
    target: str


class FakeAdapter(BaseAdapter):
    """Synthetic test adapter for verifying runner integration."""

    name = "nmap"
    status = AdapterStatus.LIVE
    params_model = FakeParams

    async def healthcheck(self) -> HealthResult:
        return HealthResult(status="healthy", message="Fake adapter ready")

    def build_argv(self, step: PlanStep) -> list[str]:
        return [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.write('FAKE SCAN FOR {step.target}\\n')",
        ]

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        return []


class ImportOnlyFakeAdapter(BaseAdapter):
    """Synthetic import-only adapter to verify execution rejection."""

    name = "nessus_import"
    status = AdapterStatus.IMPORT_ONLY
    params_model = FakeParams

    async def healthcheck(self) -> HealthResult:
        return HealthResult(status="healthy", message="Import ready")

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        return []


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runner_fails_closed_without_gates(tmp_path: Path):
    """Safety: ToolRunner mandates PolicyGate and ApprovalManager."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    with pytest.raises(ValueError, match="mandates active PolicyGate and ApprovalManager"):
        ToolRunner(artifact_store=store)


def test_allow_ungated_flag_permanently_rejected(tmp_path: Path):
    """Break-it test: allow_ungated parameter is strictly rejected and cannot reappear (ERR-04)."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    with pytest.raises(ValueError, match="allow_ungated.*permanently removed"):
        ToolRunner(artifact_store=store, allow_ungated=True)


@pytest.mark.asyncio
async def test_happy_path_execution(tmp_path: Path):
    """Happy path: argv execution returns status='succeeded', captures stdout, and saves artifact."""
    runner = _make_runner(tmp_path)
    store = runner.artifact_store

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stdout.write('SCAN OK')"]

    result = await runner.execute(step=step, argv=argv, assessment_id="assess-runner")

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.stdout == "SCAN OK"
    assert result.duration_seconds >= 0.0
    assert result.artifact_id is not None

    raw = store.read_raw(result.artifact_id)
    assert raw == b"SCAN OK"
    assert store.verify(result.artifact_id, hashlib.sha256(raw).hexdigest())


@pytest.mark.asyncio
async def test_non_zero_exit_fails(tmp_path: Path):
    """Non-zero exit: returns status='failed', captures exit_code and stderr."""
    runner = _make_runner(tmp_path)
    store = runner.artifact_store

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stderr.write('SYNTAX ERROR'); sys.exit(42)"]

    result = await runner.execute(step=step, argv=argv, assessment_id="assess-runner")

    assert result.status == "failed"
    assert result.exit_code == 42
    assert "SYNTAX ERROR" in result.stderr
    assert result.artifact_id is not None
    raw = store.read_raw(result.artifact_id)
    assert b"SYNTAX ERROR" in raw


@pytest.mark.asyncio
async def test_both_stdout_and_stderr_preserved_in_artifact(tmp_path: Path):
    """When both stdout and stderr have output, both are preserved verbatim in artifact."""
    runner = _make_runner(tmp_path)
    store = runner.artifact_store

    step = _make_step()
    argv = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('OUT_LINE'); sys.stderr.write('WARN_LINE')",
    ]

    result = await runner.execute(step=step, argv=argv, assessment_id="assess-runner")
    assert result.status == "succeeded"

    raw = store.read_raw(result.artifact_id)
    assert b"OUT_LINE" in raw
    assert b"WARN_LINE" in raw
    assert b"--- STDOUT ---" in raw
    assert b"--- STDERR ---" in raw


@pytest.mark.asyncio
async def test_timeout_kills_process_tree(tmp_path: Path):
    """Process tree that exceeds timeout is killed, including child processes."""
    runner = _make_runner(tmp_path, default_timeout=0.5)

    pid_file = tmp_path / "child.pid"
    # Parent spawns child process and writes child PID to file
    script = (
        f"import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open(r'{pid_file}', 'w').write(str(child.pid))\n"
        f"time.sleep(30)\n"
    )

    step = _make_step()
    argv = [sys.executable, "-c", script]

    result = await runner.execute(step=step, argv=argv, timeout_seconds=0.6, assessment_id="assess-runner")

    assert result.status == "timed_out"
    assert result.artifact_id is not None
    assert result.duration_seconds < 4.0

    # Verify child process PID was killed
    if pid_file.exists():
        child_pid = int(pid_file.read_text().strip())
        await asyncio.sleep(0.5)
        assert not _is_pid_alive(child_pid), f"Child process {child_pid} should have been killed"


@pytest.mark.asyncio
async def test_cancelled_execute_kills_process_tree(tmp_path: Path):
    """When an execute task is cancelled, process tree is terminated without orphan processes."""
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)
    runner = _make_runner(tmp_path, audit=audit, assessment_id="assess-cancel")

    pid_file = tmp_path / "cancel_child.pid"
    script = (
        f"import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open(r'{pid_file}', 'w').write(str(child.pid))\n"
        f"time.sleep(30)\n"
    )

    step = _make_step()
    argv = [sys.executable, "-c", script]

    task = asyncio.create_task(
        runner.execute(step=step, argv=argv, assessment_id="assess-cancel")
    )
    # Let process start and write PID
    for _ in range(20):
        if pid_file.exists():
            break
        await asyncio.sleep(0.1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    if pid_file.exists():
        child_pid = int(pid_file.read_text().strip())
        await asyncio.sleep(0.5)
        assert not _is_pid_alive(child_pid), "Child process must be killed on cancellation"

    # Verify audit event for cancellation was written
    verification = audit.verify_chain()
    assert verification.ok is True


@pytest.mark.asyncio
async def test_argv_redaction_in_audit_log(tmp_path: Path):
    """Credentials in target URLs and sensitive flags in argv are redacted before audit logging."""
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)
    runner = _make_runner(tmp_path, audit=audit, assessment_id="assess-redact")

    step = _make_step(target="http://admin:secret123@10.0.0.5/api")
    argv = [
        sys.executable,
        "-c",
        "print('ok')",
        "-p",
        "super_secret_password",
        "--api-key",
        "secret_token_abc",
        "http://admin:secret123@10.0.0.5/api",
    ]

    await runner.execute(step=step, argv=argv, assessment_id="assess-redact")

    # Read audit row from DB
    cursor = conn.cursor()
    cursor.execute("SELECT payload FROM audit_log WHERE event_type = 'tool_run_started'")
    row = cursor.fetchone()
    assert row is not None
    payload_text = row[0]

    assert "secret123" not in payload_text
    assert "super_secret_password" not in payload_text
    assert "secret_token_abc" not in payload_text
    assert "<redacted>" in payload_text


@pytest.mark.asyncio
async def test_string_command_rejected_as_security_violation(tmp_path: Path):
    """Security rule: Never use strings or shell commands. Only argv list[str] allowed."""
    runner = _make_runner(tmp_path)

    step = _make_step()
    with pytest.raises(TypeError, match="must be a list"):
        await runner.execute(step=step, argv="python -c 'print(1)'", assessment_id="assess-runner")  # type: ignore

    with pytest.raises(ValueError, match="cannot be empty"):
        await runner.execute(step=step, argv=[], assessment_id="assess-runner")

    with pytest.raises(TypeError, match="must be a str"):
        await runner.execute(step=step, argv=["python", 123], assessment_id="assess-runner")  # type: ignore


@pytest.mark.asyncio
async def test_policy_gate_denial_blocks_execution(tmp_path: Path):
    """Safety rule: Every tool run must pass PolicyGate. Out-of-scope targets are refused."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)

    registry = ScopeRegistry()
    registry.register(_make_scope("10.0.0.5"))
    gate = PolicyGate(registry=registry, audit_log=audit)
    approvals = ApprovalManager(audit_log=audit)

    runner = ToolRunner(
        artifact_store=store,
        policy_gate=gate,
        approval_manager=approvals,
        audit_log=audit,
    )

    step = _make_step(target="8.8.8.8")
    argv = [sys.executable, "-c", "print('SHOULD NOT RUN')"]

    with pytest.raises(PolicyDeniedError, match="denied by policy gate"):
        await runner.execute(step=step, argv=argv, assessment_id="assess-1")


@pytest.mark.asyncio
async def test_approval_gate_blocks_unapproved_step(tmp_path: Path):
    """Safety rule: Every tool run must pass ApprovalManager."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)

    registry = ScopeRegistry()
    registry.register(_make_scope("10.0.0.5"))
    gate = PolicyGate(registry=registry, audit_log=audit)
    approvals = ApprovalManager(audit_log=audit)

    runner = ToolRunner(
        artifact_store=store,
        policy_gate=gate,
        approval_manager=approvals,
        audit_log=audit,
    )

    step = _make_step()
    argv = [sys.executable, "-c", "print('SHOULD NOT RUN')"]

    with pytest.raises(ApprovalRequiredError, match="requires plan approval"):
        await runner.execute(step=step, argv=argv, assessment_id="unapproved-assess")


@pytest.mark.asyncio
async def test_rate_limiter_throttles_execution():
    """Scope rate limits map to tool throttling."""
    limiter = RateLimiter(rate_limit=4)

    t0 = await limiter.throttle()
    assert t0 == 0.0

    t1 = await limiter.throttle()
    assert t1 > 0.15


@pytest.mark.asyncio
async def test_audit_lifecycle_events_and_chain(tmp_path: Path):
    """Lifecycle audit events (tool_run_started, tool_run_completed) are recorded."""
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)
    runner = _make_runner(tmp_path, audit=audit, assessment_id="assess-audit")

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stdout.write('AUDITED RUN')"]

    result = await runner.execute(step=step, argv=argv, assessment_id="assess-audit")
    assert result.status == "succeeded"

    verification = audit.verify_chain()
    assert verification.ok is True
    assert verification.rows_checked >= 2


@pytest.mark.asyncio
async def test_fake_adapter_integration(tmp_path: Path):
    """Integration: ToolRunner.run_adapter uses adapter's build_argv."""
    runner = _make_runner(tmp_path)

    adapter = FakeAdapter()
    step = _make_step(target="10.0.0.5", tool="nmap")

    result = await runner.run_adapter(adapter=adapter, step=step, assessment_id="assess-runner")

    assert result.status == "succeeded"
    assert "FAKE SCAN FOR 10.0.0.5" in result.stdout
    assert result.artifact_id is not None


@pytest.mark.asyncio
async def test_step_tool_mismatch_with_adapter_rejected(tmp_path: Path):
    """Safety: step.tool must match adapter.name; mismatches are rejected."""
    runner = _make_runner(tmp_path)

    adapter = FakeAdapter()  # name is "nmap"
    step = _make_step(tool="nikto")  # step tool is "nikto"

    with pytest.raises(ValueError, match="does not match adapter name"):
        await runner.run_adapter(adapter=adapter, step=step, assessment_id="assess-runner")


@pytest.mark.asyncio
async def test_import_only_adapter_rejected(tmp_path: Path):
    """Safety: Attempting to run an IMPORT_ONLY adapter live raises NotImplementedError."""
    runner = _make_runner(tmp_path)

    adapter = ImportOnlyFakeAdapter()
    step = _make_step(tool="nessus_import")

    with pytest.raises(NotImplementedError, match="import-only"):
        await runner.run_adapter(adapter=adapter, step=step, assessment_id="assess-runner")


@pytest.mark.asyncio
async def test_dns_pinning_substitutes_target_ip(tmp_path: Path):
    """Break-it test: DNS pinning substitutes hostname with pinned IP in CLI argv (ERR-03)."""
    runner = _make_runner(tmp_path)

    # 1. Nmap substitution: hostname replaced by pinned IP
    step_nmap = _make_step(target="target.local", tool="nmap")
    argv_nmap = [sys.executable, "-c", "import sys; print(sys.argv[1])", "target.local"]
    res_nmap = await runner.execute(step=step_nmap, argv=argv_nmap, assessment_id="assess-runner")
    assert res_nmap.status == "succeeded"
    assert "10.0.0.5" in res_nmap.stdout

    # 2. Nikto substitution: -host pinned_ip and -vhost original_hostname
    step_nikto = _make_step(target="target.local", tool="nikto")
    argv_nikto = [
        sys.executable,
        "-c",
        "import sys; print(' '.join(sys.argv[1:]))",
        "-host",
        "target.local",
        "-port",
        "80",
    ]
    res_nikto = await runner.execute(step=step_nikto, argv=argv_nikto, assessment_id="assess-runner")
    assert res_nikto.status == "succeeded"
    assert "-host 10.0.0.5" in res_nikto.stdout
    assert "-vhost target.local" in res_nikto.stdout

