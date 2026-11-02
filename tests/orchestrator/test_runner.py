"""Tests for the Subprocess Runner / Tool Executor (Task A5).

Invariants tested:
1. Never use shell=True or string commands; argv must be list[str] (AGENTS.md Rule 1).
2. Every tool run goes through policy.authorize() and approvals.require() (AGENTS.md Rule 2).
3. Raw output is saved unmodified with SHA-256 into ArtifactStore (AGENTS.md Rule 8).
4. Timeouts kill the entire process tree and return status="timed_out" (Master Plan A5).
5. Non-zero exit returns status="failed" and captures stderr/exit_code.
6. Scope rate limits throttle tool execution.
7. Lifecycle audit events are written and chain is intact (AGENTS.md Rule 7).
"""

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

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


def _make_scope(target_ip: str = "10.0.0.5") -> Scope:
    now = datetime.now(UTC)
    return Scope(
        id="scope-runner-test",
        owner="tester",
        authorization_reference="AUTH-RUNNER-TEST",
        allowed_targets=[target_ip],
        exclusions=[],
        allowed_ports=[80, 443],
        tool_allowlist=["nmap", "fake_tool"],
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=8),
        rate_limit=5,
    )


def _make_step(
    target: str = "10.0.0.5",
    action_class: ActionClass = ActionClass.DISCOVERY,
    tool: str = "fake_tool",
    port: int = 80,
) -> PlanStep:
    return PlanStep(
        step_id="step-runner-01",
        tool="nmap" if tool == "nmap" else "nmap",  # plan validation allows specific literals
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

    name = "fake_tool"
    status = AdapterStatus.LIVE
    params_model = FakeParams

    async def healthcheck(self) -> HealthResult:
        return HealthResult(status="healthy", message="Fake adapter ready")

    def build_argv(self, step: PlanStep) -> list[str]:
        # Builds a safe argv list running Python to print test output
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
async def test_happy_path_execution(tmp_path: Path):
    """Happy path: argv execution returns status='succeeded', captures stdout, and saves artifact."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store)

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stdout.write('SCAN OK')"]

    result = await runner.execute(step=step, argv=argv)

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.stdout == "SCAN OK"
    assert result.duration_seconds >= 0.0
    assert result.artifact_id is not None

    # Verify artifact in store
    raw = store.read_raw(result.artifact_id)
    assert raw == b"SCAN OK"
    assert store.verify(result.artifact_id, hashlib.sha256(raw).hexdigest())


@pytest.mark.asyncio
async def test_non_zero_exit_fails(tmp_path: Path):
    """Non-zero exit: returns status='failed', captures exit_code and stderr."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store)

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stderr.write('SYNTAX ERROR'); sys.exit(42)"]

    result = await runner.execute(step=step, argv=argv)

    assert result.status == "failed"
    assert result.exit_code == 42
    assert "SYNTAX ERROR" in result.stderr
    assert result.artifact_id is not None
    # Artifact must record the output
    raw = store.read_raw(result.artifact_id)
    assert b"SYNTAX ERROR" in raw


@pytest.mark.asyncio
async def test_timeout_kills_process(tmp_path: Path):
    """Process that exceeds timeout is terminated, returns status='timed_out', and saves artifact."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store, default_timeout=0.4)

    step = _make_step()
    # A script that sleeps for 10 seconds
    argv = [sys.executable, "-c", "import time; time.sleep(10)"]

    result = await runner.execute(step=step, argv=argv, timeout_seconds=0.3)

    assert result.status == "timed_out"
    assert result.artifact_id is not None
    assert result.duration_seconds < 4.0  # Must be killed quickly, not wait 10s


@pytest.mark.asyncio
async def test_string_command_rejected_as_security_violation(tmp_path: Path):
    """Security rule: Never use strings or shell commands. Only argv list[str] allowed."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store)

    step = _make_step()
    # Passing string instead of list must fail immediately
    with pytest.raises(TypeError, match="must be a list"):
        await runner.execute(step=step, argv="python -c 'print(1)'")  # type: ignore

    # Passing empty list must fail
    with pytest.raises(ValueError, match="cannot be empty"):
        await runner.execute(step=step, argv=[])

    # Passing non-string items must fail
    with pytest.raises(TypeError, match="must be a str"):
        await runner.execute(step=step, argv=["python", 123])  # type: ignore


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

    runner = ToolRunner(artifact_store=store, policy_gate=gate, audit_log=audit)

    # Step targeting unauthorized IP 8.8.8.8
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

    approvals = ApprovalManager(audit_log=audit)
    runner = ToolRunner(artifact_store=store, approval_manager=approvals, audit_log=audit)

    # DISCOVERY step on an assessment whose plan was never approved
    step = _make_step()
    argv = [sys.executable, "-c", "print('SHOULD NOT RUN')"]

    with pytest.raises(ApprovalRequiredError, match="requires plan approval"):
        await runner.execute(step=step, argv=argv, assessment_id="unapproved-assess")


@pytest.mark.asyncio
async def test_rate_limiter_throttles_execution():
    """Scope rate limits map to tool throttling."""
    # Rate limit = 4 calls / sec -> min interval 0.25s
    limiter = RateLimiter(rate_limit=4)

    t0 = await limiter.throttle()
    assert t0 == 0.0  # First call doesn't delay

    # Immediately calling again should throttle
    t1 = await limiter.throttle()
    assert t1 > 0.15  # Slept for approximately ~0.25s


@pytest.mark.asyncio
async def test_audit_lifecycle_events_and_chain(tmp_path: Path):
    """Lifecycle audit events (tool_run_started, tool_run_completed) are recorded."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)

    runner = ToolRunner(artifact_store=store, audit_log=audit)

    step = _make_step()
    argv = [sys.executable, "-c", "import sys; sys.stdout.write('AUDITED RUN')"]

    result = await runner.execute(step=step, argv=argv, assessment_id="assess-audit")
    assert result.status == "succeeded"

    # Verify audit chain
    verification = audit.verify_chain()
    assert verification.ok is True
    # At least tool_run_started and tool_run_completed
    assert verification.rows_checked >= 2


@pytest.mark.asyncio
async def test_fake_adapter_integration(tmp_path: Path):
    """Integration: ToolRunner.run_adapter uses adapter's build_argv."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store)

    adapter = FakeAdapter()
    step = _make_step(target="10.0.0.5")

    result = await runner.run_adapter(adapter=adapter, step=step)

    assert result.status == "succeeded"
    assert "FAKE SCAN FOR 10.0.0.5" in result.stdout
    assert result.artifact_id is not None


@pytest.mark.asyncio
async def test_import_only_adapter_rejected(tmp_path: Path):
    """Safety: Attempting to run an IMPORT_ONLY adapter live raises NotImplementedError."""
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    runner = ToolRunner(artifact_store=store)

    adapter = ImportOnlyFakeAdapter()
    step = _make_step()

    with pytest.raises(NotImplementedError, match="import-only"):
        await runner.run_adapter(adapter=adapter, step=step)
