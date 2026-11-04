# DECISION: Subprocesses are executed exclusively with argv lists via asyncio.create_subprocess_exec; shell=True is never permitted.
# DECISION: Timeouts and task cancellations terminate the entire process group (POSIX: killpg, Windows: taskkill /F /T /PID) to prevent orphan scanner processes.
# DECISION: Every tool run must be authorized by PolicyGate and approved by ApprovalManager before any process is spawned (fail-closed unless allow_ungated=True).
# DECISION: All raw stdout and stderr output is saved into ArtifactStore with SHA-256 tracking. When both streams are non-empty, they are preserved in a delimited combined format.
# DECISION: Sensitive CLI flag arguments and URLs in argv are redacted before audit storage to satisfy AGENTS.md Rule 9.
"""Subprocess runner and execution coordinator under policy and approval gates."""

import asyncio
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    ExecutionResult,
)
from cipher_lens.models.plan import PlanStep
from cipher_lens.policy.approvals import ApprovalManager
from cipher_lens.policy.gate import PolicyGate, parse_target, redact_target
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog

_SENSITIVE_FLAGS = {
    "-p",
    "--password",
    "-a",
    "--api-key",
    "--apikey",
    "--token",
    "--secret",
    "--auth",
    "-u",
    "--user",
}


def redact_argv(argv: list[str]) -> list[str]:
    """Redacts credentials and sensitive flag values from command-line arguments."""
    redacted: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue

        lower_arg = arg.lower()
        if lower_arg in _SENSITIVE_FLAGS:
            redacted.append(arg)
            skip_next = True
            continue

        if "=" in arg:
            prefix, sep, _ = arg.partition("=")
            if prefix.lower() in _SENSITIVE_FLAGS:
                redacted.append(f"{prefix}{sep}<redacted>")
                continue

        redacted.append(redact_target(arg))

    return redacted


class RunnerError(Exception):
    """Base exception for runner and execution failures."""


class PolicyDeniedError(RunnerError):
    """Raised when a proposed tool execution is denied by the policy gate."""


class SubprocessExecutionError(RunnerError):
    """Raised when an unexpected error occurs during subprocess execution."""


class RateLimiter:
    """Enforces execution throttling based on scope or execution rate limits."""

    def __init__(self, rate_limit: int | None = None) -> None:
        self.rate_limit = rate_limit
        self.min_interval = (1.0 / rate_limit) if (rate_limit and rate_limit > 0) else 0.0
        self._last_time = 0.0

    async def throttle(self) -> float:
        """Sleeps as needed to satisfy rate limiting. Returns actual sleep duration in seconds."""
        if self.min_interval <= 0:
            return 0.0
        loop = asyncio.get_running_loop()
        now = loop.time()
        elapsed = now - self._last_time
        delay = self.min_interval - elapsed
        if delay > 0:
            await asyncio.sleep(delay)
            self._last_time = loop.time()
            return delay
        self._last_time = now
        return 0.0


async def _kill_process_tree(proc: asyncio.subprocess.Process) -> None:
    """Terminates a process and all its child processes across platforms."""
    if proc.returncode is not None:
        return

    pid = proc.pid
    if sys.platform == "win32":
        try:
            # Terminate full process tree using taskkill without shell=True
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/F",
                "/T",
                "/PID",
                str(pid),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        except Exception:
            pass
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    else:
        # POSIX process group termination
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass


class ToolRunner:
    """Manages subprocess execution for scanner tools with strict safety gating and audit trails."""

    def __init__(
        self,
        artifact_store: ArtifactStore,
        policy_gate: PolicyGate | None = None,
        approval_manager: ApprovalManager | None = None,
        audit_log: AuditLog | None = None,
        rate_limiter: RateLimiter | None = None,
        default_timeout: float = 300.0,
        **kwargs: Any,
    ) -> None:
        if "allow_ungated" in kwargs:
            raise ValueError(
                "Safety violation (ERR-04): 'allow_ungated' has been permanently removed. "
                "Tool execution mandates active PolicyGate and ApprovalManager."
            )
        if policy_gate is None or approval_manager is None:
            raise ValueError(
                "ToolRunner mandates active PolicyGate and ApprovalManager for safe execution."
            )

        self.artifact_store = artifact_store
        self.policy_gate = policy_gate
        self.approval_manager = approval_manager
        self.audit_log = audit_log
        self.rate_limiter = rate_limiter
        self.default_timeout = default_timeout

    async def execute(
        self,
        step: PlanStep,
        argv: list[str],
        *,
        assessment_id: str | None = None,
        timeout_seconds: float | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> ExecutionResult:
        """Executes a scanner command safely using an argv list.

        Enforces policy gate authorization, approval requirements, rate limiting,
        DNS pinning, timeout kills, artifact capture, and hash-chained audit logging.
        """
        # 1. Enforce strict argv validation (AGENTS.md Rule 1)
        if not isinstance(argv, list):
            raise TypeError(f"argv must be a list of strings, got {type(argv).__name__}")
        if not argv:
            raise ValueError("argv list cannot be empty")
        for idx, arg in enumerate(argv):
            if not isinstance(arg, str):
                raise TypeError(
                    f"argv element at index {idx} must be a str, got {type(arg).__name__}"
                )

        # 2. Enforce Policy Gate (AGENTS.md Rule 2)
        port = step.params.get("port") or step.params.get("ports")
        port_int: int | None = None
        if isinstance(port, int):
            port_int = port
        elif isinstance(port, str) and port.isdigit():
            port_int = int(port)

        decision = self.policy_gate.authorize(
            target=step.target,
            port=port_int,
            tool=step.tool,
            action_class=step.action_class,
            assessment_id=assessment_id,
        )
        if not decision.allowed:
            raise PolicyDeniedError(
                f"Step '{step.step_id}' denied by policy gate: "
                f"{decision.reason} ({decision.rule_id})"
            )

        # 3. Enforce Human Approvals Gate (AGENTS.md Rule 2)
        self.approval_manager.require(step, assessment_id=assessment_id)

        # 4. Enforce Rate Limiting
        if self.rate_limiter is not None:
            await self.rate_limiter.throttle()

        # 5. DNS Pinning & safe argv substitution (ERR-03)
        effective_argv = list(argv)
        if decision.pinned_ip:
            parsed = parse_target(step.target)
            if step.tool == "nikto":
                if "-host" in effective_argv:
                    h_idx = effective_argv.index("-host")
                    if h_idx + 1 < len(effective_argv):
                        orig_host = effective_argv[h_idx + 1]
                        effective_argv[h_idx + 1] = decision.pinned_ip
                        if orig_host != decision.pinned_ip and "-vhost" not in effective_argv:
                            effective_argv.extend(["-vhost", orig_host])
            elif step.tool == "nmap":
                for i, arg in enumerate(effective_argv):
                    if arg == step.target or arg == parsed.host:
                        effective_argv[i] = decision.pinned_ip

        # 6. Audit Run Start (AGENTS.md Rule 7, 9)
        run_id = f"run_{step.step_id}_{uuid.uuid4().hex[:8]}"
        timeout = timeout_seconds or self.default_timeout
        self._audit(
            actor="runner",
            event_type="tool_run_started",
            payload={
                "run_id": run_id,
                "step_id": step.step_id,
                "tool": step.tool,
                "target": redact_target(step.target),
                "action_class": step.action_class.value,
                "argv": redact_argv(effective_argv),
                "timeout_seconds": timeout,
                "pinned_ip": decision.pinned_ip,
            },
            assessment_id=assessment_id,
        )

        # 7. Spawn Subprocess (AGENTS.md Rule 1)
        start_time = time.perf_counter()
        timed_out = False
        stdout_bytes = b""
        stderr_bytes = b""
        exit_code: int | None = None
        proc: asyncio.subprocess.Process | None = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *effective_argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
                start_new_session=True,
            )

            try:
                try:
                    async with asyncio.timeout(timeout):
                        stdout_bytes, stderr_bytes = await proc.communicate()
                except TimeoutError:
                    timed_out = True
                    await _kill_process_tree(proc)
                    try:
                        async with asyncio.timeout(2.0):
                            stdout_bytes, stderr_bytes = await proc.communicate()
                    except Exception:
                        stdout_bytes, stderr_bytes = b"", b""
            finally:
                if proc.returncode is None:
                    await _kill_process_tree(proc)

            exit_code = proc.returncode

        except asyncio.CancelledError:
            if proc is not None and proc.returncode is None:
                await _kill_process_tree(proc)
            duration = round(time.perf_counter() - start_time, 3)
            self._audit(
                actor="runner",
                event_type="tool_run_failed",
                payload={
                    "run_id": run_id,
                    "step_id": step.step_id,
                    "tool": step.tool,
                    "status": "cancelled",
                    "error": "Execution was cancelled",
                    "duration_seconds": duration,
                },
                assessment_id=assessment_id,
            )
            raise

        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 3)
            err_msg = f"Failed to spawn subprocess: {exc}"
            artifact_meta = self.artifact_store.save_raw(
                content=err_msg.encode("utf-8"),
                source_tool=step.tool,
                run_id=run_id,
                extension="txt",
            )
            self._audit(
                actor="runner",
                event_type="tool_run_failed",
                payload={
                    "run_id": run_id,
                    "step_id": step.step_id,
                    "tool": step.tool,
                    "status": "failed",
                    "error": str(exc),
                    "duration_seconds": duration,
                    "artifact_id": artifact_meta.artifact_id,
                },
                assessment_id=assessment_id,
            )
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr=err_msg,
                exit_code=-1,
                duration_seconds=duration,
                artifact_id=artifact_meta.artifact_id,
            )

        # 7. Compute Result Status and Store Artifact
        duration = round(time.perf_counter() - start_time, 3)
        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")

        status: Literal["succeeded", "failed", "timed_out"]
        if timed_out:
            status = "timed_out"
        elif exit_code == 0:
            status = "succeeded"
        else:
            status = "failed"

        # Raw tool output: preserve both stdout and stderr verbatim (AGENTS.md Rule 8)
        if stdout_bytes and stderr_bytes:
            raw_output = b"--- STDOUT ---\n" + stdout_bytes + b"\n--- STDERR ---\n" + stderr_bytes
        elif stdout_bytes:
            raw_output = stdout_bytes
        else:
            raw_output = stderr_bytes

        ext = "xml" if raw_output.startswith(b"<?xml") else "txt"
        artifact_meta = self.artifact_store.save_raw(
            content=raw_output,
            source_tool=step.tool,
            run_id=run_id,
            extension=ext,
        )

        result = ExecutionResult(
            status=status,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            duration_seconds=duration,
            artifact_id=artifact_meta.artifact_id,
        )

        # 8. Audit Run Completion or Failure
        event_type = "tool_run_completed" if status == "succeeded" else "tool_run_failed"
        self._audit(
            actor="runner",
            event_type=event_type,
            payload={
                "run_id": run_id,
                "step_id": step.step_id,
                "tool": step.tool,
                "status": status,
                "exit_code": exit_code,
                "duration_seconds": duration,
                "artifact_id": artifact_meta.artifact_id,
                "sha256": artifact_meta.sha256_hash,
            },
            assessment_id=assessment_id,
        )

        return result

    async def run_adapter(
        self,
        adapter: BaseAdapter,
        step: PlanStep,
        *,
        assessment_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ExecutionResult:
        """Executes a tool adapter via safe argv generation."""
        if adapter.status == AdapterStatus.IMPORT_ONLY:
            raise NotImplementedError(
                f"Adapter '{adapter.name}' is import-only and cannot be executed live."
            )

        if step.tool != adapter.name:
            raise ValueError(
                f"PlanStep tool '{step.tool}' does not match adapter name '{adapter.name}'"
            )

        if not hasattr(adapter, "build_argv"):
            raise ValueError(
                f"Adapter '{adapter.name}' does not implement build_argv(step)"
            )

        effective_argv = adapter.build_argv(step)
        if not effective_argv:
            raise ValueError(
                f"Adapter '{adapter.name}' did not produce an argv list for step '{step.step_id}'"
            )

        return await self.execute(
            step=step,
            argv=effective_argv,
            assessment_id=assessment_id,
            timeout_seconds=timeout_seconds,
        )

    async def run(
        self,
        step: PlanStep,
        *,
        adapter: BaseAdapter | None = None,
        assessment_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ExecutionResult:
        """Executes a PlanStep via its adapter or direct argv parameters."""
        if adapter is not None:
            return await self.run_adapter(
                adapter=adapter,
                step=step,
                assessment_id=assessment_id,
                timeout_seconds=timeout_seconds,
            )
        argv = step.params.get("argv")
        if argv and isinstance(argv, list):
            return await self.execute(
                step=step,
                argv=argv,
                assessment_id=assessment_id,
                timeout_seconds=timeout_seconds,
            )
        raise ValueError(
            f"Cannot run step '{step.step_id}': no adapter provided and no 'argv' parameter specified."
        )

    def _audit(
        self,
        actor: str,
        event_type: str,
        payload: dict[str, Any],
        assessment_id: str | None,
    ) -> None:
        if self.audit_log is not None:
            self.audit_log.append(
                actor=actor,
                event_type=event_type,
                payload=payload,
                assessment_id=assessment_id,
            )
