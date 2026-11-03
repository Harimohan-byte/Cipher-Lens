"""Asynchronous Orchestration Engine (B15, Master Plan §7 Day 4).

Execution cycle:
plan -> policy check -> plan approval -> execute approved steps -> ingest (parse -> normalize -> enrich -> correlate -> score) -> replan or stop.

Invariants:
1. Per-step timeouts and failure isolation: tool errors never abort the assessment.
2. Idempotency keys skip repeated executions and log reasons.
3. Intrusive and Validation steps require per-step approval and wait in awaiting_approval.
4. Emits real-time lifecycle events via EventBus for Streamlit UI.
"""

import asyncio
import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from cipher_lens.adapters.base import BaseAdapter, ExecutionResult
from cipher_lens.correlate.dedup import correlate_findings
from cipher_lens.correlate.normalize import normalize_finding
from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.enrichment.service import EnrichmentService
from cipher_lens.models.findings import Evidence, Finding, RawFinding
from cipher_lens.models.plan import PlanStep
from cipher_lens.orchestrator.events import AssessmentEvent, EventBus
from cipher_lens.orchestrator.runner import ToolRunner
from cipher_lens.policy.approvals import ApprovalError, ApprovalManager
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import ScopeRegistry
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.repository import AssessmentRepository

logger = logging.getLogger(__name__)


class OrchestrationEngine:
    """Coordinates plan execution, tool adapters, ingest pipelines, and event distribution."""

    def __init__(
        self,
        repository: AssessmentRepository,
        scope_registry: ScopeRegistry,
        policy_gate: PolicyGate,
        approval_manager: ApprovalManager,
        artifact_store: ArtifactStore,
        runner: ToolRunner,
        adapters: dict[str, BaseAdapter],
        enrichment_service: EnrichmentService | None = None,
        risk_scorer: RiskScorer | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.repo = repository
        self.scope_registry = scope_registry
        self.policy_gate = policy_gate
        self.approval_manager = approval_manager
        self.artifact_store = artifact_store
        self.runner = runner
        self.adapters = adapters
        self.enrichment = enrichment_service
        self.scorer = risk_scorer
        self.event_bus = event_bus or EventBus()
        self._executed_keys: set[str] = set()
        self._inflight_tasks: dict[str, asyncio.Task[ExecutionResult]] = {}

    def _emit(self, assessment_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.event_bus.publish(
            AssessmentEvent(
                event_id=f"ev_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                event_type=event_type,
                payload=payload,
            )
        )

    def compute_idempotency_key(self, step: PlanStep, assessment_id: str | None = None) -> str:
        """Deterministic hash of assessment, tool, target, and sorted params to prevent duplicated work."""
        payload = f"{assessment_id or ''}|{step.tool}|{step.target}|{sorted(step.params.items())}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    async def execute_step(
        self,
        assessment_id: str,
        step: PlanStep,
    ) -> ExecutionResult:
        """Executes a single plan step under policy gate, approval check, and runner execution."""
        step_id = step.step_id
        idem_key = step.idempotency_key or self.compute_idempotency_key(step, assessment_id=assessment_id)

        # 1. Check idempotency:
        # If already succeeded in this assessment, skip execution.
        if idem_key in self._executed_keys:
            self._emit(
                assessment_id,
                "step_skipped_duplicate",
                {"step_id": step_id, "reason": f"Duplicate idempotency key {idem_key}"},
            )
            return ExecutionResult(
                status="succeeded",
                stdout="[skipped duplicate]",
                stderr="",
                exit_code=0,
                duration_seconds=0.0,
            )

        # If currently running concurrently, await the in-flight task shielded from cancellation
        # so that a waiter cancellation does not cancel the underlying executing task.
        if idem_key in self._inflight_tasks:
            return await asyncio.shield(self._inflight_tasks[idem_key])

        # 2. Check policy gate authorization
        raw_port = step.params.get("port")
        parsed_port: int | None = None
        if raw_port is not None:
            try:
                parsed_port = int(raw_port)
            except (ValueError, TypeError):
                err_msg = f"Invalid port specification: '{raw_port}'"
                self._emit(
                    assessment_id,
                    "step_rejected_by_policy",
                    {"step_id": step_id, "reason": err_msg},
                )
                return ExecutionResult(
                    status="failed",
                    stdout="",
                    stderr=err_msg,
                    exit_code=1,
                    duration_seconds=0.0,
                )

        auth_decision = self.policy_gate.authorize(
            target=step.target,
            port=parsed_port,
            tool=step.tool,
            action_class=step.action_class,
            assessment_id=assessment_id,
        )

        if not auth_decision.allowed:
            self._emit(
                assessment_id,
                "step_rejected_by_policy",
                {"step_id": step_id, "reason": auth_decision.reason},
            )
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr=f"Policy gate rejection: {auth_decision.reason}",
                exit_code=1,
                duration_seconds=0.0,
            )

        # 3. Check approval requirement
        try:
            self.approval_manager.require(step, assessment_id=assessment_id)
        except ApprovalError as exc:
            self._emit(
                assessment_id,
                "step_awaiting_approval",
                {"step_id": step_id, "action_class": str(step.action_class), "error": str(exc)},
            )
            return ExecutionResult(
                status="failed",
                stdout="[awaiting_approval]",
                stderr=f"Approval requirement not met: {exc}",
                exit_code=2,
                duration_seconds=0.0,
            )

        adapter = self.adapters.get(step.tool)
        if not adapter:
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr=f"No adapter registered for tool '{step.tool}'",
                exit_code=127,
                duration_seconds=0.0,
            )

        # 4. Execute step via ToolRunner with in-flight task tracking
        self._emit(assessment_id, "step_started", {"step_id": step_id, "tool": step.tool})
        task = asyncio.current_task()
        if task is not None:
            self._inflight_tasks[idem_key] = task

        try:
            exec_result = await self.runner.run(step, assessment_id=assessment_id)
        finally:
            self._inflight_tasks.pop(idem_key, None)

        # Register idempotency key only after successful run so failures can be retried
        if exec_result.status == "succeeded":
            self._executed_keys.add(idem_key)

        self._emit(
            assessment_id,
            "step_finished",
            {
                "step_id": step_id,
                "status": exec_result.status,
                "exit_code": exec_result.exit_code,
            },
        )
        return exec_result

    async def ingest_artifact(
        self,
        assessment_id: str,
        step: PlanStep,
        exec_result: ExecutionResult,
    ) -> list[Finding]:
        """Ingests raw output: parse -> normalize -> enrich -> correlate -> score."""
        if not exec_result.artifact_id:
            return []

        adapter = self.adapters.get(step.tool)
        if not adapter:
            return []

        raw_bytes = self.artifact_store.read_raw(exec_result.artifact_id)
        ev_meta = Evidence(
            id=f"ev_{uuid.uuid4().hex[:8]}",
            source_tool=step.tool,
            run_id=f"run_{step.step_id}",
            artifact_id=exec_result.artifact_id,
            locator=f"/{step.tool}/output",
            raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            snippet="",
            observed_at=datetime.now(UTC),
            origin="live" if adapter.status.value == "live" else "sample",
        )

        parsed_items = adapter.parse(raw_bytes, ev_meta)
        raw_findings = [p for p in parsed_items if isinstance(p, RawFinding)]

        if not raw_findings:
            return []

        # 1. Normalize
        normalized = [normalize_finding(rf) for rf in raw_findings]

        # 2. Correlate
        correlated = correlate_findings(normalized)

        # 3. Enrich and score
        final_findings: list[Finding] = []
        for finding in correlated:
            enrichment_data = None
            if self.enrichment and finding.cve:
                try:
                    enrichment_data = await self.enrichment.enrich_cve(finding.cve[0])
                    if enrichment_data and enrichment_data.cvss:
                        finding.cvss = enrichment_data.cvss
                except Exception as exc:
                    logger.warning(
                        "CVE enrichment failed for %s; scoring without enrichment data: %s",
                        finding.cve[0],
                        exc,
                    )

            if self.scorer:
                finding.risk = self.scorer.score_finding(finding, enrichment=enrichment_data)

            self.repo.create_finding(assessment_id, finding)
            final_findings.append(finding)

        self._emit(
            assessment_id,
            "findings_ingested",
            {"count": len(final_findings), "step_id": step.step_id},
        )
        return final_findings
