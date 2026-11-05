"""Repository layer for persisting assessments, steps, runs, findings, evidence, and approvals.

Supports crash recovery and resume-from-DB functionality (Task A8).
"""

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.assessment import (
    Assessment,
    AssessmentResumeState,
    AssessmentStatus,
    StepRun,
)
from cipher_lens.models.findings import (
    Asset,
    CvssInfo,
    Evidence,
    Finding,
    Inference,
    RiskScore,
    ValidationRecord,
)
from cipher_lens.models.plan import ActionClass, PlanStep


class AssessmentRepository:
    """SQLite-backed persistence repository for assessment data."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # -----------------------------------------------------------------------
    # Assessments
    # -----------------------------------------------------------------------

    def create_assessment(self, assessment: Assessment) -> Assessment:
        """Stores a new assessment record."""
        # DECISION: Assessments are created with explicit timestamps in UTC ISO format.
        stmt = """
        INSERT INTO assessments (id, title, target, scope_id, status, created_at, updated_at, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.conn.execute(
            stmt,
            (
                assessment.id,
                assessment.title,
                assessment.target,
                assessment.scope_id,
                assessment.status.value,
                assessment.created_at.isoformat(),
                assessment.updated_at.isoformat(),
                json.dumps(assessment.metadata),
            ),
        )
        return assessment

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        """Fetches an assessment by ID."""
        cursor = self.conn.execute(
            "SELECT id, title, target, scope_id, status, created_at, updated_at, metadata FROM assessments WHERE id = ?",
            (assessment_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return Assessment(
            id=row[0],
            title=row[1],
            target=row[2],
            scope_id=row[3],
            status=AssessmentStatus(row[4]),
            created_at=datetime.fromisoformat(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
            metadata=json.loads(row[7]),
        )

    def update_assessment_status(
        self, assessment_id: str, status: AssessmentStatus | str
    ) -> None:
        """Updates assessment lifecycle status."""
        val = status.value if isinstance(status, AssessmentStatus) else status
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "UPDATE assessments SET status = ?, updated_at = ? WHERE id = ?",
            (val, now, assessment_id),
        )

    def update_assessment_target(
        self, assessment_id: str, target: str
    ) -> None:
        """Updates the target host/IP for an assessment."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "UPDATE assessments SET target = ?, updated_at = ? WHERE id = ?",
            (target, now, assessment_id),
        )

    def list_assessments(
        self, status: AssessmentStatus | str | None = None
    ) -> list[Assessment]:
        """Lists assessments, optionally filtered by status."""
        if status is not None:
            val = status.value if isinstance(status, AssessmentStatus) else status
            cursor = self.conn.execute(
                "SELECT id, title, target, scope_id, status, created_at, updated_at, metadata FROM assessments WHERE status = ? ORDER BY created_at DESC",
                (val,),
            )
        else:
            cursor = self.conn.execute(
                "SELECT id, title, target, scope_id, status, created_at, updated_at, metadata FROM assessments ORDER BY created_at DESC"
            )
        results = []
        for row in cursor.fetchall():
            results.append(
                Assessment(
                    id=row[0],
                    title=row[1],
                    target=row[2],
                    scope_id=row[3],
                    status=AssessmentStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    updated_at=datetime.fromisoformat(row[6]),
                    metadata=json.loads(row[7]),
                )
            )
        return results

    def get_resumable_assessments(self) -> list[Assessment]:
        """Returns assessments that are in created, planning, in_progress, or paused status."""
        cursor = self.conn.execute(
            "SELECT id, title, target, scope_id, status, created_at, updated_at, metadata FROM assessments WHERE status IN ('created', 'planning', 'in_progress', 'paused') ORDER BY updated_at DESC"
        )
        results = []
        for row in cursor.fetchall():
            results.append(
                Assessment(
                    id=row[0],
                    title=row[1],
                    target=row[2],
                    scope_id=row[3],
                    status=AssessmentStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    updated_at=datetime.fromisoformat(row[6]),
                    metadata=json.loads(row[7]),
                )
            )
        return results

    def reset_interrupted_steps(self, assessment_id: str) -> int:
        """Resets steps left in 'running' status back to 'pending' after an unexpected crash/restart."""
        now = datetime.now(UTC).isoformat()
        cursor = self.conn.execute(
            "UPDATE plan_steps SET status = 'pending', updated_at = ? WHERE assessment_id = ? AND status = 'running'",
            (now, assessment_id),
        )
        return cursor.rowcount

    # -----------------------------------------------------------------------
    # Plan Steps
    # -----------------------------------------------------------------------

    def save_step(
        self, assessment_id: str, step: PlanStep, status: str = "pending"
    ) -> None:
        """Saves or updates a plan step belonging to an assessment."""
        now = datetime.now(UTC).isoformat()
        stmt = """
        INSERT INTO plan_steps (
            step_id, assessment_id, tool, action_class, target, params,
            rationale, triggered_by, expected_outcome, nist_phase,
            idempotency_key, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(assessment_id, step_id) DO UPDATE SET
            tool = excluded.tool,
            action_class = excluded.action_class,
            target = excluded.target,
            params = excluded.params,
            rationale = excluded.rationale,
            triggered_by = excluded.triggered_by,
            expected_outcome = excluded.expected_outcome,
            nist_phase = excluded.nist_phase,
            idempotency_key = excluded.idempotency_key,
            status = excluded.status,
            updated_at = excluded.updated_at
        """
        self.conn.execute(
            stmt,
            (
                step.step_id,
                assessment_id,
                step.tool,
                step.action_class.value,
                step.target,
                json.dumps(step.params),
                step.rationale,
                json.dumps(step.triggered_by),
                step.expected_outcome,
                step.nist_phase,
                step.idempotency_key,
                status,
                now,
                now,
            ),
        )

    def save_steps(
        self, assessment_id: str, steps: list[tuple[PlanStep, str]]
    ) -> None:
        """Batch saves steps with their status."""
        for step, status in steps:
            self.save_step(assessment_id, step, status)

    def get_step(
        self, assessment_id: str, step_id: str
    ) -> tuple[PlanStep, str] | None:
        """Fetches a plan step and its current status."""
        cursor = self.conn.execute(
            """
            SELECT step_id, tool, action_class, target, params, rationale,
                   triggered_by, expected_outcome, nist_phase, idempotency_key, status
            FROM plan_steps
            WHERE assessment_id = ? AND step_id = ?
            """,
            (assessment_id, step_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        step = PlanStep(
            step_id=row[0],
            tool=row[1],
            action_class=ActionClass(row[2]),
            target=row[3],
            params=json.loads(row[4]),
            rationale=row[5],
            triggered_by=json.loads(row[6]),
            expected_outcome=row[7],
            nist_phase=row[8],
            idempotency_key=row[9],
        )
        return step, row[10]

    def get_steps(
        self, assessment_id: str, status: str | None = None
    ) -> list[tuple[PlanStep, str]]:
        """Lists plan steps for an assessment, optionally filtered by status."""
        if status is not None:
            cursor = self.conn.execute(
                """
                SELECT step_id, tool, action_class, target, params, rationale,
                       triggered_by, expected_outcome, nist_phase, idempotency_key, status
                FROM plan_steps
                WHERE assessment_id = ? AND status = ?
                ORDER BY created_at ASC
                """,
                (assessment_id, status),
            )
        else:
            cursor = self.conn.execute(
                """
                SELECT step_id, tool, action_class, target, params, rationale,
                       triggered_by, expected_outcome, nist_phase, idempotency_key, status
                FROM plan_steps
                WHERE assessment_id = ?
                ORDER BY created_at ASC
                """,
                (assessment_id,),
            )
        results = []
        for row in cursor.fetchall():
            step = PlanStep(
                step_id=row[0],
                tool=row[1],
                action_class=ActionClass(row[2]),
                target=row[3],
                params=json.loads(row[4]),
                rationale=row[5],
                triggered_by=json.loads(row[6]),
                expected_outcome=row[7],
                nist_phase=row[8],
                idempotency_key=row[9],
            )
            results.append((step, row[10]))
        return results

    def update_step_status(
        self, assessment_id: str, step_id: str, status: str
    ) -> None:
        """Updates the execution status of a step."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "UPDATE plan_steps SET status = ?, updated_at = ? WHERE assessment_id = ? AND step_id = ?",
            (status, now, assessment_id, step_id),
        )

    def get_step_by_idempotency_key(
        self, assessment_id: str, idempotency_key: str
    ) -> tuple[PlanStep, str] | None:
        """Finds a step by its idempotency key within an assessment."""
        cursor = self.conn.execute(
            """
            SELECT step_id, tool, action_class, target, params, rationale,
                   triggered_by, expected_outcome, nist_phase, idempotency_key, status
            FROM plan_steps
            WHERE assessment_id = ? AND idempotency_key = ?
            """,
            (assessment_id, idempotency_key),
        )
        row = cursor.fetchone()
        if not row:
            return None
        step = PlanStep(
            step_id=row[0],
            tool=row[1],
            action_class=ActionClass(row[2]),
            target=row[3],
            params=json.loads(row[4]),
            rationale=row[5],
            triggered_by=json.loads(row[6]),
            expected_outcome=row[7],
            nist_phase=row[8],
            idempotency_key=row[9],
        )
        return step, row[10]

    # -----------------------------------------------------------------------
    # Step Runs
    # -----------------------------------------------------------------------

    def save_run(self, run: StepRun) -> StepRun:
        """Persists a tool execution run record."""
        stmt = """
        INSERT INTO runs (
            run_id, assessment_id, step_id, tool_name, status, exit_code,
            stdout_artifact_id, stderr_artifact_id, raw_sha256,
            started_at, ended_at, duration_ms, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
            status = excluded.status,
            exit_code = excluded.exit_code,
            stdout_artifact_id = excluded.stdout_artifact_id,
            stderr_artifact_id = excluded.stderr_artifact_id,
            raw_sha256 = excluded.raw_sha256,
            ended_at = excluded.ended_at,
            duration_ms = excluded.duration_ms,
            error_message = excluded.error_message
        """
        self.conn.execute(
            stmt,
            (
                run.run_id,
                run.assessment_id,
                run.step_id,
                run.tool_name,
                run.status,
                run.exit_code,
                run.stdout_artifact_id,
                run.stderr_artifact_id,
                run.raw_sha256,
                run.started_at.isoformat(),
                run.ended_at.isoformat() if run.ended_at else None,
                run.duration_ms,
                run.error_message,
            ),
        )
        return run

    def get_run(self, run_id: str) -> StepRun | None:
        """Retrieves a run by ID."""
        cursor = self.conn.execute(
            """
            SELECT run_id, assessment_id, step_id, tool_name, status, exit_code,
                   stdout_artifact_id, stderr_artifact_id, raw_sha256,
                   started_at, ended_at, duration_ms, error_message
            FROM runs WHERE run_id = ?
            """,
            (run_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_run(row)

    def list_runs(
        self, assessment_id: str, step_id: str | None = None
    ) -> list[StepRun]:
        """Lists runs for an assessment, optionally filtered by step_id."""
        if step_id is not None:
            cursor = self.conn.execute(
                """
                SELECT run_id, assessment_id, step_id, tool_name, status, exit_code,
                       stdout_artifact_id, stderr_artifact_id, raw_sha256,
                       started_at, ended_at, duration_ms, error_message
                FROM runs WHERE assessment_id = ? AND step_id = ? ORDER BY started_at ASC
                """,
                (assessment_id, step_id),
            )
        else:
            cursor = self.conn.execute(
                """
                SELECT run_id, assessment_id, step_id, tool_name, status, exit_code,
                       stdout_artifact_id, stderr_artifact_id, raw_sha256,
                       started_at, ended_at, duration_ms, error_message
                FROM runs WHERE assessment_id = ? ORDER BY started_at ASC
                """,
                (assessment_id,),
            )
        return [self._row_to_run(r) for r in cursor.fetchall()]

    @staticmethod
    def _row_to_run(row: Any) -> StepRun:
        return StepRun(
            run_id=row[0],
            assessment_id=row[1],
            step_id=row[2],
            tool_name=row[3],
            status=row[4],
            exit_code=row[5],
            stdout_artifact_id=row[6],
            stderr_artifact_id=row[7],
            raw_sha256=row[8],
            started_at=datetime.fromisoformat(row[9]),
            ended_at=datetime.fromisoformat(row[10]) if row[10] else None,
            duration_ms=row[11],
            error_message=row[12],
        )

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------

    def save_finding(self, assessment_id: str, finding: Finding) -> None:
        """Persists a normalized Finding record."""
        # DECISION: Observed evidence and AI inferences are saved in separate columns; never mixed.
        stmt = """
        INSERT INTO findings (
            id, assessment_id, title, asset, sources, evidence, inferences,
            cve, cwe, cvss, tool_severity, confidence, status, status_reason,
            limitations, risk, validation, correlation_key, related_ids,
            first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(assessment_id, id) DO UPDATE SET
            title = excluded.title,
            asset = excluded.asset,
            sources = excluded.sources,
            evidence = excluded.evidence,
            inferences = excluded.inferences,
            cve = excluded.cve,
            cwe = excluded.cwe,
            cvss = excluded.cvss,
            tool_severity = excluded.tool_severity,
            confidence = excluded.confidence,
            status = excluded.status,
            status_reason = excluded.status_reason,
            limitations = excluded.limitations,
            risk = excluded.risk,
            validation = excluded.validation,
            correlation_key = excluded.correlation_key,
            related_ids = excluded.related_ids,
            last_seen = excluded.last_seen
        """
        self.conn.execute(
            stmt,
            (
                finding.id,
                assessment_id,
                finding.title,
                finding.asset.model_dump_json(),
                json.dumps(finding.sources),
                json.dumps([e.model_dump(mode="json") for e in finding.evidence]),
                json.dumps([i.model_dump(mode="json") for i in finding.inferences]),
                json.dumps(finding.cve),
                json.dumps(finding.cwe),
                finding.cvss.model_dump_json() if finding.cvss else None,
                finding.tool_severity,
                finding.confidence,
                finding.status,
                finding.status_reason,
                json.dumps(finding.limitations),
                finding.risk.model_dump_json() if finding.risk else None,
                finding.validation.model_dump_json() if finding.validation else None,
                finding.correlation_key,
                json.dumps(finding.related_ids),
                finding.first_seen.isoformat(),
                finding.last_seen.isoformat(),
            ),
        )

    def save_findings(self, assessment_id: str, findings: list[Finding]) -> None:
        """Batch saves findings."""
        for finding in findings:
            self.save_finding(assessment_id, finding)

    def get_finding(self, assessment_id: str, finding_id: str) -> Finding | None:
        """Fetches a finding by ID within an assessment."""
        cursor = self.conn.execute(
            """
            SELECT id, title, asset, sources, evidence, inferences, cve, cwe, cvss,
                   tool_severity, confidence, status, status_reason, limitations,
                   risk, validation, correlation_key, related_ids, first_seen, last_seen
            FROM findings
            WHERE assessment_id = ? AND id = ?
            """,
            (assessment_id, finding_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_finding(row)

    def list_findings(self, assessment_id: str) -> list[Finding]:
        """Lists all findings for an assessment."""
        cursor = self.conn.execute(
            """
            SELECT id, title, asset, sources, evidence, inferences, cve, cwe, cvss,
                   tool_severity, confidence, status, status_reason, limitations,
                   risk, validation, correlation_key, related_ids, first_seen, last_seen
            FROM findings
            WHERE assessment_id = ?
            ORDER BY id ASC
            """,
            (assessment_id,),
        )
        return [self._row_to_finding(r) for r in cursor.fetchall()]

    def get_finding_by_correlation_key(
        self, assessment_id: str, correlation_key: str
    ) -> Finding | None:
        """Fetches a finding matching a specific correlation key."""
        cursor = self.conn.execute(
            """
            SELECT id, title, asset, sources, evidence, inferences, cve, cwe, cvss,
                   tool_severity, confidence, status, status_reason, limitations,
                   risk, validation, correlation_key, related_ids, first_seen, last_seen
            FROM findings
            WHERE assessment_id = ? AND correlation_key = ?
            """,
            (assessment_id, correlation_key),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_finding(row)

    @staticmethod
    def _row_to_finding(row: Any) -> Finding:
        ev_list = [Evidence.model_validate(e) for e in json.loads(row[4])]
        inf_list = [Inference.model_validate(i) for i in json.loads(row[5])]
        cvss = CvssInfo.model_validate_json(row[8]) if row[8] else None
        risk = RiskScore.model_validate_json(row[14]) if row[14] else None
        val = ValidationRecord.model_validate_json(row[15]) if row[15] else None

        return Finding(
            id=row[0],
            title=row[1],
            asset=Asset.model_validate_json(row[2]),
            sources=json.loads(row[3]),
            evidence=ev_list,
            inferences=inf_list,
            cve=json.loads(row[6]),
            cwe=json.loads(row[7]),
            cvss=cvss,
            tool_severity=row[9],
            confidence=row[10],
            status=row[11],
            status_reason=row[12],
            limitations=json.loads(row[13]),
            risk=risk,
            validation=val,
            correlation_key=row[16],
            related_ids=json.loads(row[17]),
            first_seen=datetime.fromisoformat(row[18]),
            last_seen=datetime.fromisoformat(row[19]),
        )

    # -----------------------------------------------------------------------
    # Evidence Standalone Table
    # -----------------------------------------------------------------------

    def save_evidence(
        self,
        assessment_id: str,
        evidence: Evidence,
        finding_id: str | None = None,
    ) -> None:
        """Stores an individual evidence record."""
        stmt = """
        INSERT INTO evidence (
            id, assessment_id, finding_id, source_tool, run_id, artifact_id,
            locator, raw_sha256, snippet, observed_at, origin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(assessment_id, id) DO UPDATE SET
            finding_id = excluded.finding_id,
            source_tool = excluded.source_tool,
            run_id = excluded.run_id,
            artifact_id = excluded.artifact_id,
            locator = excluded.locator,
            raw_sha256 = excluded.raw_sha256,
            snippet = excluded.snippet,
            observed_at = excluded.observed_at,
            origin = excluded.origin
        """
        self.conn.execute(
            stmt,
            (
                evidence.id,
                assessment_id,
                finding_id,
                evidence.source_tool,
                evidence.run_id,
                evidence.artifact_id,
                evidence.locator,
                evidence.raw_sha256,
                evidence.snippet,
                evidence.observed_at.isoformat(),
                evidence.origin,
            ),
        )

    def list_evidence(
        self, assessment_id: str, finding_id: str | None = None
    ) -> list[Evidence]:
        """Lists evidence records for an assessment, optionally filtered by finding_id."""
        if finding_id is not None:
            cursor = self.conn.execute(
                """
                SELECT id, source_tool, run_id, artifact_id, locator, raw_sha256,
                       snippet, observed_at, origin
                FROM evidence WHERE assessment_id = ? AND finding_id = ?
                ORDER BY observed_at ASC
                """,
                (assessment_id, finding_id),
            )
        else:
            cursor = self.conn.execute(
                """
                SELECT id, source_tool, run_id, artifact_id, locator, raw_sha256,
                       snippet, observed_at, origin
                FROM evidence WHERE assessment_id = ?
                ORDER BY observed_at ASC
                """,
                (assessment_id,),
            )
        return [
            Evidence(
                id=r[0],
                source_tool=r[1],
                run_id=r[2],
                artifact_id=r[3],
                locator=r[4],
                raw_sha256=r[5],
                snippet=r[6],
                observed_at=datetime.fromisoformat(r[7]),
                origin=r[8],
            )
            for r in cursor.fetchall()
        ]

    # -----------------------------------------------------------------------
    # Approvals
    # -----------------------------------------------------------------------

    def save_approval_request(self, request: ApprovalRequest) -> None:
        """Stores a pending human approval request."""
        stmt = """
        INSERT INTO approvals (
            approval_id, assessment_id, step_id, action_class, tool,
            target, rationale, requested_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(approval_id) DO UPDATE SET
            status = excluded.status
        """
        self.conn.execute(
            stmt,
            (
                request.approval_id,
                request.assessment_id,
                request.step_id,
                request.action_class.value,
                request.tool,
                request.target,
                request.rationale,
                request.requested_at.isoformat(),
                request.status,
            ),
        )

    def record_approval_decision(self, decision: ApprovalDecision) -> None:
        """Records a human decision on an existing approval request."""
        # DECISION: Decision updates request status and attaches decided_by, reason, and notes.
        stmt = """
        UPDATE approvals
        SET status = ?, decision = ?, decided_by = ?, reason = ?, decided_at = ?, notes = ?
        WHERE approval_id = ?
        """
        self.conn.execute(
            stmt,
            (
                decision.decision,
                decision.decision,
                decision.decided_by,
                decision.reason,
                decision.decided_at.isoformat(),
                decision.notes,
                decision.approval_id,
            ),
        )

    def get_approval(
        self, approval_id: str
    ) -> tuple[ApprovalRequest, ApprovalDecision | None] | None:
        """Fetches an approval request and its optional human decision."""
        cursor = self.conn.execute(
            """
            SELECT approval_id, assessment_id, step_id, action_class, tool,
                   target, rationale, requested_at, status, decision, decided_by,
                   reason, decided_at, notes
            FROM approvals WHERE approval_id = ?
            """,
            (approval_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_approval(row)

    def list_approvals(
        self, assessment_id: str, status: str | None = None
    ) -> list[tuple[ApprovalRequest, ApprovalDecision | None]]:
        """Lists approval requests and decisions for an assessment."""
        if status is not None:
            cursor = self.conn.execute(
                """
                SELECT approval_id, assessment_id, step_id, action_class, tool,
                       target, rationale, requested_at, status, decision, decided_by,
                       reason, decided_at, notes
                FROM approvals WHERE assessment_id = ? AND status = ?
                ORDER BY requested_at ASC
                """,
                (assessment_id, status),
            )
        else:
            cursor = self.conn.execute(
                """
                SELECT approval_id, assessment_id, step_id, action_class, tool,
                       target, rationale, requested_at, status, decision, decided_by,
                       reason, decided_at, notes
                FROM approvals WHERE assessment_id = ?
                ORDER BY requested_at ASC
                """,
                (assessment_id,),
            )
        return [self._row_to_approval(r) for r in cursor.fetchall()]

    @staticmethod
    def _row_to_approval(
        row: Any,
    ) -> tuple[ApprovalRequest, ApprovalDecision | None]:
        req = ApprovalRequest(
            approval_id=row[0],
            assessment_id=row[1],
            step_id=row[2],
            action_class=ActionClass(row[3]),
            tool=row[4],
            target=row[5],
            rationale=row[6],
            requested_at=datetime.fromisoformat(row[7]),
            status=row[8],
        )
        dec = None
        if row[9] is not None:  # decision
            dec = ApprovalDecision(
                approval_id=row[0],
                decision=row[9],
                decided_by=row[10] or "",
                reason=row[11] or "",
                decided_at=datetime.fromisoformat(row[12])
                if row[12]
                else datetime.now(UTC),
                notes=row[13],
            )
        return req, dec

    # -----------------------------------------------------------------------
    # Resume-from-DB Support
    # -----------------------------------------------------------------------

    def resume_assessment(self, assessment_id: str) -> AssessmentResumeState:
        """Reconstructs the full in-memory state of an assessment for resumption."""
        # DECISION: resume_assessment loads assessment, separates steps by execution state,
        # and gathers all existing runs, findings, and approval records.
        assessment = self.get_assessment(assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment '{assessment_id}' not found")

        all_steps = self.get_steps(assessment_id)
        pending_steps = [s for s, status in all_steps if status in ("pending", "awaiting_approval")]
        completed_steps = [s for s, status in all_steps if status == "completed"]
        failed_steps = [s for s, status in all_steps if status in ("failed", "skipped")]

        runs = self.list_runs(assessment_id)
        findings = self.list_findings(assessment_id)
        approvals = self.list_approvals(assessment_id)

        return AssessmentResumeState(
            assessment=assessment,
            pending_steps=pending_steps,
            completed_steps=completed_steps,
            failed_steps=failed_steps,
            runs=runs,
            findings=findings,
            approvals=approvals,
        )
