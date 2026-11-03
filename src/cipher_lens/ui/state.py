"""UI Controller and state coordinator for Streamlit application (Task A12).

Invariants:
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
- AGENTS.md Rule 2: Every action goes through policy authorization and approval gating.
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cipher_lens.models.assessment import Assessment, AssessmentStatus
from cipher_lens.models.findings import Finding
from cipher_lens.models.plan import PlanStep
from cipher_lens.planner.intake import parse_intake
from cipher_lens.planner.llm import LlmClient
from cipher_lens.planner.models import AssessmentRequest, PlanProposal, StateSummary
from cipher_lens.planner.planner import AdaptivePlanner
from cipher_lens.policy.approvals import ApprovalDecision, ApprovalManager
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditEvent, AuditLog, ChainVerification
from cipher_lens.store.db import connect, init_db
from cipher_lens.store.repository import AssessmentRepository


class UIController:
    """Coordinates Streamlit UI requests with underlying core engines and state repositories."""

    def __init__(
        self,
        db_path: Path | str = "local_data/cipher_lens.db",
        artifacts_dir: Path | str = "local_data/artifacts",
        llm_provider: str | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.artifacts_dir = Path(artifacts_dir)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.conn = connect(self.db_path)
        init_db(self.conn)

        self.audit_log = AuditLog(conn=self.conn)
        self.scope_registry = ScopeRegistry()
        self.policy_gate = PolicyGate(registry=self.scope_registry, audit_log=self.audit_log)
        self.approval_manager = ApprovalManager(audit_log=self.audit_log)
        self.artifact_store = ArtifactStore(base_dir=self.artifacts_dir)
        self.repository = AssessmentRepository(conn=self.conn)

        self.llm_client = LlmClient(
            provider=llm_provider,
            db_conn=self.conn,
        )
        self.planner = AdaptivePlanner(
            llm_client=self.llm_client,
            gate=self.policy_gate,
            audit_log=self.audit_log,
        )

    def register_scope(self, scope: Scope) -> Scope:
        """Registers authorized assessment boundary and writes audit record."""
        self.scope_registry.register(scope)
        self.audit_log.append(
            actor="ui_operator",
            event_type="scope_registered",
            payload={
                "scope_id": scope.id,
                "name": scope.name or scope.owner,
                "targets": scope.allowed_targets,
                "exclusions": scope.exclusions,
                "allowed_ports": scope.allowed_ports,
                "authorization_reference": scope.authorization_reference,
            },
        )
        return scope

    def list_scopes(self) -> list[Scope]:
        """Returns all registered scopes."""
        return self.scope_registry.list_all()

    def get_scope(self, scope_id: str) -> Scope | None:
        """Retrieves a registered scope by ID."""
        return self.scope_registry.get(scope_id)

    def submit_intake(
        self,
        user_request: str,
        title: str = "Automated Lab Assessment",
        scope_id: str | None = None,
    ) -> tuple[Assessment, AssessmentRequest, list[str]]:
        """Parses natural language intake, authorizes targets against scope, and initializes assessment."""
        assm_id = f"assm-{uuid.uuid4().hex[:8]}"

        req, refused = parse_intake(
            user_request=user_request,
            llm_client=self.llm_client,
            gate=self.policy_gate,
            assessment_id=assm_id,
        )

        effective_scope = scope_id
        if not effective_scope:
            all_scopes = self.scope_registry.list_all()
            effective_scope = all_scopes[0].id if all_scopes else "none"

        primary_target = req.targets[0] if req.targets else "none"

        assm = Assessment(
            id=assm_id,
            title=title,
            target=primary_target,
            scope_id=effective_scope,
            status=AssessmentStatus.PLANNING,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self.repository.create_assessment(assm)
        return assm, req, refused

    def generate_plan(self, assessment_id: str) -> PlanProposal:
        """Generates adaptive plan proposals for the current assessment state."""
        assm = self.repository.get_assessment(assessment_id)
        if not assm:
            raise ValueError(f"Assessment '{assessment_id}' not found")

        evidence_list = self.repository.list_evidence(assessment_id)
        findings = self.repository.list_findings(assessment_id)
        existing_steps = self.repository.get_steps(assessment_id)
        done_steps = [s.idempotency_key for s in existing_steps if s.idempotency_key]

        state = StateSummary(
            scope_target=assm.target,
            allowed_tools=["nmap", "nikto", "zap"],
            observations=[],
            findings=findings,
            done_steps=done_steps,
            failures=[],
            remaining_budget=30,
            evidence_ids=["scope"] + [e.id for e in evidence_list],
        )

        plan = self.planner.plan_next_steps(state, assessment_id=assessment_id)

        # Persist proposed steps
        for step in plan.steps:
            plan_step = PlanStep(
                step_id=step.step_id,
                tool=step.tool,  # type: ignore[arg-type]
                action_class=step.action_class,
                target=step.target,
                params=step.params,
                rationale=step.rationale,
                triggered_by=step.triggered_by,
                expected_outcome=step.expected_outcome,
                nist_phase="discovery" if step.nist_phase == "discovery" else "attack",
                idempotency_key=step.idempotency_key,
            )
            self.repository.save_step(assessment_id, plan_step)

        return plan

    def approve_plan(
        self, assessment_id: str, decided_by: str = "analyst", reason: str = "Approved from UI"
    ) -> ApprovalDecision:
        """Records human-in-the-loop approval for assessment plan."""
        decision = self.approval_manager.approve_plan(
            assessment_id=assessment_id,
            decided_by=decided_by,
            reason=reason,
        )
        self.repository.record_approval_decision(decision)
        self.repository.update_assessment_status(assessment_id, AssessmentStatus.IN_PROGRESS)
        return decision

    def get_audit_events(self, assessment_id: str | None = None) -> list[AuditEvent]:
        """Queries audit events by assessment_id or all."""
        return self.audit_log.query(assessment_id=assessment_id)

    def verify_audit_chain(self) -> ChainVerification:
        """Verifies cryptographic hash chain integrity of the audit log."""
        return self.audit_log.verify_chain()

    def get_llm_traces(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        """Queries SQLite llm_traces table for AI transparency."""
        query = "SELECT id, ts, provider, model, prompt_hash, input_summary, output, label, outcome, latency_ms, assessment_id FROM llm_traces"
        params: list[Any] = []
        if assessment_id:
            query += " WHERE assessment_id = ?"
            params.append(assessment_id)
        query += " ORDER BY id DESC"

        cursor = self.conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

        traces = []
        for r in rows:
            traces.append(
                {
                    "id": r[0],
                    "timestamp": r[1],
                    "provider": r[2],
                    "model": r[3],
                    "prompt_hash": r[4],
                    "input_summary": r[5],
                    "output": r[6],
                    "label": r[7],
                    "outcome": r[8],
                    "latency_ms": r[9],
                    "assessment_id": r[10],
                }
            )
        return traces

    def list_assessments(self) -> list[Assessment]:
        """Lists all assessments in the repository."""
        return self.repository.list_assessments()

    def list_findings(self, assessment_id: str) -> list[Finding]:
        """Lists findings associated with an assessment."""
        return self.repository.list_findings(assessment_id)
