"""UI Controller and state coordinator for Streamlit application (Task A12).

Invariants:
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
- AGENTS.md Rule 2: Every action goes through policy authorization and approval gating.
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event.
"""

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cipher_lens.adapters.imports.burp import BurpImporter
from cipher_lens.adapters.imports.nessus import NessusImporter
from cipher_lens.adapters.imports.openvas import OpenvasImporter
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.models.assessment import Assessment, AssessmentStatus
from cipher_lens.models.findings import Finding
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.orchestrator.chaos import ChaosConfig, ChaosManager
from cipher_lens.orchestrator.replay import ReplayRunner
from cipher_lens.planner.intake import parse_intake
from cipher_lens.planner.llm import LlmClient
from cipher_lens.planner.models import AssessmentRequest, PlanProposal, StateSummary
from cipher_lens.planner.planner import AdaptivePlanner
from cipher_lens.policy.approvals import ApprovalDecision, ApprovalManager
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.policy.validation import (
    decide_validation_request,
    record_validation_outcome,
    request_validation,
)
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

        self.adapters = {
            "nmap": NmapAdapter(),
            "nikto": NiktoAdapter(),
            "zap": ZapAdapter(),
            "burp": BurpImporter(),
            "burp_import": BurpImporter(),
            "nessus": NessusImporter(),
            "nessus_import": NessusImporter(),
            "openvas": OpenvasImporter(),
            "openvas_import": OpenvasImporter(),
        }
        self.chaos_manager = ChaosManager()
        self.replay_runner = ReplayRunner(
            repository=self.repository,
            artifact_store=self.artifact_store,
            adapters=self.adapters,
            risk_scorer=RiskScorer(),
            audit_log=self.audit_log,
        )

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

        if self.chaos_manager.config.llm_down:
            from cipher_lens.planner.rules_planner import rule_based_plan
            plan = rule_based_plan(state)
        else:
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

    def request_validation(
        self,
        assessment_id: str,
        finding_id: str,
        requested_by: str,
        reason: str,
        potential_impact: str,
    ) -> Any:
        """Requests human approval for manual lab validation of a finding."""
        finding = self.repository.get_finding(assessment_id, finding_id)
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in assessment '{assessment_id}'")
        req = request_validation(
            finding=finding,
            requested_by=requested_by,
            reason=reason,
            potential_impact=potential_impact,
            approval_manager=self.approval_manager,
            assessment_id=assessment_id,
        )
        self.repository.save_approval_request(req)
        return req

    def decide_validation(
        self,
        assessment_id: str,
        approval_id: str,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str,
    ) -> ApprovalDecision:
        """Records an approval or rejection decision for a manual validation request."""
        # Ensure approval request exists in memory manager if it was persisted
        if approval_id not in self.approval_manager._step_requests:
            app_tuple = self.repository.get_approval(approval_id)
            if app_tuple is None:
                raise ValueError(f"Approval '{approval_id}' not found")
            req, existing = app_tuple
            if existing is not None:
                if existing.decision != decision:
                    raise ValueError(
                        f"Approval decision for '{approval_id}' is final ({existing.decision}) and cannot be modified"
                    )
                return existing
            self.approval_manager._step_requests[req.approval_id] = req
            self.approval_manager._step_to_approval[(req.assessment_id, req.step_id)] = req.approval_id

        dec = decide_validation_request(
            approval_id=approval_id,
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            approval_manager=self.approval_manager,
            assessment_id=assessment_id,
        )
        self.repository.record_approval_decision(dec)
        return dec

    def get_validation_approval_for_finding(
        self, assessment_id: str, finding_id: str
    ) -> tuple[Any, ApprovalDecision | None] | None:
        """Finds any pending or decided validation approval for a finding."""
        approvals = self.repository.list_approvals(assessment_id)
        for req, dec in reversed(approvals):
            if req.action_class == ActionClass.VALIDATION and re.fullmatch(
                rf"val-{re.escape(finding_id)}-[0-9a-f]{{6}}", req.step_id
            ):
                return req, dec
        return None

    def get_approval_decision(self, approval_id: str) -> ApprovalDecision | None:
        """Retrieves an approval decision if already decided."""
        app = self.repository.get_approval(approval_id)
        if app:
            return app[1]
        return None

    def record_validation(
        self,
        assessment_id: str,
        finding_id: str,
        approval_decision: ApprovalDecision,
        outcome: Literal["not_run", "succeeded", "failed", "inconclusive"],
        attested_by: str,
        evidence_bytes: bytes | str | None,
    ) -> Finding:
        """Records attested manual validation results and updates finding status."""
        finding = self.repository.get_finding(assessment_id, finding_id)
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in assessment '{assessment_id}'")

        linked = self.get_validation_approval_for_finding(assessment_id, finding_id)
        if linked is None or linked[0].approval_id != approval_decision.approval_id:
            raise PermissionError("Approval does not belong to this finding's validation request")
        stored = linked[1]
        if stored is None:
            raise PermissionError("Validation request has no recorded decision")
        if stored.decision != "approved":
            raise PermissionError(f"Validation approval was not approved ({stored.decision})")
        if finding.validation is not None and finding.validation.approval_id == stored.approval_id:
            raise ValueError("Validation outcome already recorded for this approval")

        updated = record_validation_outcome(
            finding=finding,
            approval_decision=stored,
            outcome=outcome,
            attested_by=attested_by,
            evidence_bytes=evidence_bytes,
            artifact_store=self.artifact_store,
            audit_log=self.audit_log,
            assessment_id=assessment_id,
            approval_request=linked[0],
        )
        self.repository.save_finding(assessment_id, updated)
        return updated

    def replay_fixtures(
        self,
        assessment_id: str,
        fixture_paths: list[Path | str] | None = None,
    ) -> list[Finding]:
        """Replays recorded scanner artifacts into the assessment with origin='replayed'."""
        if fixture_paths is None:
            fixtures_dir = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures"
            fixture_paths = [
                fixtures_dir / "nmap_synthetic.xml",
                fixtures_dir / "nikto_synthetic.xml",
                fixtures_dir / "burp_synthetic.xml",
            ]
        return self.replay_runner.replay_fixtures(assessment_id, fixture_paths)

    def set_chaos_switch(self, switch_name: str, enabled: bool) -> None:
        """Toggles a runtime failure / chaos switch for resilience testing."""
        if hasattr(self.chaos_manager.config, switch_name):
            setattr(self.chaos_manager.config, switch_name, enabled)
            self.audit_log.append(
                actor="chaos_operator",
                event_type="chaos_switch_toggled",
                payload={"switch": switch_name, "enabled": enabled},
                assessment_id=None,
            )

    def get_chaos_config(self) -> ChaosConfig:
        """Retrieves the active chaos configuration."""
        return self.chaos_manager.config

    def get_limitations(self, assessment_id: str) -> list[str]:
        """Returns recorded limitation gaps for an assessment."""
        return self.chaos_manager.get_limitations(assessment_id)

