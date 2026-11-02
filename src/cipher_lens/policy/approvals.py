# DECISION: INTRUSIVE and VALIDATION action classes require per-step human approval; IMPORT, DISCOVERY, and SCAN require plan approval.
# DECISION: Approval decisions are final and immutable. A rejected step cannot be approved later; a new step must be proposed to preserve auditability.
# DECISION: Re-applying the exact same decision for an approval is idempotent and returns the existing decision record.
# DECISION: Approvals are bound to (assessment_id, step_id) and match step content (tool, target, action_class). Unclassified action classes fail closed.
"""Human-in-the-loop approval management and safety gating."""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.store.audit import AuditLog


class ApprovalError(Exception):
    """Base exception for approval enforcement failures."""


class ApprovalRequiredError(ApprovalError):
    """Raised when an action or plan requires approval that has not been granted."""


class ApprovalRejectedError(ApprovalError):
    """Raised when an action or plan has been explicitly rejected by a human analyst."""


def requires_per_step_approval(action_class: ActionClass) -> bool:
    """Returns True if the action class requires per-step human approval."""
    return action_class in (ActionClass.INTRUSIVE, ActionClass.VALIDATION)


def requires_plan_approval(action_class: ActionClass) -> bool:
    """Returns True if the action class is governed by overall plan approval."""
    return action_class in (ActionClass.IMPORT, ActionClass.DISCOVERY, ActionClass.SCAN)


class ApprovalManager:
    """Manages human approval requests, final decisions, and execution gating."""

    def __init__(self, audit_log: AuditLog | None = None) -> None:
        self.audit_log = audit_log
        self._plan_approvals: dict[str, ApprovalDecision] = {}
        self._step_requests: dict[str, ApprovalRequest] = {}
        self._step_to_approval: dict[tuple[str, str], str] = {}
        self._decisions: dict[str, ApprovalDecision] = {}

    def approve_plan(
        self,
        assessment_id: str,
        decided_by: str,
        reason: str,
        notes: str | None = None,
    ) -> ApprovalDecision:
        """Approves the overall assessment plan, authorizing discovery and scan steps."""
        if assessment_id in self._plan_approvals:
            existing = self._plan_approvals[assessment_id]
            if existing.decision != "approved":
                raise ValueError(
                    f"Plan decision for assessment '{assessment_id}' is final ({existing.decision})"
                )
            return existing

        now = datetime.now(UTC)
        decision = ApprovalDecision(
            approval_id=f"plan_{assessment_id}_{now.strftime('%Y%m%d%H%M%S')}",
            decision="approved",
            decided_by=decided_by,
            reason=reason,
            decided_at=now,
            notes=notes,
        )
        self._plan_approvals[assessment_id] = decision
        self._audit(
            actor=decided_by,
            event_type="plan_approved",
            payload={
                "assessment_id": assessment_id,
                "approval_id": decision.approval_id,
                "reason": reason,
                "notes": notes,
            },
            assessment_id=assessment_id,
        )
        return decision

    def reject_plan(
        self,
        assessment_id: str,
        decided_by: str,
        reason: str,
        notes: str | None = None,
    ) -> ApprovalDecision:
        """Rejects the assessment plan; discovery and scan steps will be blocked."""
        if assessment_id in self._plan_approvals:
            existing = self._plan_approvals[assessment_id]
            if existing.decision != "rejected":
                raise ValueError(
                    f"Plan decision for assessment '{assessment_id}' is final ({existing.decision})"
                )
            return existing

        now = datetime.now(UTC)
        decision = ApprovalDecision(
            approval_id=f"plan_{assessment_id}_{now.strftime('%Y%m%d%H%M%S')}",
            decision="rejected",
            decided_by=decided_by,
            reason=reason,
            decided_at=now,
            notes=notes,
        )
        self._plan_approvals[assessment_id] = decision
        self._audit(
            actor=decided_by,
            event_type="plan_rejected",
            payload={
                "assessment_id": assessment_id,
                "approval_id": decision.approval_id,
                "reason": reason,
                "notes": notes,
            },
            assessment_id=assessment_id,
        )
        return decision

    def is_plan_approved(self, assessment_id: str) -> bool:
        """Returns True if the assessment plan has been explicitly approved."""
        return (
            assessment_id in self._plan_approvals
            and self._plan_approvals[assessment_id].decision == "approved"
        )

    def request_approval(self, step: PlanStep, assessment_id: str) -> ApprovalRequest:
        """Registers a pending approval request for a restricted action step."""
        key = (assessment_id, step.step_id)
        if key in self._step_to_approval:
            appr_id = self._step_to_approval[key]
            existing_req = self._step_requests[appr_id]
            if (
                existing_req.tool != step.tool
                or existing_req.target != step.target
                or existing_req.action_class != step.action_class
            ):
                raise ValueError(
                    f"Step '{step.step_id}' in assessment '{assessment_id}' already has an approval "
                    f"request with different parameters; step parameters cannot be modified"
                )
            return existing_req

        now = datetime.now(UTC)
        approval_id = f"appr_{assessment_id}_{step.step_id}_{uuid.uuid4().hex[:6]}"
        request = ApprovalRequest(
            approval_id=approval_id,
            assessment_id=assessment_id,
            step_id=step.step_id,
            action_class=step.action_class,
            tool=step.tool,
            target=step.target,
            rationale=step.rationale,
            requested_at=now,
            status="pending",
        )
        self._step_requests[approval_id] = request
        self._step_to_approval[key] = approval_id

        self._audit(
            actor="orchestrator",
            event_type="approval_requested",
            payload={
                "approval_id": approval_id,
                "assessment_id": assessment_id,
                "step_id": step.step_id,
                "action_class": str(step.action_class.value),
                "tool": step.tool,
                "target": step.target,
                "rationale": step.rationale,
            },
            assessment_id=assessment_id,
        )
        return request

    def decide(
        self,
        approval_id: str,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str,
        notes: str | None = None,
    ) -> ApprovalDecision:
        """Records a human decision for a pending approval request.

        Decisions are immutable and final; a rejected approval cannot be changed.
        """
        if approval_id not in self._step_requests:
            raise KeyError(f"Approval request '{approval_id}' not found")

        # Idempotency and finality checks
        if approval_id in self._decisions:
            existing = self._decisions[approval_id]
            if existing.decision == decision:
                return existing
            raise ValueError(
                f"Approval decision for '{approval_id}' is final ({existing.decision}) "
                f"and cannot be modified; a new step must be proposed"
            )

        now = datetime.now(UTC)
        dec_record = ApprovalDecision(
            approval_id=approval_id,
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            decided_at=now,
            notes=notes,
        )
        self._decisions[approval_id] = dec_record

        # Update the request status
        req = self._step_requests[approval_id]
        self._step_requests[approval_id] = req.model_copy(update={"status": decision})

        self._audit(
            actor=decided_by,
            event_type=f"approval_{decision}",
            payload={
                "approval_id": approval_id,
                "assessment_id": req.assessment_id,
                "step_id": req.step_id,
                "action_class": str(req.action_class.value),
                "decision": decision,
                "reason": reason,
                "notes": notes,
            },
            assessment_id=req.assessment_id,
        )
        return dec_record

    def require(self, step: PlanStep, assessment_id: str | None = None) -> None:
        """Enforces approval gates prior to step execution.

        Raises ApprovalRequiredError or ApprovalRejectedError if unapproved.
        """
        if requires_per_step_approval(step.action_class):
            if assessment_id is None:
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"requires assessment_id for per-step approval verification"
                )

            key = (assessment_id, step.step_id)
            appr_id = self._step_to_approval.get(key)
            if appr_id is None:
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"requires human per-step approval; no approval requested for assessment '{assessment_id}'"
                )

            req = self._step_requests[appr_id]
            if (
                req.assessment_id != assessment_id
                or req.tool != step.tool
                or req.target != step.target
                or req.action_class != step.action_class
            ):
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' differs from the approved request; "
                    f"a new approval is required"
                )

            if req.status == "pending":
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"requires human per-step approval; currently pending"
                )
            if req.status == "rejected":
                dec = self._decisions.get(appr_id)
                reason = dec.reason if dec else "explicitly rejected"
                raise ApprovalRejectedError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"was rejected: {reason}"
                )
            return

        if requires_plan_approval(step.action_class):
            if assessment_id is None:
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"requires plan approval, but assessment_id was not provided"
                )

            if not self.is_plan_approved(assessment_id):
                if (
                    assessment_id in self._plan_approvals
                    and self._plan_approvals[assessment_id].decision == "rejected"
                ):
                    raise ApprovalRejectedError(
                        f"Plan for assessment '{assessment_id}' was rejected: "
                        f"{self._plan_approvals[assessment_id].reason}"
                    )
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' ({step.action_class.value}) "
                    f"requires plan approval for assessment '{assessment_id}'"
                )
            return

        # Fail closed for any unclassified action class
        raise ApprovalRequiredError(
            f"Step '{step.step_id}' has unclassified action class "
            f"'{step.action_class.value if hasattr(step.action_class, 'value') else step.action_class}'; "
            f"approval tier is undefined"
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
