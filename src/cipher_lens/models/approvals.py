"""Human-in-the-loop approval models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from cipher_lens.models.plan import ActionClass


class ApprovalRequest(BaseModel):
    """A pending approval required before executing restricted actions."""
    approval_id: str
    assessment_id: str
    step_id: str
    action_class: ActionClass
    tool: str
    target: str
    rationale: str
    requested_at: datetime
    requested_by: str = "operator"
    plan_hash: str | None = None
    scope_hash: str | None = None
    status: Literal["pending", "approved", "rejected"] = "pending"


class ApprovalDecision(BaseModel):
    """The recorded human decision for an approval request."""
    approval_id: str
    decision: Literal["approved", "rejected"]
    decided_by: str
    reason: str
    decided_at: datetime
    notes: str | None = None
    plan_hash: str | None = None
    scope_hash: str | None = None
    expires_at: datetime | None = None
