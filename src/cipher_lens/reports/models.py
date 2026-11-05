"""Data container models for PDF report generation."""

from pydantic import BaseModel, Field

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.assessment import Assessment, StepRun
from cipher_lens.models.findings import Evidence, Finding


class ReportData(BaseModel):
    """Aggregate data structure used to generate the assessment PDF report."""

    assessment: Assessment
    scope_target: str
    scope_reference: str = "Authorized Lab Scope"
    testing_window: str = "Defined testing window"
    rate_limits: str = "Enforced per adapter policy"
    findings: list[Finding] = Field(default_factory=list)
    runs: list[StepRun] = Field(default_factory=list)
    approvals: list[tuple[ApprovalRequest, ApprovalDecision | None]] = Field(
        default_factory=list
    )
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    executive_summary: str = ""
    executive_summary_badge: str = "[DETERMINISTIC FALLBACK]"
    audit_event_count: int = 0
    audit_head_hash: str = "genesis"
    audit_verified: bool = True
