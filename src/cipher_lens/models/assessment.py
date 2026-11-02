"""Assessment and execution run persistence models."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.findings import Finding
from cipher_lens.models.plan import PlanStep


class AssessmentStatus(str, Enum):
    """Lifecycle status of an assessment."""

    CREATED = "created"
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class Assessment(BaseModel):
    """Assessment configuration and lifecycle metadata."""

    id: str
    title: str
    target: str
    scope_id: str | None = None
    status: AssessmentStatus = AssessmentStatus.CREATED
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class StepRun(BaseModel):
    """A tool execution run associated with a plan step."""

    run_id: str
    assessment_id: str
    step_id: str
    tool_name: str
    status: Literal["success", "failed", "timeout", "skipped"]
    exit_code: int | None = None
    stdout_artifact_id: str | None = None
    stderr_artifact_id: str | None = None
    raw_sha256: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    duration_ms: int | None = None
    error_message: str | None = None


class AssessmentResumeState(BaseModel):
    """State reconstructed from the repository to resume an assessment."""

    assessment: Assessment
    pending_steps: list[PlanStep] = Field(default_factory=list)
    completed_steps: list[PlanStep] = Field(default_factory=list)
    failed_steps: list[PlanStep] = Field(default_factory=list)
    runs: list[StepRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    approvals: list[tuple[ApprovalRequest, ApprovalDecision | None]] = Field(default_factory=list)
