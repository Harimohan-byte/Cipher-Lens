"""Data models for assessment intake and adaptive planning (Task A11).

Invariants:
- AGENTS.md Rule 4: Observed evidence and AI inference are separate fields and never mixed.
- AGENTS.md Rule 5: LLM output is untrusted input, validated with Pydantic.
- Master Plan §9: Every step has rationale and triggered_by IDs referencing known evidence.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

from cipher_lens.models.findings import Finding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass


class AssessmentRequest(BaseModel):
    """Structured assessment request parsed from natural language intake."""

    targets: list[str] = Field(default_factory=list)
    objectives: list[str] = Field(default_factory=list)
    depth: Literal["quick", "standard", "thorough"] = "standard"
    constraints: list[str] = Field(default_factory=list)
    is_ambiguous: bool = False
    clarifying_question: str | None = None


class ProposedStep(BaseModel):
    """Individual action step proposed by planner."""

    step_id: str
    tool: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    triggered_by: list[str] = Field(default_factory=list)
    expected_outcome: str
    nist_phase: str = "discovery"
    action_class: ActionClass = ActionClass.DISCOVERY
    idempotency_key: str | None = None


class InferenceProposal(BaseModel):
    """AI inference separated from observed evidence (AGENTS.md Rule 4)."""

    inference_id: str | None = None
    summary: str
    confidence: float = 0.5
    rationale: str = ""


class PlanProposal(BaseModel):
    """Adaptive plan proposal returned by the planner."""

    steps: list[ProposedStep] = Field(default_factory=list)
    inferences: list[InferenceProposal] = Field(default_factory=list)
    stop: bool = False
    stop_reason: str | None = None
    planner_source: Literal["live", "cached", "rule-based"] = "rule-based"


class StateSummary(BaseModel):
    """Aggregated assessment state presented to the planner."""

    scope_target: str
    allowed_tools: list[str] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    done_steps: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    remaining_budget: int = 30
    evidence_ids: list[str] = Field(default_factory=list)
