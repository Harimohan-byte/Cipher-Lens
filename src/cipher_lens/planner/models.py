"""Data models for assessment intake and adaptive planning (Task A11).

Invariants:
- AGENTS.md Rule 4: Observed evidence and AI inference are separate fields and never mixed.
- AGENTS.md Rule 5: LLM output is untrusted input, validated with Pydantic.
- Master Plan §9: Every step has rationale and triggered_by IDs referencing known evidence.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cipher_lens.models.findings import Finding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass


class StepParams(BaseModel):
    """Structured step parameters compliant with Gemini Developer API JSON schema constraints.

    Eliminates unconstrained dictionary schemas to ensure full compatibility with the
    Google Gemini Developer API.
    """

    model_config = ConfigDict(extra="ignore")

    target: str = ""
    port: int | None = None
    ports: str = ""
    profile: str = "discovery"
    mode: str = "passive"
    ssl: bool = False
    scripts: list[str] = Field(default_factory=list)
    argv: list[str] = Field(default_factory=list)
    pinned_ip: str | None = None
    context_name: str | None = None
    exclusions: list[str] = Field(default_factory=list)
    max_poll_seconds: float = 300.0
    poll_interval_seconds: float = 2.0
    active_scan: bool = False
    active: bool = False

    def get(self, key: str, default: Any = None) -> Any:
        val = getattr(self, key, default)
        return default if val is None else val

    def items(self) -> Any:
        return self.model_dump().items()

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return hasattr(self, str(key))


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
    target: str = ""
    params: StepParams = Field(default_factory=StepParams)
    rationale: str = "Reconnaissance and vulnerability assessment action"
    triggered_by: list[str] = Field(default_factory=list)
    expected_outcome: str = "Discover open services and potential vulnerabilities"
    nist_phase: str = "discovery"
    action_class: ActionClass = ActionClass.DISCOVERY
    idempotency_key: str | None = None

    @field_validator("params", mode="before")
    @classmethod
    def validate_params(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return StepParams(**v)
        if isinstance(v, StepParams):
            return v
        return StepParams()


class InferenceProposal(BaseModel):
    """AI inference separated from observed evidence (AGENTS.md Rule 4)."""

    inference_id: str | None = None
    summary: str = "General assessment inference"
    confidence: float = 0.5
    rationale: str = ""


class PlanProposal(BaseModel):
    """Adaptive plan proposal returned by the planner."""

    steps: list[ProposedStep] = Field(default_factory=list)
    inferences: list[InferenceProposal] = Field(default_factory=list)
    stop: bool = False
    stop_reason: str | None = None
    planner_source: Literal["live", "cached", "rule-based"] = "rule-based"

    @classmethod
    def _coerce_inferences(cls, v: Any) -> list[Any]:
        if isinstance(v, dict):
            items = []
            for k, val in v.items():
                items.append({"summary": f"{k}: {val}", "confidence": 0.5})
            return items
        if isinstance(v, list):
            norm_list = []
            for item in v:
                if isinstance(item, dict) and "summary" not in item:
                    summary = " ".join(f"{k}: {val}" for k, val in item.items()) or "Inference note"
                    norm_list.append({"summary": summary, "confidence": item.get("confidence", 0.5)})
                elif isinstance(item, str):
                    norm_list.append({"summary": item, "confidence": 0.5})
                else:
                    norm_list.append(item)
            return norm_list
        return []

    @field_validator("inferences", mode="before")
    @classmethod
    def validate_inferences(cls, v: Any) -> list[Any]:
        return cls._coerce_inferences(v)


class StateSummary(BaseModel):
    """Aggregated assessment state presented to the planner."""

    scope_target: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    done_steps: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    remaining_budget: int = 30
    evidence_ids: list[str] = Field(default_factory=list)
