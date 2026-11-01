"""Execution plan and action class models."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class ActionClass(str, Enum):
    """Action classes with defined authorization tiers."""
    IMPORT = "import"
    DISCOVERY = "discovery"
    SCAN = "scan"
    INTRUSIVE = "intrusive"
    VALIDATION = "validation"


class PlanStep(BaseModel):
    """An atomic step proposed by the planner or human."""
    step_id: str
    tool: Literal[
        "nmap",
        "nikto",
        "zap",
        "nessus_import",
        "openvas_import",
        "burp_import",
        "manual_validation",
    ]
    action_class: ActionClass
    target: str
    params: dict = Field(default_factory=dict)
    rationale: str
    triggered_by: list[str] = Field(default_factory=list)
    expected_outcome: str
    nist_phase: Literal["planning", "discovery", "attack", "reporting"]
    idempotency_key: str | None = None
