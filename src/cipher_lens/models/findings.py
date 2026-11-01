"""Vulnerability and finding data models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Asset(BaseModel):
    """Network or application target asset."""
    host: str
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    url_path: str | None = None


class Evidence(BaseModel):
    """Observed direct evidence from tools."""
    id: str
    source_tool: str
    run_id: str
    artifact_id: str
    locator: str  # xpath / JSON pointer / line range
    raw_sha256: str
    snippet: str  # verbatim, truncated
    observed_at: datetime
    origin: Literal["live", "import", "replayed", "sample"]


class Inference(BaseModel):
    """AI-generated inference, always explicitly labeled."""
    id: str
    text: str
    provider: str
    label: Literal["live", "cached", "rule-based"]
    based_on: list[str]
    created_at: datetime


class CvssInfo(BaseModel):
    """CVSS score and vector information."""
    score: float
    version: str
    vector: str | None = None
    source: str  # tool name or "nvd"


class FactorValue(BaseModel):
    """Individual factor contributing to composite risk score."""
    value: float
    source: str
    description: str | None = None


class RiskScore(BaseModel):
    """Composite risk score breakdown."""
    total: float
    band: str
    factors: dict[str, FactorValue]
    weights_version: str


class ValidationRecord(BaseModel):
    """Human-approved validation activity outcome."""
    approval_id: str
    outcome: Literal["not_run", "succeeded", "failed", "inconclusive"]
    attested_by: str
    evidence_artifact_id: str | None = None
    recorded_at: datetime


class Finding(BaseModel):
    """A normalized, correlated vulnerability finding."""
    id: str  # e.g., VAPT-0001
    title: str
    asset: Asset
    sources: list[str]
    evidence: list[Evidence]
    inferences: list[Inference] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss: CvssInfo | None = None
    tool_severity: str
    confidence: Literal["high", "medium", "low"]
    status: Literal["confirmed", "suspected", "false_positive", "accepted_risk"]
    status_reason: str
    limitations: list[str] = Field(default_factory=list)
    risk: RiskScore | None = None
    validation: ValidationRecord | None = None
    correlation_key: str
    related_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime

    @field_validator("evidence")
    @classmethod
    def validate_evidence_non_empty(cls, v: list[Evidence]) -> list[Evidence]:
        if not v:
            raise ValueError("At least one evidence record is required for a Finding.")
        return v


class RawFinding(BaseModel):
    """Pre-correlation finding parsed directly from tool output."""
    title: str
    asset: Asset
    tool_name: str
    tool_severity: str
    raw_evidence: Evidence
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    description: str | None = None
    solution: str | None = None
    confidence: Literal["high", "medium", "low"] = "medium"
