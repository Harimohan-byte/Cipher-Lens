"""Observed facts from tools (hosts, ports, services, banners)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from cipher_lens.models.findings import Asset, Evidence


class Observation(BaseModel):
    """An observed factual entity that does not inherently constitute a vulnerability."""
    id: str
    source_tool: str
    asset: Asset
    observation_type: Literal["host", "port", "service", "os", "banner", "tech"]
    data: dict = Field(default_factory=dict)
    raw_evidence: Evidence
    observed_at: datetime
