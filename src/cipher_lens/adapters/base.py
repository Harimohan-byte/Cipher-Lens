"""Base adapter interface and execution types."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import PlanStep
from cipher_lens.store.artifacts import ArtifactStore


class AdapterStatus(str, Enum):
    """Operational status of a tool adapter."""
    LIVE = "live"
    IMPORT_ONLY = "import_only"
    MANUAL = "manual"
    PLANNED = "planned"
    UNSUPPORTED = "unsupported"


class HealthResult(BaseModel):
    """Health check outcome for an adapter and its underlying binary/service."""
    status: Literal["healthy", "degraded", "unavailable"]
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    """Result of running an adapter."""
    status: Literal["succeeded", "failed", "timed_out"]
    stdout: str
    stderr: str
    exit_code: int | None = None
    duration_seconds: float
    artifact_id: str | None = None


class ExecutionContext(BaseModel):
    """Contextual runtime dependencies passed to adapter execution."""
    artifact_store: ArtifactStore
    rate_limit: int | None = None
    timeout_seconds: int = 300

    model_config = {"arbitrary_types_allowed": True}


class BaseAdapter(ABC):
    """Abstract base class for all scanner and import adapters.

    Invariants:
    1. Adapters must never render UI.
    2. Adapters must never assign authoritative risk scores.
    3. Import-only adapters must explicitly reject live run() calls.
    """

    name: str
    status: AdapterStatus
    params_model: type[BaseModel]

    @abstractmethod
    async def healthcheck(self) -> HealthResult:
        """Check if local binary or remote service is reachable and responsive."""
        pass

    async def run(self, step: PlanStep, ctx: ExecutionContext) -> ExecutionResult:
        """Execute tool against validated target.

        Import-only adapters inherit this default implementation which safely rejects execution.
        """
        if self.status == AdapterStatus.IMPORT_ONLY:
            raise NotImplementedError(
                f"Adapter '{self.name}' is import-only and cannot be executed live."
            )
        raise NotImplementedError(f"Live execution not implemented for {self.name}")

    @abstractmethod
    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Parse raw artifact output into standardized Observations and RawFindings.

        Must use defusedxml for XML outputs and preserve verbatim evidence snippets.
        """
        pass
