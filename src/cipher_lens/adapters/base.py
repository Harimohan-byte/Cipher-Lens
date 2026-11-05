"""Base adapter interface and execution types."""

import ipaddress
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import PlanStep
from cipher_lens.store.artifacts import ArtifactStore

_RFC_1123_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
_PORTS_REGEX = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")


def validate_safe_target(target: str) -> str:
    """Validates a target host or IP using strict allowlisting (ERR-07).

    Accepts valid IPv4/IPv6 addresses or RFC 1123 hostnames.
    Rejects leading hyphens ('-'), shell metacharacters, and whitespace.
    """
    clean = str(target or "").strip()
    if not clean:
        raise ValueError("Invalid characters in target; cannot be empty")
    if clean.startswith("-"):
        raise ValueError(f"Invalid characters in target '{clean}'; cannot begin with a hyphen (flag injection defense)")
    # Validate as IP address
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass
    # Validate as RFC 1123 Hostname
    if _RFC_1123_HOSTNAME_RE.match(clean):
        return clean
    raise ValueError(f"Invalid characters in target '{clean}'; target is neither a valid IP address nor an RFC 1123 hostname")


def validate_safe_ports(ports: str | None) -> str | None:
    """Validates comma-separated port numbers or ranges (1-65535) (ERR-07)."""
    if ports is None:
        return None
    clean = str(ports).strip()
    if not clean:
        return None
    if not _PORTS_REGEX.match(clean):
        raise ValueError(f"Invalid port specification '{ports}'; must be comma-separated numbers or ranges")
    for part in clean.split(","):
        if "-" in part:
            low, high = map(int, part.split("-", 1))
            if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
                raise ValueError(f"Port range '{part}' out of valid bounds (1-65535)")
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port '{p}' out of valid bounds (1-65535)")
    return clean


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
    pinned_ip: str | None = None

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
