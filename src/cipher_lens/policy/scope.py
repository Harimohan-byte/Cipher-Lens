"""Scope definition and registry for authorized target boundaries."""

from datetime import UTC, datetime
from typing import Any

from pydantic import AwareDatetime, BaseModel, Field, model_validator


class Scope(BaseModel):
    """Registered authorization boundaries and constraints for assessment targets."""

    id: str
    owner: str = "Authorized Operator"
    name: str = ""
    authorization_reference: str
    allowed_targets: list[str] = Field(default_factory=list)
    targets: list[str] | None = None
    exclusions: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    valid_from: AwareDatetime | None = None
    valid_to: AwareDatetime | None = None
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    rate_limit: int | None = None
    asset_tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "targets" in data and ("allowed_targets" not in data or not data.get("allowed_targets")):
                data["allowed_targets"] = data.get("targets", [])
            if "window_start" in data and "valid_from" not in data:
                data["valid_from"] = data["window_start"]
            if "window_end" in data and "valid_to" not in data:
                data["valid_to"] = data["window_end"]
        return data

    @model_validator(mode="after")
    def _check_window(self) -> "Scope":
        start = self.valid_from or self.window_start
        end = self.valid_to or self.window_end
        if start and end and start > end:
            raise ValueError("valid_from must not be after valid_to")
        return self

    def is_valid_at(self, check_time: datetime | None = None) -> bool:
        """Checks if the given or current timestamp falls within the validity window."""
        t = check_time or datetime.now(UTC)
        start = self.valid_from or self.window_start
        end = self.valid_to or self.window_end
        if start and t < start:
            return False
        if end and t > end:
            return False
        return True


class ScopeRegistry:
    """In-memory registry maintaining registered target scopes."""

    def __init__(self) -> None:
        self._scopes: dict[str, Scope] = {}

    def register(self, scope: Scope) -> None:
        """Registers or replaces an authorized scope."""
        self._scopes[scope.id] = scope

    def get(self, scope_id: str) -> Scope | None:
        """Retrieves a scope by its identifier."""
        return self._scopes.get(scope_id)

    def list_all(self) -> list[Scope]:
        """Returns all registered scopes."""
        return list(self._scopes.values())

