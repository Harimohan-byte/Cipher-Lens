"""Scope definition and registry for authorized target boundaries."""

from datetime import UTC, datetime

from pydantic import AwareDatetime, BaseModel, Field, model_validator


class Scope(BaseModel):
    """Registered authorization boundaries and constraints for assessment targets."""

    id: str
    owner: str
    authorization_reference: str
    allowed_targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    valid_from: AwareDatetime
    valid_to: AwareDatetime
    rate_limit: int | None = None
    asset_tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_window(self) -> "Scope":
        if self.valid_from > self.valid_to:
            raise ValueError("valid_from must not be after valid_to")
        return self

    def is_valid_at(self, check_time: datetime | None = None) -> bool:
        """Checks if the given or current timestamp falls within the validity window."""
        t = check_time or datetime.now(UTC)
        return self.valid_from <= t <= self.valid_to


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

