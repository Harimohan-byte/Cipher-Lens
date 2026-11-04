"""Scope definition and registry for authorized target boundaries."""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from pydantic import AwareDatetime, BaseModel, Field, model_validator

HARD_DENY_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),     # IPv4 Link-Local / Cloud Metadata
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
    ipaddress.ip_network("0.0.0.0/8"),          # Unspecified / Host-on-this-net
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

PROHIBITED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


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
    allow_public_targets: bool = False
    allow_localhost: bool = True

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

    @model_validator(mode="after")
    def _validate_targets(self) -> "Scope":
        """Enforces minimum prefix lengths, hard-deny list, and private/lab defaults (ERR-02)."""
        if self.allow_public_targets and (
            not self.authorization_reference or not self.authorization_reference.strip()
        ):
            raise ValueError("Public scope targets mandate a non-empty authorization_reference")

        for target in self.allowed_targets:
            clean = target.strip()
            if not clean:
                raise ValueError("Scope allowed_target cannot be empty")
            if clean.startswith("-"):
                raise ValueError(f"Scope target '{clean}' cannot begin with a hyphen")

            # Check prohibited cloud metadata domains
            host_only = clean.split("://", 1)[1] if "://" in clean else clean
            host_only = host_only.split("/", 1)[0].split(":", 1)[0].lower()
            if host_only in PROHIBITED_METADATA_HOSTS:
                raise ValueError(f"Target '{clean}' is a prohibited cloud metadata destination")

            # Check CIDRs
            is_cidr = False
            if "://" not in clean and "/" in clean:
                parts = clean.split("/")
                if len(parts) == 2 and parts[1].isdigit():
                    is_cidr = True

            if is_cidr:
                try:
                    net = ipaddress.ip_network(clean, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR network '{clean}': {e}") from e

                # Prefix length enforcement (min /16 for IPv4, min /48 for IPv6)
                if net.version == 4 and net.prefixlen < 16:
                    raise ValueError(
                        f"IPv4 CIDR '{clean}' prefix length /{net.prefixlen} is too broad (minimum prefix is /16)"
                    )
                if net.version == 6 and net.prefixlen < 48:
                    raise ValueError(
                        f"IPv6 CIDR '{clean}' prefix length /{net.prefixlen} is too broad (minimum prefix is /48)"
                    )

                # Hard deny overlapping networks
                for deny in HARD_DENY_NETWORKS:
                    if net.overlaps(deny):
                        raise ValueError(f"Scope CIDR '{clean}' overlaps with prohibited network '{deny}'")

                # Routable public ranges require explicit flag
                if not (net.is_private or net.is_loopback):
                    if not self.allow_public_targets:
                        raise ValueError(
                            f"Routable public network '{clean}' requires allow_public_targets=True on Scope"
                        )
            else:
                # Single IP or Hostname
                is_parsed_ip = False
                try:
                    ip = ipaddress.ip_address(host_only)
                    is_parsed_ip = True
                except ValueError:
                    pass

                if is_parsed_ip:
                    for deny in HARD_DENY_NETWORKS:
                        if ip in deny:
                            raise ValueError(f"Scope target IP '{clean}' is within prohibited network '{deny}'")
                    if not (ip.is_private or ip.is_loopback):
                        if not self.allow_public_targets:
                            raise ValueError(
                                f"Public target IP '{clean}' requires allow_public_targets=True on Scope"
                            )

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

