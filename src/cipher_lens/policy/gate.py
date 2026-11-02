# DECISION: Default DNS resolution treats any resolution failure or partial out-of-scope resolution as an immediate denial to prevent DNS rebinding or unauthorized scans.
# DECISION: Exclusions take absolute precedence over allows, checked before allow verification.
"""Deterministic policy gate enforcing registered target scope, tool allowlists, and boundaries."""

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.audit import AuditLog


@dataclass(frozen=True)
class ParsedTarget:
    """Sanitized and stripped target destination with optional port."""

    raw: str
    host: str
    port: int | None
    is_ip: bool


@dataclass(frozen=True)
class Decision:
    """Deterministic policy authorization decision."""

    allowed: bool
    reason: str
    rule_id: str


def parse_target(raw_target: str) -> ParsedTarget:
    """Safely extracts the destination host and port from a target string.

    Strips scheme, userinfo (e.g. user@host tricks), paths, queries, and fragments.
    """
    clean_target = raw_target.strip()
    port: int | None = None

    if "://" in clean_target:
        parsed = urlsplit(clean_target)
        host = parsed.hostname or ""
        port = parsed.port
    else:
        # Check for userinfo trick without scheme e.g. user@host
        if "@" in clean_target:
            clean_target = clean_target.rpartition("@")[2]

        # Handle path/query if passed without scheme e.g. host:port/path
        if "/" in clean_target:
            clean_target = clean_target.split("/")[0]

        # Handle bracketed IPv6: [2001:db8::1]:8080 or [2001:db8::1]
        if clean_target.startswith("["):
            bracket_end = clean_target.find("]")
            if bracket_end != -1:
                host = clean_target[1:bracket_end]
                rest = clean_target[bracket_end + 1 :]
                if rest.startswith(":") and rest[1:].isdigit():
                    port = int(rest[1:])
            else:
                host = clean_target.strip("[]")
        elif clean_target.count(":") == 1:
            parts = clean_target.split(":")
            if parts[1].isdigit():
                host = parts[0]
                port = int(parts[1])
            else:
                host = clean_target
        else:
            host = clean_target

    is_ip = _is_ip(host)
    return ParsedTarget(raw=raw_target, host=host, port=port, is_ip=is_ip)


def _is_ip(candidate: str) -> bool:
    """Checks whether a host string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _ip_matches_entry(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, entry: str) -> bool:
    """Checks if an IP matches an allowed or excluded entry (exact IP or CIDR network)."""
    clean_entry = entry.strip()
    if "/" in clean_entry:
        try:
            net = ipaddress.ip_network(clean_entry, strict=False)
            return ip_obj.version == net.version and ip_obj in net
        except ValueError:
            return False
    else:
        try:
            target_ip = ipaddress.ip_address(clean_entry)
            return ip_obj == target_ip
        except ValueError:
            return False


def default_dns_resolver(host: str) -> list[str]:
    """Default DNS resolver using getaddrinfo to resolve all IPv4 and IPv6 addresses."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        if not ips:
            raise ValueError(f"No IP addresses resolved for host {host}")
        return ips
    except (socket.gaierror, OSError) as exc:
        raise ValueError(f"DNS resolution failed for {host}: {exc}") from exc


class PolicyGate:
    """Deterministic security gate authorizing every scanner action against registered scope."""

    def __init__(
        self,
        registry: ScopeRegistry,
        audit_log: AuditLog | None = None,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.registry = registry
        self.audit_log = audit_log
        self.resolver = resolver or default_dns_resolver

    def authorize(
        self,
        target: str,
        port: int | None = None,
        tool: str = "nmap",
        action_class: ActionClass = ActionClass.DISCOVERY,
        assessment_id: str | None = None,
    ) -> Decision:
        """Evaluates whether an action is authorized within registered scope and audits the decision."""
        scopes = self.registry.list_all()
        if not scopes:
            decision = Decision(
                allowed=False,
                reason="No registered scope found; all scanning actions are blocked",
                rule_id="NO_SCOPE_REGISTERED",
            )
            self._audit(decision, target, port, tool, action_class, assessment_id)
            return decision

        parsed = parse_target(target)
        effective_port = port if port is not None else parsed.port

        # Evaluate against active scopes (first matching allowed scope or best denial reason)
        best_decision = Decision(
            allowed=False,
            reason=f"Target '{target}' (host '{parsed.host}') is not in registered scope",
            rule_id="NOT_IN_SCOPE",
        )

        for scope in scopes:
            decision = self._check_scope(scope, parsed, effective_port, tool)
            if decision.allowed:
                best_decision = decision
                break
            # If rejected specifically by exclusion, tool, or port, prioritize that explicit reason
            if decision.rule_id in (
                "EXCLUDED_TARGET",
                "PORT_NOT_ALLOWED",
                "TOOL_NOT_ALLOWED",
                "EXPIRED_VALIDITY_WINDOW",
                "DNS_RESOLUTION_OUT_OF_SCOPE",
            ):
                best_decision = decision
                if decision.rule_id == "EXCLUDED_TARGET":
                    break

        self._audit(best_decision, target, effective_port, tool, action_class, assessment_id)
        return best_decision

    def _check_scope(
        self,
        scope: Scope,
        parsed: ParsedTarget,
        port: int | None,
        tool: str,
    ) -> Decision:
        """Evaluates a single scope against the proposed target, tool, and port."""
        # 1. Validity window
        if not scope.is_valid_at():
            return Decision(
                allowed=False,
                reason=f"Scope '{scope.id}' validity window is not active",
                rule_id="EXPIRED_VALIDITY_WINDOW",
            )

        # 2. Tool allowlist
        if scope.tool_allowlist and tool.lower() not in [t.lower() for t in scope.tool_allowlist]:
            return Decision(
                allowed=False,
                reason=f"Tool '{tool}' is not in the scope tool allowlist for scope '{scope.id}'",
                rule_id="TOOL_NOT_ALLOWED",
            )

        # 3. Resolve IPs if hostname
        ips_to_check: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        if parsed.is_ip:
            try:
                ips_to_check.append(ipaddress.ip_address(parsed.host))
            except ValueError:
                return Decision(
                    allowed=False,
                    reason=f"Malformed IP address '{parsed.host}'",
                    rule_id="INVALID_IP",
                )
        else:
            try:
                resolved_strings = self.resolver(parsed.host)
                for ip_str in resolved_strings:
                    ips_to_check.append(ipaddress.ip_address(ip_str))
            except Exception as exc:
                return Decision(
                    allowed=False,
                    reason=f"DNS resolution failed or out-of-scope for '{parsed.host}': {exc}",
                    rule_id="DNS_RESOLUTION_FAILED",
                )

        # 4. Exclusions strictly beat allows
        for exclusion in scope.exclusions:
            clean_ex = exclusion.strip()
            # Direct host/URL match
            if clean_ex.lower() == parsed.host.lower() or clean_ex.lower() == parsed.raw.lower():
                return Decision(
                    allowed=False,
                    reason=f"Target '{parsed.host}' is explicitly excluded in scope '{scope.id}'",
                    rule_id="EXCLUDED_TARGET",
                )
            # IP / CIDR exclusion match
            for ip_obj in ips_to_check:
                if _ip_matches_entry(ip_obj, clean_ex):
                    return Decision(
                        allowed=False,
                        reason=(
                            f"Resolved IP '{ip_obj}' for target '{parsed.host}' "
                            f"is explicitly excluded in scope '{scope.id}'"
                        ),
                        rule_id="EXCLUDED_TARGET",
                    )

        # 5. Target containment in allowed_targets
        # Check direct host or exact IP match
        direct_match = False
        for allowed in scope.allowed_targets:
            clean_al = allowed.strip()
            if clean_al.lower() == parsed.host.lower() or clean_al.lower() == parsed.raw.lower():
                direct_match = True
                break

        if not direct_match:
            # For every resolved IP, require that it falls inside at least one allowed target
            for ip_obj in ips_to_check:
                ip_in_scope = False
                for allowed in scope.allowed_targets:
                    if _ip_matches_entry(ip_obj, allowed):
                        ip_in_scope = True
                        break
                if not ip_in_scope:
                    rule = "NOT_IN_SCOPE" if parsed.is_ip else "DNS_RESOLUTION_OUT_OF_SCOPE"
                    return Decision(
                        allowed=False,
                        reason=(
                            f"{'Target IP' if parsed.is_ip else 'Resolved IP'} '{ip_obj}' for target '{parsed.host}' "
                            f"is not in registered scope '{scope.id}'"
                        ),
                        rule_id=rule,
                    )

        # 6. Allowed ports check for targets within scope
        if scope.allowed_ports and port is not None and port not in scope.allowed_ports:
            return Decision(
                allowed=False,
                reason=f"Port {port} for target '{parsed.host}' is not in allowed ports {scope.allowed_ports} for scope '{scope.id}'",
                rule_id="PORT_NOT_ALLOWED",
            )

        return Decision(
            allowed=True,
            reason=f"Target '{parsed.host}' authorized within scope '{scope.id}'",
            rule_id="ALLOW_EXACT" if direct_match else "ALLOW_CIDR",
        )

    def _audit(
        self,
        decision: Decision,
        target: str,
        port: int | None,
        tool: str,
        action_class: ActionClass,
        assessment_id: str | None,
    ) -> None:
        """Records an immutable audit event for every policy decision."""
        if self.audit_log is None:
            return

        payload: dict[str, Any] = {
            "target": target,
            "port": port,
            "tool": tool,
            "action_class": str(action_class.value if hasattr(action_class, "value") else action_class),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
        }
        self.audit_log.append(
            actor="policy_gate",
            event_type="policy_decision",
            payload=payload,
            assessment_id=assessment_id,
        )
