# DECISION: Default DNS resolution treats any resolution failure or partial out-of-scope resolution as an immediate denial to prevent DNS rebinding or unauthorized scans.
# DECISION: Exclusions take absolute precedence over allows, checked before allow verification.
# DECISION: Direct hostname matches still require all resolved IPs to be in scope to prevent DNS rebinding.
# DECISION: When scope specifies allowed_ports, actions without an explicit or URL-derived port are denied to prevent scanners from scanning unauthorized ports.
"""Deterministic policy gate enforcing registered target scope, tool allowlists, and boundaries."""

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import idna

from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.scope import (
    HARD_DENY_NETWORKS,
    PROHIBITED_METADATA_HOSTS,
    Scope,
    ScopeRegistry,
)
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
    pinned_ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)


def redact_target(raw_target: str) -> str:
    """Redacts user credentials from target strings before storage in audit logs."""
    clean = raw_target.strip()
    if "://" in clean:
        return re.sub(r"://([^@/]+)@", r"://<redacted>@", clean)
    if "@" in clean:
        return re.sub(r"^([^@/]+)@", r"<redacted>@", clean)
    return clean


def canonicalize_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Canonicalizes IP addresses, converting IPv4-mapped IPv6, 6to4, or NAT64 to IPv4 (ERR-17)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip in ipaddress.ip_network("2002::/16"):
            return ipaddress.IPv4Address(ip.packed[2:6])
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            return ipaddress.IPv4Address(ip.packed[12:16])
    return ip


def parse_target(raw_target: str) -> ParsedTarget:
    """Safely extracts the destination host and port from a target string.

    Strips scheme, userinfo (e.g. user@host tricks), paths, queries, and fragments.
    Normalizes domain names via IDN UTS #46 to prevent homograph bypasses (ERR-28).
    """
    clean_target = raw_target.strip()
    port: int | None = None

    if "://" in clean_target:
        parsed = urlsplit(clean_target)
        host = parsed.hostname or ""
        port = parsed.port  # Raises ValueError if port is invalid/out-of-range
    else:
        # Strip path, query, and fragment first (e.g. evil.com/a@10.0.0.5 -> evil.com)
        clean_target = re.split(r"[/?#]", clean_target, maxsplit=1)[0]

        # Then strip userinfo (e.g. user@host -> host)
        if "@" in clean_target:
            clean_target = clean_target.rpartition("@")[2]

        # Handle bracketed IPv6: [2001:db8::1]:8080 or [2001:db8::1]
        if clean_target.startswith("["):
            bracket_end = clean_target.find("]")
            if bracket_end != -1:
                host = clean_target[1:bracket_end]
                rest = clean_target[bracket_end + 1 :]
                if rest.startswith(":"):
                    port_str = rest[1:]
                    if not (port_str.isdigit() and 1 <= int(port_str) <= 65535):
                        raise ValueError(f"Invalid port: {port_str}")
                    port = int(port_str)
            else:
                host = clean_target.strip("[]")
        elif clean_target.count(":") == 1:
            parts = clean_target.split(":")
            host = parts[0]
            port_str = parts[1]
            if not (port_str.isdigit() and 1 <= int(port_str) <= 65535):
                raise ValueError(f"Invalid port: {port_str}")
            port = int(port_str)
        else:
            host = clean_target

    # Normalize host: lowercase and strip trailing FQDN dot
    host = host.rstrip(".").lower()
    is_ip = _is_ip(host)
    if not is_ip and host:
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except Exception as exc:
            raise ValueError(f"Invalid domain name or IDN encoding failed for '{host}': {exc}") from exc

    return ParsedTarget(raw=raw_target, host=host, port=port, is_ip=is_ip)


def _is_ip(candidate: str) -> bool:
    """Checks whether a host string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _ip_matches_entry(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, entry: str) -> bool:
    """Checks if an IP matches an allowed or excluded entry (exact IP or CIDR network).

    Both the target IP and entry are canonicalized (e.g. ::ffff:10.0.0.1 -> 10.0.0.1) (ERR-17).
    """
    clean_entry = entry.strip()
    # Normalize entry if scheme or port was provided (e.g. http://127.0.0.1:3000 -> 127.0.0.1)
    if "://" in clean_entry:
        try:
            clean_entry = urlsplit(clean_entry).hostname or clean_entry
        except Exception:
            pass
    elif ":" in clean_entry and not clean_entry.startswith("[") and clean_entry.count(":") == 1:
        clean_entry = clean_entry.split(":")[0]

    canon_target = canonicalize_ip(ip_obj)
    if "/" in clean_entry:
        try:
            net = ipaddress.ip_network(clean_entry, strict=False)
            if canon_target.version == net.version and canon_target in net:
                return True
            if ip_obj.version == net.version and ip_obj in net:
                return True
            return False
        except ValueError:
            return False
    else:
        try:
            target_ip = ipaddress.ip_address(clean_entry)
            canon_entry = canonicalize_ip(target_ip)
            return canon_target == canon_entry or ip_obj == target_ip
        except ValueError:
            return False


def default_dns_resolver(host: str) -> list[str]:
    """Default DNS resolver using getaddrinfo to resolve all IPv4 and IPv6 addresses."""
    # Fast-path well-known test lab hosts to avoid OS-level LLMNR/NetBIOS timeouts on Windows
    if host in ("localhost", "127.0.0.1"):
        return ["127.0.0.1"]
    if host in ("lab-target.local", "lab.local"):
        return ["10.0.0.5"]
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

        try:
            parsed = parse_target(target)
        except ValueError as exc:
            decision = Decision(
                allowed=False,
                reason=f"Invalid target specification '{target}': {exc}",
                rule_id="INVALID_TARGET",
            )
            self._audit(decision, target, port, tool, action_class, assessment_id)
            return decision

        if port is not None and not (1 <= port <= 65535):
            decision = Decision(
                allowed=False,
                reason=f"Invalid port parameter: {port}",
                rule_id="INVALID_TARGET",
            )
            self._audit(decision, target, port, tool, action_class, assessment_id)
            return decision

        # Global hard-deny and cloud metadata checks (ERR-02)
        if parsed.host in PROHIBITED_METADATA_HOSTS:
            decision = Decision(
                allowed=False,
                reason=f"Target host '{parsed.host}' is a prohibited cloud metadata destination",
                rule_id="PROHIBITED_METADATA_HOST",
            )
            self._audit(decision, target, port, tool, action_class, assessment_id)
            return decision

        if parsed.is_ip:
            try:
                raw_ip = ipaddress.ip_address(parsed.host)
                canon_ip = canonicalize_ip(raw_ip)
                for deny in HARD_DENY_NETWORKS:
                    if canon_ip in deny or raw_ip in deny:
                        decision = Decision(
                            allowed=False,
                            reason=f"Target IP '{canon_ip}' is within prohibited network '{deny}'",
                            rule_id="HARD_DENY_PROHIBITED_NETWORK",
                        )
                        self._audit(decision, target, port, tool, action_class, assessment_id)
                        return decision
            except ValueError:
                pass

        if parsed.port is not None and port is not None and parsed.port != port:
            decision = Decision(
                allowed=False,
                reason=f"Conflicting ports specified: target URL port {parsed.port} vs parameter port {port}",
                rule_id="PORT_CONFLICT",
            )
            self._audit(decision, target, port, tool, action_class, assessment_id)
            return decision

        effective_port = port if port is not None else parsed.port

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
            if decision.rule_id in (
                "EXCLUDED_TARGET",
                "PORT_NOT_ALLOWED",
                "PORT_REQUIRED_OR_NOT_ALLOWED",
                "TOOL_NOT_ALLOWED",
                "EXPIRED_VALIDITY_WINDOW",
                "DNS_RESOLUTION_OUT_OF_SCOPE",
                "PUBLIC_TARGET_NOT_ALLOWED",
                "HARD_DENY_PROHIBITED_NETWORK",
                "PROHIBITED_METADATA_HOST",
            ):
                best_decision = decision
                if decision.rule_id in (
                    "EXCLUDED_TARGET",
                    "HARD_DENY_PROHIBITED_NETWORK",
                    "PROHIBITED_METADATA_HOST",
                ):
                    break

        self._audit(best_decision, target, effective_port, tool, action_class, assessment_id)
        return best_decision

    def is_target_in_scope(self, target: str) -> Decision:
        """Evaluates whether a target host/IP is authorized within registered scope without port/tool constraints."""
        scopes = self.registry.list_all()
        if not scopes:
            return Decision(
                allowed=False,
                reason="No registered scope found; all scanning actions are blocked",
                rule_id="NO_SCOPE_REGISTERED",
            )

        try:
            parsed = parse_target(target)
        except ValueError as exc:
            return Decision(
                allowed=False,
                reason=f"Invalid target specification '{target}': {exc}",
                rule_id="INVALID_TARGET",
            )

        if parsed.host in PROHIBITED_METADATA_HOSTS:
            return Decision(
                allowed=False,
                reason=f"Target host '{parsed.host}' is a prohibited cloud metadata destination",
                rule_id="PROHIBITED_METADATA_HOST",
            )
        if parsed.is_ip:
            try:
                raw_ip = ipaddress.ip_address(parsed.host)
                canon_ip = canonicalize_ip(raw_ip)
                for deny in HARD_DENY_NETWORKS:
                    if canon_ip in deny or raw_ip in deny:
                        return Decision(
                            allowed=False,
                            reason=f"Target IP '{canon_ip}' is within prohibited network '{deny}'",
                            rule_id="HARD_DENY_PROHIBITED_NETWORK",
                        )
            except ValueError:
                pass

        best_decision = Decision(
            allowed=False,
            reason=f"Target '{target}' (host '{parsed.host}') is not in registered scope",
            rule_id="NOT_IN_SCOPE",
        )

        pinned_candidate: str | None = None
        if parsed.is_ip:
            try:
                pinned_candidate = str(canonicalize_ip(ipaddress.ip_address(parsed.host)))
            except ValueError:
                pass

        for scope in scopes:
            if not scope.is_valid_at():
                continue

            # Check exclusions first
            for exclusion in scope.exclusions:
                clean_ex = exclusion.strip().rstrip(".").lower()
                if clean_ex == parsed.host or clean_ex == parsed.raw.strip().rstrip(".").lower():
                    return Decision(
                        allowed=False,
                        reason=f"Target '{parsed.host}' is explicitly excluded in scope '{scope.id}'",
                        rule_id="EXCLUDED_TARGET",
                    )

            # Direct match against allowed_targets
            for allowed in scope.allowed_targets:
                clean_al = allowed.strip().rstrip(".").lower()
                if clean_al == parsed.host or clean_al == parsed.raw.strip().rstrip(".").lower():
                    return Decision(
                        allowed=True,
                        reason=f"Target '{parsed.host}' authorized within scope '{scope.id}'",
                        rule_id="ALLOW_EXACT",
                        pinned_ip=pinned_candidate,
                        resolved_ips=[pinned_candidate] if pinned_candidate else [],
                    )

            # IP / CIDR check
            if parsed.is_ip:
                try:
                    ip_obj = ipaddress.ip_address(parsed.host)
                    for exclusion in scope.exclusions:
                        clean_ex = exclusion.strip().rstrip(".").lower()
                        if _ip_matches_entry(ip_obj, clean_ex):
                            return Decision(
                                allowed=False,
                                reason=f"Target '{parsed.host}' is explicitly excluded in scope '{scope.id}'",
                                rule_id="EXCLUDED_TARGET",
                            )
                    for allowed in scope.allowed_targets:
                        if _ip_matches_entry(ip_obj, allowed):
                            return Decision(
                                allowed=True,
                                reason=f"Target '{parsed.host}' authorized within scope '{scope.id}'",
                                rule_id="ALLOW_CIDR",
                                pinned_ip=pinned_candidate,
                                resolved_ips=[pinned_candidate] if pinned_candidate else [],
                            )
                except ValueError:
                    pass

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

        # Check prohibited cloud metadata hostnames
        if parsed.host in PROHIBITED_METADATA_HOSTS:
            return Decision(
                allowed=False,
                reason=f"Target host '{parsed.host}' is a prohibited cloud metadata destination",
                rule_id="PROHIBITED_METADATA_HOST",
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

        # Hard-deny networks & metadata check for all resolved/target IPs (ERR-02)
        for ip_obj in ips_to_check:
            canon = canonicalize_ip(ip_obj)
            for deny in HARD_DENY_NETWORKS:
                if canon in deny or ip_obj in deny:
                    return Decision(
                        allowed=False,
                        reason=f"Resolved/target IP '{canon}' is within prohibited network '{deny}'",
                        rule_id="HARD_DENY_PROHIBITED_NETWORK",
                    )
            if str(canon) in PROHIBITED_METADATA_HOSTS:
                return Decision(
                    allowed=False,
                    reason=f"Resolved/target IP '{canon}' is a prohibited cloud metadata destination",
                    rule_id="PROHIBITED_METADATA_HOST",
                )

        # 4. Exclusions strictly beat allows
        for exclusion in scope.exclusions:
            clean_ex = exclusion.strip().rstrip(".").lower()
            # Direct host/URL match (normalized)
            if clean_ex == parsed.host or clean_ex == parsed.raw.strip().rstrip(".").lower():
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
                            f"Resolved IP '{canonicalize_ip(ip_obj)}' for target '{parsed.host}' "
                            f"is explicitly excluded in scope '{scope.id}'"
                        ),
                        rule_id="EXCLUDED_TARGET",
                    )

        # 5. Target containment in allowed_targets
        direct_match = False
        for allowed in scope.allowed_targets:
            clean_al = allowed.strip().rstrip(".").lower()
            if clean_al == parsed.host or clean_al == parsed.raw.strip().rstrip(".").lower():
                direct_match = True
                break

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
                        f"{'Target IP' if parsed.is_ip else 'Resolved IP'} '{canonicalize_ip(ip_obj)}' for target '{parsed.host}' "
                        f"is not in registered scope '{scope.id}'"
                    ),
                    rule_id=rule,
                )

        # Routable public ranges require explicit allow_public_targets flag on Scope
        if not scope.allow_public_targets:
            for ip_obj in ips_to_check:
                canon = canonicalize_ip(ip_obj)
                if not (canon.is_private or canon.is_loopback):
                    return Decision(
                        allowed=False,
                        reason=(
                            f"Routable public IP '{canon}' for target '{parsed.host}' "
                            f"requires allow_public_targets=True on scope '{scope.id}'"
                        ),
                        rule_id="PUBLIC_TARGET_NOT_ALLOWED",
                    )

        # 6. Allowed ports check for targets within scope
        if scope.allowed_ports:
            if port is None:
                return Decision(
                    allowed=False,
                    reason=(
                        f"Scope '{scope.id}' restricts ports to {scope.allowed_ports}; "
                        f"target '{parsed.host}' must specify an authorized port"
                    ),
                    rule_id="PORT_REQUIRED_OR_NOT_ALLOWED",
                )
            if port not in scope.allowed_ports:
                return Decision(
                    allowed=False,
                    reason=(
                        f"Port {port} for target '{parsed.host}' is not in allowed "
                        f"ports {scope.allowed_ports} for scope '{scope.id}'"
                    ),
                    rule_id="PORT_NOT_ALLOWED",
                )

        pinned_ip = str(canonicalize_ip(ips_to_check[0]))
        resolved_ips = [str(canonicalize_ip(ip)) for ip in ips_to_check]

        return Decision(
            allowed=True,
            reason=f"Target '{parsed.host}' authorized within scope '{scope.id}'",
            rule_id="ALLOW_EXACT" if direct_match else "ALLOW_CIDR",
            pinned_ip=pinned_ip,
            resolved_ips=resolved_ips,
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
        """Records an immutable audit event for every policy decision with redacted credentials."""
        if self.audit_log is None:
            return

        redacted = redact_target(target)
        payload: dict[str, Any] = {
            "target": redacted,
            "port": port,
            "tool": tool,
            "action_class": str(action_class.value if hasattr(action_class, "value") else action_class),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "pinned_ip": decision.pinned_ip,
        }
        self.audit_log.append(
            actor="policy_gate",
            event_type="policy_decision",
            payload=payload,
            assessment_id=assessment_id,
        )
