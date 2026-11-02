"""Tests for PolicyGate and Scope authorization safety checks."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.gate import PolicyGate, parse_target
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    """Fixture providing initialized database connection."""
    conn = connect(tmp_path / "test_policy.db")
    init_db(conn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def audit_log(db_conn: sqlite3.Connection) -> AuditLog:
    """Fixture providing an AuditLog instance."""
    return AuditLog(db_conn)


@pytest.fixture
def sample_scope() -> Scope:
    """Standard authorized lab scope fixture."""
    now = datetime.now(UTC)
    return Scope(
        id="scope-lab-01",
        owner="Security Team",
        authorization_reference="AUTH-LAB-2026-001",
        allowed_targets=[
            "192.168.1.10",
            "192.168.1.0/24",
            "10.0.0.0/28",
            "app.local",
            "2001:db8:abcd::/48",
            "http://intranet.local:8080/portal",
        ],
        exclusions=[
            "192.168.1.1",  # Gateway inside 192.168.1.0/24
            "192.168.1.254",
            "excluded.app.local",
            "2001:db8:abcd::1",
        ],
        allowed_ports=[80, 443, 8080, 8443],
        tool_allowlist=["nmap", "nikto", "zap"],
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=1),
        rate_limit=10,
        asset_tags={"criticality": "high", "exposure": "internal"},
    )


@pytest.fixture
def mock_resolver():
    """Mock DNS resolver mapping hostnames to IPs without external network access."""
    dns_table = {
        "app.local": ["192.168.1.10"],
        "multi.local": ["192.168.1.10", "192.168.1.20"],
        "mixed.local": ["192.168.1.10", "8.8.8.8"],  # One in-scope, one out-of-scope
        "evil.com": ["93.184.216.34"],
        "excluded.app.local": ["192.168.1.15"],
        "ipv6.local": ["2001:db8:abcd::100"],
    }

    def _resolve(host: str) -> list[str]:
        if host in dns_table:
            return dns_table[host]
        raise ValueError(f"NXDOMAIN: {host}")

    return _resolve


@pytest.fixture
def policy_gate(sample_scope: Scope, audit_log: AuditLog, mock_resolver) -> PolicyGate:
    """Fixture providing PolicyGate configured with scope and mock DNS."""
    registry = ScopeRegistry()
    registry.register(sample_scope)
    return PolicyGate(registry=registry, audit_log=audit_log, resolver=mock_resolver)


def test_target_parsing_and_sanitization():
    """Test target parsing strips scheme, path, query, userinfo, and extracts port."""
    parsed = parse_target("http://192.168.1.10:8080/test?foo=bar#hash")
    assert parsed.host == "192.168.1.10"
    assert parsed.port == 8080

    parsed_bare = parse_target("192.168.1.10")
    assert parsed_bare.host == "192.168.1.10"
    assert parsed_bare.port is None

    # Userinfo trick attempt
    parsed_userinfo = parse_target("http://10.0.0.5@evil.com/path")
    assert parsed_userinfo.host == "evil.com"


def test_exact_match_allowed(policy_gate: PolicyGate):
    """Test 1: Exact match on allowed host and IP is permitted."""
    dec = policy_gate.authorize(
        target="192.168.1.10",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is True
    assert dec.rule_id == "ALLOW_EXACT"


def test_cidr_boundary_containment(policy_gate: PolicyGate):
    """Test 2: CIDR edges (network, first, last, broadcast, out of range)."""
    # 10.0.0.0/28 covers 10.0.0.0 to 10.0.0.15
    for ip in ["10.0.0.0", "10.0.0.1", "10.0.0.14", "10.0.0.15"]:
        dec = policy_gate.authorize(
            target=ip,
            port=443,
            tool="nmap",
            action_class=ActionClass.DISCOVERY,
        )
        assert dec.allowed is True
        assert dec.rule_id == "ALLOW_CIDR"

    # 10.0.0.16 is immediately outside 10.0.0.0/28
    dec_outside = policy_gate.authorize(
        target="10.0.0.16",
        port=443,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_outside.allowed is False


def test_exclusion_precedence(policy_gate: PolicyGate):
    """Test 3: Exclusions strictly beat allows, even if inside an allowed CIDR."""
    # 192.168.1.1 is inside allowed 192.168.1.0/24 but explicitly excluded
    dec = policy_gate.authorize(
        target="192.168.1.1",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert dec.rule_id == "EXCLUDED_TARGET"
    assert "explicitly excluded" in dec.reason


def test_unregistered_target_refused(policy_gate: PolicyGate):
    """Test 4: Unregistered target outside scope is refused."""
    dec = policy_gate.authorize(
        target="172.16.50.4",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert dec.rule_id == "NOT_IN_SCOPE"


def test_dns_multi_ip_and_out_of_scope_rejection(policy_gate: PolicyGate):
    """Test 5: Hostname where one resolved IP is out-of-scope must be completely refused."""
    # multi.local resolves to [192.168.1.10, 192.168.1.20] (both in 192.168.1.0/24) -> allowed
    dec_ok = policy_gate.authorize(
        target="multi.local",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_ok.allowed is True

    # mixed.local resolves to [192.168.1.10, 8.8.8.8] -> MUST be refused
    dec_mixed = policy_gate.authorize(
        target="mixed.local",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_mixed.allowed is False
    assert "8.8.8.8" in dec_mixed.reason


def test_userinfo_trick_rejected(policy_gate: PolicyGate):
    """Test 6: Userinfo trick http://10.0.0.5@evil.com/ is evaluated as evil.com and rejected."""
    dec = policy_gate.authorize(
        target="http://10.0.0.5@evil.com/",
        port=80,
        tool="zap",
        action_class=ActionClass.SCAN,
    )
    assert dec.allowed is False
    assert "evil.com" in dec.reason or "NOT_IN_SCOPE" in dec.rule_id


def test_ipv6_scope_and_exclusions(policy_gate: PolicyGate):
    """Test 7: IPv6 target inside 2001:db8:abcd::/48 is allowed; excluded IPv6 is blocked."""
    dec_allowed = policy_gate.authorize(
        target="2001:db8:abcd::100",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_allowed.allowed is True

    # 2001:db8:abcd::1 is explicitly excluded
    dec_excluded = policy_gate.authorize(
        target="2001:db8:abcd::1",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_excluded.allowed is False
    assert dec_excluded.rule_id == "EXCLUDED_TARGET"


def test_disallowed_port_rejected(policy_gate: PolicyGate):
    """Test 8: Ports not in scope.allowed_ports are refused."""
    dec_blocked = policy_gate.authorize(
        target="192.168.1.10",
        port=22,  # SSH port not in [80, 443, 8080, 8443]
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec_blocked.allowed is False
    assert "Port 22" in dec_blocked.reason


def test_expired_validity_window(sample_scope: Scope, audit_log: AuditLog, mock_resolver):
    """Test 9: Assessment request outside the scope validity window is refused."""
    now = datetime.now(UTC)
    expired_scope = sample_scope.model_copy(
        update={
            "valid_from": now - timedelta(days=10),
            "valid_to": now - timedelta(days=2),
        }
    )
    registry = ScopeRegistry()
    registry.register(expired_scope)
    gate = PolicyGate(registry=registry, audit_log=audit_log, resolver=mock_resolver)

    dec = gate.authorize(
        target="192.168.1.10",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert "validity window" in dec.reason.lower()


def test_disabled_tool_rejected(policy_gate: PolicyGate):
    """Test 10: Tools not present in tool_allowlist are refused."""
    dec = policy_gate.authorize(
        target="192.168.1.10",
        port=80,
        tool="sqlmap",  # Not in ["nmap", "nikto", "zap"]
        action_class=ActionClass.SCAN,
    )
    assert dec.allowed is False
    assert "sqlmap" in dec.reason.lower()
    assert dec.rule_id == "TOOL_NOT_ALLOWED"


def test_request_for_8_8_8_8_refused_with_readable_reason(policy_gate: PolicyGate):
    """Test 11: Scanning 8.8.8.8 is refused with a clear human-readable reason."""
    dec = policy_gate.authorize(
        target="8.8.8.8",
        port=53,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert dec.rule_id in ("NOT_IN_SCOPE", "PORT_NOT_ALLOWED")
    assert "8.8.8.8" in dec.reason
    assert "not authorized" in dec.reason.lower() or "not in registered scope" in dec.reason.lower()


def test_every_decision_is_audited(policy_gate: PolicyGate, db_conn: sqlite3.Connection):
    """Test 12: Every authorize call (allowed or refused) writes an audit event."""
    policy_gate.authorize(
        target="192.168.1.10",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    policy_gate.authorize(
        target="8.8.8.8",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )

    cur = db_conn.cursor()
    cur.execute("SELECT actor, event_type, payload FROM audit_log ORDER BY id ASC")
    rows = cur.fetchall()

    assert len(rows) == 2
    for actor, event_type, _ in rows:
        assert actor == "policy_gate"
        assert event_type == "policy_decision"


def test_invalid_port_in_url_audited_as_denied(
    policy_gate: PolicyGate, db_conn: sqlite3.Connection
):
    """CodeRabbit fix 1: Invalid port in URL raises ValueError, caught & audited as denied."""
    dec = policy_gate.authorize(
        target="http://192.168.1.10:99999/",
        port=None,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert dec.rule_id == "INVALID_TARGET"

    cur = db_conn.cursor()
    cur.execute("SELECT actor, event_type, payload FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    assert row[0] == "policy_gate"
    assert row[1] == "policy_decision"
    assert '"allowed":false' in row[2]


def test_schemeless_path_userinfo_parse_order():
    """CodeRabbit fix 2: Path stripped before userinfo so @ in path does not change host."""
    parsed = parse_target("evil.com/a@10.0.0.5")
    assert parsed.host == "evil.com"


def test_trailing_dot_exclusion_bypass_prevented(policy_gate: PolicyGate):
    """CodeRabbit fix 3: Trailing FQDN dot (e.g. excluded.app.local.) cannot bypass exclusions."""
    dec = policy_gate.authorize(
        target="excluded.app.local.",
        port=80,
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
    )
    assert dec.allowed is False
    assert dec.rule_id == "EXCLUDED_TARGET"


def test_allowed_hostname_resolving_out_of_scope_is_rejected(
    sample_scope: Scope, audit_log: AuditLog
):
    """CodeRabbit fix 4: Allowed hostname resolving to out-of-scope IP is strictly rejected."""
    # Poisoned DNS resolver: app.local resolves to public 8.8.8.8
    poisoned_resolver = lambda host: ["8.8.8.8"]  # noqa: E731
    registry = ScopeRegistry()
    registry.register(sample_scope)
    gate = PolicyGate(registry=registry, audit_log=audit_log, resolver=poisoned_resolver)

    dec = gate.authorize(target="app.local", port=80, tool="nmap")
    assert dec.allowed is False
    assert dec.rule_id == "DNS_RESOLUTION_OUT_OF_SCOPE"
    assert "8.8.8.8" in dec.reason


def test_unspecified_port_and_port_conflict(policy_gate: PolicyGate):
    """CodeRabbit fix 5: Port required if scope sets allowed_ports; conflicting ports rejected."""
    # 1. Scope restricts ports to [80, 443, 8080, 8443], but target has no port
    dec_no_port = policy_gate.authorize(
        target="192.168.1.10",
        port=None,
        tool="nmap",
    )
    assert dec_no_port.allowed is False
    assert dec_no_port.rule_id == "PORT_REQUIRED_OR_NOT_ALLOWED"

    # 2. Conflicting ports: URL specifies 8080, argument specifies 443
    dec_conflict = policy_gate.authorize(
        target="http://192.168.1.10:8080/",
        port=443,
        tool="zap",
    )
    assert dec_conflict.allowed is False
    assert dec_conflict.rule_id == "PORT_CONFLICT"


def test_credentials_redacted_in_audit_log(
    policy_gate: PolicyGate, db_conn: sqlite3.Connection
):
    """CodeRabbit fix 6: Credentials in target URL must never leak into audit log."""
    raw_target_with_secret = "http://admin:super_secret_password_123@192.168.1.10:8080/admin"
    dec = policy_gate.authorize(
        target=raw_target_with_secret,
        port=8080,
        tool="zap",
    )
    assert dec.allowed is True

    cur = db_conn.cursor()
    cur.execute("SELECT payload FROM audit_log ORDER BY id DESC LIMIT 1")
    payload = cur.fetchone()[0]

    # Secret password MUST NOT appear anywhere in the audit payload
    assert "super_secret_password_123" not in payload
    assert "<redacted>@" in payload

