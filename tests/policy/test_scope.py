"""Tests for Scope model and ScopeRegistry."""

from datetime import UTC, datetime, timedelta

from cipher_lens.policy.scope import Scope, ScopeRegistry


def test_scope_model_and_validity_window():
    """Test Scope model validation and validity window checks."""
    now = datetime.now(UTC)
    scope = Scope(
        id="test-scope",
        owner="SecOps",
        authorization_reference="AUTH-TEST-001",
        allowed_targets=["10.10.10.0/24"],
        exclusions=["10.10.10.1"],
        allowed_ports=[80, 443],
        tool_allowlist=["nmap"],
        valid_from=now - timedelta(hours=2),
        valid_to=now + timedelta(hours=2),
    )

    assert scope.id == "test-scope"
    assert scope.is_valid_at(now) is True
    assert scope.is_valid_at(now - timedelta(hours=3)) is False
    assert scope.is_valid_at(now + timedelta(hours=3)) is False


def test_scope_registry_operations():
    """Test registering, retrieving, and listing scopes."""
    registry = ScopeRegistry()
    assert len(registry.list_all()) == 0

    now = datetime.now(UTC)
    scope1 = Scope(
        id="s1",
        owner="Alice",
        authorization_reference="AUTH-1",
        valid_from=now,
        valid_to=now + timedelta(days=1),
    )
    scope2 = Scope(
        id="s2",
        owner="Bob",
        authorization_reference="AUTH-2",
        valid_from=now,
        valid_to=now + timedelta(days=1),
    )

    registry.register(scope1)
    registry.register(scope2)

    assert registry.get("s1") == scope1
    assert registry.get("s2") == scope2
    assert registry.get("non-existent") is None
    assert len(registry.list_all()) == 2


def test_scope_validation_rejects_naive_datetime_and_inverted_window():
    """CodeRabbit fix 7: Scope requires timezone-aware datetime and valid_from <= valid_to."""
    import pytest
    from pydantic import ValidationError

    now_aware = datetime.now(UTC)
    now_naive = datetime.now()  # No tzinfo

    # 1. Naive datetime rejected
    with pytest.raises(ValidationError):
        Scope(
            id="bad-tz",
            owner="Alice",
            authorization_reference="AUTH-BAD",
            valid_from=now_naive,
            valid_to=now_aware,
        )

    # 2. Inverted window (valid_from > valid_to) rejected
    with pytest.raises(ValidationError, match="valid_from must not be after valid_to"):
        Scope(
            id="bad-window",
            owner="Alice",
            authorization_reference="AUTH-BAD",
            valid_from=now_aware + timedelta(days=5),
            valid_to=now_aware,
        )


def test_scope_rejects_wildcard_and_broad_cidrs():
    """Break-it test: Broad CIDRs (e.g. /0, /1) are strictly rejected (ERR-02)."""
    import pytest
    from pydantic import ValidationError

    for broad_cidr in ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0"]:
        with pytest.raises(ValidationError, match="is too broad"):
            Scope(
                id="wildcard-scope",
                owner="Adversary",
                authorization_reference="AUTH-FAKE",
                allowed_targets=[broad_cidr],
            )


def test_scope_rejects_cloud_metadata_hard_deny():
    """Break-it test: 169.254/16 and cloud metadata are permanently blocked (ERR-02)."""
    import pytest
    from pydantic import ValidationError

    for blocked in ["169.254.169.254", "169.254.0.0/16", "metadata.google.internal"]:
        with pytest.raises(ValidationError, match="prohibited"):
            Scope(
                id="metadata-scope",
                owner="Attacker",
                authorization_reference="AUTH-FAKE",
                allowed_targets=[blocked],
            )


def test_scope_public_target_requires_explicit_flag():
    """Public routable targets mandate allow_public_targets=True (ERR-02)."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="requires allow_public_targets=True"):
        Scope(
            id="public-scope",
            owner="Operator",
            authorization_reference="AUTH-PUB",
            allowed_targets=["8.8.8.8"],
            allow_public_targets=False,
        )

