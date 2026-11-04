"""Global pytest fixtures and environment pinning for Cipher-Lens test suite."""

from collections.abc import Generator

import pytest

from cipher_lens.config import get_settings


@pytest.fixture(autouse=True)
def pin_test_environment(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Pin environment variables across all tests to prevent leakage from host environment."""
    # Ensure offline mode tokens and defaults are pinned for test reproducibility
    monkeypatch.setenv("CIPHER_LENS_ADMIN_TOKEN", "test-admin-secret-token-123456")
    monkeypatch.setenv("CIPHER_LENS_AUDITOR_TOKEN", "test-auditor-secret-token-123456")
    monkeypatch.setenv("ALLOW_SELF_APPROVAL", "true")

    # Clear cached settings so monkeypatched env is observed
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
