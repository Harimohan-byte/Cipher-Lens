"""Integration Tests for Streamlit UI Workflow (Task A12 Streamlit Testing).

Validates end-to-end rendering and state flow across the 6 dashboard pages using
streamlit.testing.v1.AppTest:
- Auth barrier login with role and security token
- Page 1: Scope Boundary Registration
- Page 2: Natural Language Intake & Conversational Dialogue
- Page 3: Plan Approvals & Execution
- Page 4: Findings & Risk Prioritization
- Page 5: Tamper-Evident Audit Log & LLM Traces
- Page 6: Executive PDF Report Generation
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).parent.parent.parent / "src" / "cipher_lens" / "ui" / "app.py")


def test_streamlit_auth_barrier_rendering() -> None:
    """Verifies that unauthenticated user sees the authentication barrier."""
    at = AppTest.from_file(APP_PATH)
    at.run()

    # Must render access control barrier without uncaught errors
    assert not at.exception
    assert any("Cipher-Lens Access Control" in str(t.value) for t in at.title)


def test_streamlit_six_page_navigation_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Smoke tests all 6 pages of the Streamlit application for clean rendering without crash."""
    db_file = str(tmp_path / "app_smoke.db")
    art_dir = str(tmp_path / "app_artifacts")

    monkeypatch.setenv("CIPHER_LENS_DB", db_file)
    monkeypatch.setenv("CIPHER_LENS_ARTIFACTS", art_dir)
    monkeypatch.setenv("LLM_PROVIDER", "offline")
    monkeypatch.setenv("CIPHER_LENS_ADMIN_TOKEN", "test-admin-secret-token-123456")

    pages = [
        "1. Scope Boundary",
        "2. Natural Intake & Plan",
        "3. Plan Approvals & Execution",
        "4. Findings & Risk Prioritization",
        "5. Audit Log & LLM Traces",
        "6. Executive PDF Report",
    ]

    for target_page in pages:
        at = AppTest.from_file(APP_PATH)
        at.run()

        # Pre-authenticate as lead analyst
        at.session_state["authenticated_user"] = {
            "username": "lead_analyst_test",
            "role": "lead_analyst",
        }
        at.session_state["main_navigation_radio"] = target_page
        at.run()

        assert not at.exception, f"Rendering page '{target_page}' raised an uncaught exception: {at.exception}"
