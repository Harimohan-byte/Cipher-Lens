"""Tests for UI Session Authentication and Separation of Duties (ERR-01, ERR-20)."""

from unittest.mock import patch

import pytest

from cipher_lens.config import Settings
from cipher_lens.ui.app import get_current_user, render_auth_barrier


def test_get_current_user_unauthenticated():
    """Returns None when no user is authenticated in session state."""
    session_state = {}
    with patch("streamlit.session_state", session_state):
        assert get_current_user() is None


def test_get_current_user_authenticated():
    """Returns user dict when session state has authenticated user."""
    session_state = {"authenticated_user": {"username": "alice", "role": "operator"}}
    with patch("streamlit.session_state", session_state):
        user = get_current_user()
        assert user is not None
        assert user["username"] == "alice"
        assert user["role"] == "operator"


def test_auth_barrier_already_authenticated():
    """Returns True immediately when session state already has authenticated user."""
    session_state = {"authenticated_user": {"username": "bob", "role": "lead_analyst"}}
    with patch("streamlit.session_state", session_state):
        assert render_auth_barrier() is True


def test_auth_barrier_token_validation_with_hmac(monkeypatch: pytest.MonkeyPatch):
    """Verifies that token validation uses constant-time comparison against configured token."""
    session_state = {}
    mock_settings = Settings(
        admin_token="SuperSecretAdminPass123",
        operator_token="OperatorPass456",
        auditor_token="AuditorPass789",
    )

    with patch("streamlit.session_state", session_state), \
         patch("cipher_lens.ui.app.get_settings", return_value=mock_settings), \
         patch("streamlit.form_submit_button", return_value=True), \
         patch("streamlit.text_input", side_effect=["alice", "WrongPass"]), \
         patch("streamlit.selectbox", return_value="operator"), \
         patch("streamlit.error") as mock_error:
        # Calling barrier with wrong token
        result = render_auth_barrier()
        assert result is False
        assert mock_error.called
        assert "Invalid security token" in mock_error.call_args[0][0]
        assert "authenticated_user" not in session_state


def test_auth_barrier_successful_login(monkeypatch: pytest.MonkeyPatch):
    """Successful authentication sets session state and returns True after rerun."""
    session_state = {}
    mock_settings = Settings(admin_token="AdminSecret")

    with patch("streamlit.session_state", session_state), \
         patch("cipher_lens.ui.app.get_settings", return_value=mock_settings), \
         patch("streamlit.form_submit_button", return_value=True), \
         patch("streamlit.text_input", side_effect=["bob", "AdminSecret"]), \
         patch("streamlit.selectbox", return_value="lead_analyst"), \
         patch("streamlit.rerun"):
        render_auth_barrier()
        assert session_state.get("authenticated_user") == {
            "username": "bob",
            "role": "lead_analyst",
        }


def test_auth_predefined_users_auto_role():
    """Verifies that predefined users from config/users.yaml have auto-assigned roles."""
    from cipher_lens.ui.auth import get_user_by_name, verify_user_credentials

    # Test Harimohan -> Lead Analyst
    hari = get_user_by_name("Harimohan")
    assert hari is not None
    assert hari["role"] == "lead_analyst"
    auth_hari, err = verify_user_credentials("Harimohan", "leadanalyst123")
    assert auth_hari == {"username": "Harimohan", "role": "lead_analyst"}
    assert err is None

    # Test Bhavyaa -> Operator
    bhavyaa = get_user_by_name("Bhavyaa")
    assert bhavyaa is not None
    assert bhavyaa["role"] == "operator"
    auth_bhavyaa, err = verify_user_credentials("Bhavyaa", "operator123")
    assert auth_bhavyaa == {"username": "Bhavyaa", "role": "operator"}
    assert err is None

    # Test Yash -> Auditor
    yash = get_user_by_name("Yash")
    assert yash is not None
    assert yash["role"] == "auditor"
    auth_yash, err = verify_user_credentials("Yash", "auditor123")
    assert auth_yash == {"username": "Yash", "role": "auditor"}
    assert err is None

    # Test wrong password rejection
    auth_fail, err_fail = verify_user_credentials("Harimohan", "incorrect_pwd")
    assert auth_fail is None
    assert "Invalid security token" in err_fail

