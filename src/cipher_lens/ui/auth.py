"""Authentication registry, default test credentials, and role bindings (Task A11 / ERR-01).

Loads predefined test users from config/users.yaml so that entering recognized names
(e.g., Harimohan -> Lead Analyst, Bhavyaa -> Operator, Yash -> Auditor) automatically
determines the role and validates passwords using constant-time comparisons.
"""

from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

import yaml

from cipher_lens.config import get_settings

DEFAULT_USERS_PATH = Path("config/users.yaml")

# Fallback in-memory defaults matching user requirements
FALLBACK_USERS = [
    {
        "username": "Harimohan",
        "role": "lead_analyst",
        "display_role": "Lead Security Analyst",
        "password": "leadanalyst123",
    },
    {
        "username": "Bhavyaa",
        "role": "operator",
        "display_role": "Operator / Pen-Tester",
        "password": "operator123",
    },
    {
        "username": "Yash",
        "role": "auditor",
        "display_role": "Security Auditor",
        "password": "auditor123",
    },
]


def load_user_registry(path: Path | None = None) -> dict[str, dict[str, str]]:
    """Loads users from YAML configuration file, keyed by case-insensitive username."""
    config_file = path or DEFAULT_USERS_PATH
    users_list: list[dict[str, Any]] = []

    if config_file.exists():
        try:
            content = config_file.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "users" in data and isinstance(data["users"], list):
                users_list = data["users"]
        except Exception:
            users_list = []

    if not users_list:
        users_list = FALLBACK_USERS

    registry: dict[str, dict[str, str]] = {}
    for entry in users_list:
        uname = str(entry.get("username", "")).strip()
        if not uname:
            continue
        role = str(entry.get("role", "operator")).strip().lower()
        disp_role = str(entry.get("display_role", role.replace("_", " ").title())).strip()
        pwd = str(entry.get("password", "")).strip()
        registry[uname.lower()] = {
            "username": uname,
            "role": role,
            "display_role": disp_role,
            "password": pwd,
        }

    return registry


def get_user_by_name(username: str, path: Path | None = None) -> dict[str, str] | None:
    """Returns the registered user configuration by name (case-insensitive), or None."""
    registry = load_user_registry(path)
    return registry.get(username.strip().lower())


def verify_user_credentials(
    username: str,
    provided_password: str,
    selected_role: str | None = None,
    path: Path | None = None,
    settings: Any | None = None,
) -> tuple[dict[str, str] | None, str | None]:
    """Verifies credentials against config/users.yaml or fallback environment tokens.

    Returns:
        (user_dict, None) on success
        (None, error_message) on failure
    """
    clean_name = username.strip()
    if not clean_name:
        return None, "Username cannot be empty."

    registered = get_user_by_name(clean_name, path)
    active_settings = settings or get_settings()

    if registered:
        # Predefined/configured user: enforce their configured role and password
        expected_pwd = registered["password"]
        if expected_pwd:
            if not provided_password:
                return None, f"Password is required for user '{registered['username']}'."
            if not hmac.compare_digest(provided_password.encode("utf-8"), expected_pwd.encode("utf-8")):
                return None, "Invalid security token."
        return {
            "username": registered["username"],
            "role": registered["role"],
        }, None

    # Custom user not in config/users.yaml: fallback to environment token check if configured
    role = selected_role or "operator"
    required_token = None
    if role == "lead_analyst":
        required_token = active_settings.admin_token
    elif role == "operator":
        required_token = active_settings.operator_token or active_settings.admin_token
    elif role == "auditor":
        required_token = active_settings.auditor_token or active_settings.admin_token

    if required_token:
        if not provided_password:
            return None, f"Security token is required for role '{role}'."
        if not hmac.compare_digest(provided_password.encode("utf-8"), required_token.encode("utf-8")):
            return None, "Invalid security token."

    return {
        "username": clean_name,
        "role": role,
    }, None
