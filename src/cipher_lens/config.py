"""Configuration settings for Cipher-Lens.

Defines a unified Pydantic Settings class loading from environment variables
and optional .env file, providing validated settings for LLM, scanners,
enrichment, storage, and operational security flags.
"""

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Unified configuration for Cipher-Lens."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM Settings
    llm_provider: Literal["gemini", "none", "offline"] = Field(
        default="gemini",
        validation_alias=AliasChoices("LLM_PROVIDER", "CIPHER_LENS_LLM_PROVIDER"),
    )
    gemini_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GEMINI_API_KEY",
            "GEMINI_API_KEY_PRIMARY",
            "CIPHER_LENS_GEMINI_API_KEY",
        ),
    )
    gemini_api_key_secondary: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GEMINI_API_KEY_SECONDARY",
            "CIPHER_LENS_GEMINI_API_KEY_SECONDARY",
        ),
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        validation_alias=AliasChoices(
            "GEMINI_MODEL",
            "GEMINI_MODEL_PRIMARY",
            "CIPHER_LENS_GEMINI_MODEL",
            "CIPHER_LENS_PRIMARY_MODEL",
        ),
    )
    gemini_model_secondary: str = Field(
        default="gemini-2.0-flash",
        validation_alias=AliasChoices(
            "GEMINI_MODEL_SECONDARY",
            "CIPHER_LENS_GEMINI_MODEL_SECONDARY",
            "CIPHER_LENS_FALLBACK_MODEL",
        ),
    )
    llm_call_budget: int = Field(
        default=30,
        validation_alias=AliasChoices("LLM_CALL_BUDGET", "CIPHER_LENS_LLM_CALL_BUDGET"),
    )
    llm_max_output_tokens: int = Field(
        default=2048,
        validation_alias=AliasChoices("LLM_MAX_OUTPUT_TOKENS", "CIPHER_LENS_LLM_MAX_OUTPUT_TOKENS"),
    )
    llm_cache_dir: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_CACHE_DIR", "CIPHER_LENS_LLM_CACHE_DIR"),
    )

    # Scanners and Threat Intel APIs
    zap_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("ZAP_API_KEY", "CIPHER_LENS_ZAP_API_KEY"),
    )
    zap_url: str = Field(
        default="http://localhost:8080",
        validation_alias=AliasChoices("ZAP_URL", "CIPHER_LENS_ZAP_URL"),
    )
    nvd_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("NVD_API_KEY", "CIPHER_LENS_NVD_API_KEY"),
    )

    # Local Storage and Cryptography
    db_path: str = Field(
        default="local_data/cipher_lens.db",
        validation_alias=AliasChoices("DB_PATH", "CIPHER_LENS_DB", "CIPHER_LENS_DB_PATH"),
    )
    raw_dir: str = Field(
        default="local_data/artifacts",
        validation_alias=AliasChoices("RAW_DIR", "CIPHER_LENS_ARTIFACTS", "CIPHER_LENS_RAW_DIR"),
    )
    fernet_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("FERNET_KEY", "CIPHER_LENS_FERNET_KEY"),
    )

    # Operational & Safety Flags
    offline_mode: bool = Field(
        default=False,
        validation_alias=AliasChoices("OFFLINE_MODE", "CIPHER_LENS_OFFLINE_MODE"),
    )
    enable_chaos: bool = Field(
        default=False,
        validation_alias=AliasChoices("ENABLE_CHAOS", "CIPHER_LENS_ENABLE_CHAOS"),
    )
    allow_self_approval: bool = Field(
        default=False,
        validation_alias=AliasChoices("ALLOW_SELF_APPROVAL", "CIPHER_LENS_ALLOW_SELF_APPROVAL"),
    )

    # Authentication Tokens
    admin_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ADMIN_TOKEN", "CIPHER_LENS_ADMIN_TOKEN"),
    )
    operator_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OPERATOR_TOKEN", "CIPHER_LENS_OPERATOR_TOKEN"),
    )
    auditor_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("AUDITOR_TOKEN", "CIPHER_LENS_AUDITOR_TOKEN"),
    )

    @field_validator("llm_provider", mode="before")
    @classmethod
    def validate_llm_provider(cls, v: object) -> str:
        val = str(v).lower().strip()
        if val == "mock":
            # DECISION: Disallow setting provider to 'mock' via environment configuration.
            # Mock provider is constructor-only in LlmClient to prevent test leakage in production.
            raise ValueError(
                "LLM_PROVIDER cannot be set to 'mock' in environment configuration. "
                "The mock provider is constructor-only in LlmClient for test isolation."
            )
        if val not in ("gemini", "none", "offline"):
            raise ValueError(
                f"Invalid LLM_PROVIDER '{v}'. Must be one of: 'gemini', 'none', 'offline'."
            )
        return val


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
