"""Application configuration.

All configuration is environment-driven. Nothing in this module may contain a
default that is a real credential, hostname, or IP address belonging to the
target environment. Defaults exist only to make the application importable and
testable; a deployment must supply real values via the environment or `.env`.

Secrets are typed as :class:`pydantic.SecretStr` so that they are redacted by
default in reprs, tracebacks, and structured log payloads.
"""

from __future__ import annotations

import json
from enum import StrEnum
from functools import lru_cache
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment. Controls a small number of secure defaults."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class ApiKeyPrincipalConfig(BaseModel):
    """A single statically configured API-key credential.

    This is the Milestone 1 authentication mechanism only. The fields here are
    deliberately mapped onto the provider-neutral Principal model
    (``subject``/``display_name``/``roles``), so replacing this backend with
    OIDC later changes nothing downstream of :mod:`acop.auth.principal`.

    ``secret`` is compared using a constant-time comparison. Storing the plain
    secret in the environment is acceptable for Milestone 1 and is explicitly
    revisited when a secrets manager is introduced (see
    ``docs/security/secrets.md``).
    """

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description=(
            "Stable, opaque identifier for the acting party. Must remain stable "
            "across authentication backends: if this principal later "
            "authenticates via OIDC, the OIDC subject claim should be mapped to "
            "this same value so historical audit records stay attributable."
        ),
    )
    secret: SecretStr = Field(..., description="Shared secret presented as the API key.")
    display_name: str = Field(default="", max_length=255)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    principal_type: Literal["human", "service", "agent"] = "human"


class Settings(BaseSettings):
    """Root application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ACOP_",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "CyberWithSteve ACOP"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False

    api_host: str = "0.0.0.0"  # noqa: S104 - bound inside a container network
    api_port: int = 8000
    api_root_path: str = ""
    """Set when ACOP is served behind a reverse proxy at a sub-path."""

    docs_enabled: bool = True
    """Swagger/OpenAPI UI. Milestone 1 uses this as the primary interface."""

    cors_allow_origins: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "acop"
    postgres_password: SecretStr = SecretStr("")
    postgres_db: str = "acop"

    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_pre_ping: bool = True
    db_echo: bool = False
    db_connect_timeout_seconds: float = 5.0

    # ------------------------------------------------------------------
    # Ollama / local inference
    # ------------------------------------------------------------------
    ollama_base_url: str = "http://127.0.0.1:11434"
    """Base URL of the Ollama API. In this deployment Ollama runs on a separate
    GPU host, so this is a network address, not a container link."""

    ollama_model: str = "qwen3:32b"
    """Primary reasoning model tag, exactly as reported by ``ollama list``."""

    ollama_control_timeout_seconds: float = 5.0
    """Timeout for cheap control-plane calls (version, tag listing, health)."""

    ollama_generate_timeout_seconds: float = 300.0
    """Timeout for inference calls. Deliberately separate from the control-plane
    timeout so a slow generation can never make health checks appear to hang."""

    ollama_num_ctx: int = 8192
    """Context window requested per call.

    Ollama silently truncates to its own default (historically 4096) when this
    is not set explicitly, which would quietly discard retrieved evidence in
    later milestones. It is therefore set explicitly from Milestone 1.
    """

    ollama_keep_alive: str = "10m"

    # ------------------------------------------------------------------
    # Knowledge (Milestone 3)
    # ------------------------------------------------------------------
    knowledge_embedding_base_url: str = "http://127.0.0.1:11434"
    """Embedding provider endpoint. **Separate from ``ollama_base_url`` on
    purpose**: the reasoning model and the embedding model are different models
    with different resource profiles and may well live on different hosts.
    Collapsing them would make moving either one a change to every deployment's
    configuration shape rather than to one value."""

    knowledge_embedding_model: str = "embeddinggemma:latest"
    knowledge_embedding_dimensions: int = 768
    knowledge_embedding_timeout_seconds: float = 120.0
    knowledge_embedding_normalize: bool = True

    knowledge_fingerprint_salt: SecretStr = SecretStr("")
    """HMAC key for secret-finding fingerprints.

    Salted so the findings table cannot become an offline-crackable dictionary
    of the estate's secrets. Required outside development: a shipped default
    salt would give the appearance of protection with none of the substance,
    so the validator below refuses to start without a real one."""

    knowledge_retrieval_k: int = 10
    knowledge_ann_overfetch: int = 8
    knowledge_ann_candidate_cap: int = 2000
    knowledge_hnsw_ef_search: int = 100
    knowledge_hnsw_iterative_scan: str | None = None
    """pgvector 0.8+ only. Applied when the running server has the setting and
    ignored when it does not, so one configuration spans 0.6 in development and
    0.8.6 in production."""

    knowledge_exact_fallback_enabled: bool = True
    knowledge_exact_max_rows: int = 50_000
    knowledge_exact_timeout_ms: int = 5_000
    knowledge_lexical_limit: int = 100

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    health_cache_ttl_seconds: float = 10.0
    """Dependency probe results are cached this long so that a monitoring
    scrape interval cannot turn the health endpoint into a load generator."""

    # ------------------------------------------------------------------
    # Authentication (Milestone 1: static API keys)
    # ------------------------------------------------------------------
    auth_enabled: bool = True
    api_keys: list[ApiKeyPrincipalConfig] = Field(default_factory=list)
    """JSON array in ``ACOP_API_KEYS``. See ``.env.example``."""

    api_key_header: str = "X-ACOP-API-Key"

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @field_validator("api_keys", "cors_allow_origins", mode="before")
    @classmethod
    def _parse_json_list(cls, value: Any) -> Any:
        """Allow list-valued settings to be supplied as a JSON string."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                # Fall back to comma-separated form for simple scalar lists.
                return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator("ollama_base_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("api_keys")
    @classmethod
    def _require_keys_when_auth_enabled(
        cls, value: list[ApiKeyPrincipalConfig], info: ValidationInfo
    ) -> list[ApiKeyPrincipalConfig]:
        auth_enabled = info.data.get("auth_enabled", True)
        environment = info.data.get("environment", Environment.DEVELOPMENT)
        if (
            auth_enabled
            and not value
            and environment
            in (
                Environment.STAGING,
                Environment.PRODUCTION,
            )
        ):
            raise ValueError(
                "ACOP_API_KEYS must define at least one credential when "
                "authentication is enabled outside development/test."
            )
        subjects = [item.subject for item in value]
        duplicates = {s for s in subjects if subjects.count(s) > 1}
        if duplicates:
            raise ValueError(
                f"Duplicate API key subjects configured: {sorted(duplicates)}"
            )
        return value

    @field_validator("knowledge_fingerprint_salt")
    @classmethod
    def _require_fingerprint_salt(
        cls, value: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        """Refuse to run outside development without a real salt.

        An empty or shipped salt makes every deployment's fingerprints
        identical and precomputable, which turns the findings table from a
        redacted record into a lookup table for the estate's secrets. Failing
        at startup is the only honest response.
        """
        environment = info.data.get("environment", Environment.DEVELOPMENT)
        if not value.get_secret_value() and environment in (
            Environment.STAGING,
            Environment.PRODUCTION,
        ):
            raise ValueError(
                "ACOP_KNOWLEDGE_FINGERPRINT_SALT must be set outside "
                "development. Generate one with `openssl rand -hex 32`."
            )
        return value

    @field_validator("debug")
    @classmethod
    def _no_debug_in_production(cls, value: bool, info: ValidationInfo) -> bool:
        if value and info.data.get("environment") == Environment.PRODUCTION:
            raise ValueError("debug must be disabled in production")
        return value

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy URL used by the application."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:"
            f"{self.postgres_password.get_secret_value()}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Synchronous URL. Used only by tooling that cannot run async."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:"
            f"{self.postgres_password.get_secret_value()}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def safe_database_target(self) -> str:
        """Credential-free description of the database target, safe to log."""
        return f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so that configuration is parsed and validated exactly once. Tests
    clear the cache via ``get_settings.cache_clear()``.
    """
    return Settings()
