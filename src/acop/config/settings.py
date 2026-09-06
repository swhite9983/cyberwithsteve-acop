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
import re
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
from sqlalchemy.engine import URL


class Environment(StrEnum):
    """Deployment environment. Controls a small number of secure defaults."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


#: The shape of ``proxmox_instance_id``. Deliberately narrow: the value is
#: concatenated into identifier values such as ``homelab-pve/100``, so a
#: slash, a colon or whitespace in it would make an identifier ambiguous
#: about where the instance ends and the object begins.
_INSTANCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


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
    # Tool framework (Milestone 4)
    # ------------------------------------------------------------------
    tools_allow_self_approval: bool = False
    """Whether a requester may approve their own invocation.

    **Never caller-controlled.** The approval API has no field for it: the
    value is derived server-side from this setting, the tool's own policy, and
    whether the approver's subject equals the requester's. A validator below
    refuses to start production with it enabled, and the database CHECK
    ``approver_subject <> requester_subject OR self_approval IS TRUE`` is the
    third layer behind both.

    It exists at all so a single-operator development environment can exercise
    the approval path end to end without two identities."""

    tools_dispatcher_enabled: bool = True
    """Whether the background dispatcher polls for READY invocations."""

    tools_dispatcher_poll_seconds: float = 1.0
    tools_execution_lease_seconds: float = 120.0
    """How long a worker's claim on an invocation is honoured before the reaper
    treats it as lost. Must exceed the longest declared tool timeout, or a slow
    tool would be reaped while it is still running."""

    tools_reaper_interval_seconds: float = 30.0
    tools_inline_wait_seconds: float = 30.0
    """How long a Class 0/1 request waits for the shared execution path to
    finish before returning 202 and letting the caller poll. The request is
    waiting on the *same* dispatcher a background worker would use; it never
    bypasses it."""

    # ------------------------------------------------------------------
    # Proxmox (Milestone 5)
    #
    # The adapter owns this configuration and is the only code that reads it.
    # Nothing here is ever accepted from a caller: a tool input carrying a
    # host, a URL or a token is refused at *import* by contract rules 9, 10
    # and 11, so the endpoint can only ever come from the environment.
    # ------------------------------------------------------------------
    proxmox_enabled: bool = False
    """Whether the Proxmox adapter may talk to anything.

    Off by default, so an existing deployment is unchanged by this milestone
    and a half-configured one cannot reach a hypervisor by accident."""

    proxmox_instance_id: str = ""
    """The stable, ACOP-owned name for one configured Proxmox connection.

    It scopes every composite Proxmox identifier - ``<instance>/<vmid>`` and
    friends - and it is deliberately **not** derived from anything Proxmox
    reports. The cluster name is the obvious candidate and the wrong one: an
    administrator can rename a cluster, and every identifier built on that
    name would change at once, orphaning every asset under it. Assign this
    once; never change it."""

    proxmox_base_url: str = ""
    """e.g. ``https://pve.example.invalid:8006``. Adapter-owned."""

    proxmox_token_id: str = ""
    """The API token identifier, ``user@realm!tokenname``. Not a secret - it
    names the principal, and hiding it would only obscure a misconfiguration."""

    proxmox_token_secret: SecretStr = SecretStr("")
    """The API token secret. ``SecretStr`` so that a traceback, a ``repr`` or
    a structured log line rendering this object cannot spill it."""

    proxmox_verify_tls: bool = True
    """TLS certificate verification. A home lab with a self-signed cluster
    certificate may turn this off in development; a deployed environment may
    not, and the validator refuses to start if it tries."""

    proxmox_timeout_seconds: float = 15.0
    """Default per-request budget for the adapter's HTTP client."""

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

    @field_validator("tools_allow_self_approval")
    @classmethod
    def _no_self_approval_in_production(cls, value: bool, info: ValidationInfo) -> bool:
        """Refuse to start production with self-approval enabled.

        Separation of duties is the entire control that makes a Class 2 or
        Class 3 approval mean anything. A deployment that quietly enabled this
        would keep producing approval records that look identical to real ones,
        so the failure has to be at startup rather than at approval time.
        """
        if value and info.data.get("environment") in (
            Environment.STAGING,
            Environment.PRODUCTION,
        ):
            raise ValueError(
                "ACOP_TOOLS_ALLOW_SELF_APPROVAL must be false outside "
                "development. Separation of duties is not optional in a "
                "deployed environment."
            )
        return value

    @field_validator("proxmox_instance_id")
    @classmethod
    def _proxmox_instance_id_is_a_stable_slug(
        cls, value: str, info: ValidationInfo
    ) -> str:
        """A malformed instance id would be embedded in every identifier written.

        Checked only when the integration is enabled, so a deployment that
        does not use Proxmox is unaffected.
        """
        if info.data.get("proxmox_enabled") and not _INSTANCE_ID_PATTERN.match(value):
            raise ValueError(
                "ACOP_PROXMOX_INSTANCE_ID must be 1-32 characters of "
                "lowercase letters, digits and hyphens, starting with a "
                "letter or digit (for example 'homelab-pve'). It scopes every "
                "Proxmox identifier and can never be changed afterwards."
            )
        return value

    @field_validator("proxmox_base_url")
    @classmethod
    def _proxmox_base_url_is_https(cls, value: str, info: ValidationInfo) -> str:
        """https, or nothing.

        The API token travels in a request header. Over plain http it travels
        in clear text on the management network, which is the one network on
        which a hypervisor credential must never be readable. There is no
        development exemption because there is no development benefit - a
        self-signed certificate is handled by ``proxmox_verify_tls``, not by
        abandoning transport security.
        """
        value = value.rstrip("/")
        if not info.data.get("proxmox_enabled"):
            return value
        if not value:
            raise ValueError(
                "ACOP_PROXMOX_BASE_URL is required when ACOP_PROXMOX_ENABLED is true."
            )
        if not value.startswith("https://"):
            raise ValueError(
                "ACOP_PROXMOX_BASE_URL must use https. The API token is sent "
                "as a request header and http would put it on the wire in "
                "clear text; use ACOP_PROXMOX_VERIFY_TLS for a self-signed "
                "certificate instead."
            )
        return value

    @field_validator("proxmox_token_id")
    @classmethod
    def _proxmox_token_id_required_when_enabled(
        cls, value: str, info: ValidationInfo
    ) -> str:
        if info.data.get("proxmox_enabled") and not value.strip():
            raise ValueError(
                "ACOP_PROXMOX_TOKEN_ID is required when ACOP_PROXMOX_ENABLED "
                "is true (for example 'acop@pve!discovery')."
            )
        return value

    @field_validator("proxmox_token_secret")
    @classmethod
    def _proxmox_token_secret_required_when_enabled(
        cls, value: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        """Fail at startup, not on the first call at three in the morning."""
        if info.data.get("proxmox_enabled") and not value.get_secret_value():
            raise ValueError(
                "ACOP_PROXMOX_TOKEN_SECRET is required when ACOP_PROXMOX_ENABLED is true."
            )
        return value

    @field_validator("proxmox_verify_tls")
    @classmethod
    def _proxmox_tls_verification_outside_development(
        cls, value: bool, info: ValidationInfo
    ) -> bool:
        """A home lab may skip verification. A deployed environment may not.

        Unverified TLS authenticates nothing: the connection is encrypted to
        whoever answered, which is exactly the property an interception needs.
        """
        if not value and info.data.get("environment") in (
            Environment.STAGING,
            Environment.PRODUCTION,
        ):
            raise ValueError(
                "ACOP_PROXMOX_VERIFY_TLS must be true outside development. "
                "For a self-signed cluster certificate, trust its CA rather "
                "than disabling verification."
            )
        return value

    @field_validator("proxmox_timeout_seconds")
    @classmethod
    def _proxmox_timeout_is_positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("ACOP_PROXMOX_TIMEOUT_SECONDS must be greater than zero.")
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
        return URL.create(
            "postgresql+asyncpg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)

    @property
    def sync_database_url(self) -> str:
        """Synchronous URL. Used only by tooling that cannot run async."""
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)

    @property
    def alembic_database_url(self) -> str:
        """Database URL escaped for Alembic ConfigParser interpolation."""
        return self.database_url.replace("%", "%%")

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
