"""Shared test fixtures.

Tests are split by what they require:

* Unit tests need nothing external. Ollama is mocked at the HTTP layer with
  ``respx`` so the real client code - including its error translation - is
  exercised rather than replaced by a stub.
* Integration tests are marked ``integration`` and skip unless
  ``ACOP_TEST_DATABASE=1`` and a reachable PostgreSQL is configured.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from acop.config import ApiKeyPrincipalConfig, Environment, Settings
from acop.main import create_app

TEST_API_SECRET = "test-secret-value-0123456789abcdef"
TEST_SUBJECT = "acop:user:test-operator"
OLLAMA_BASE_URL = "http://ollama.test:11434"

#: Distinctive so that "did this value leak into a response?" assertions cannot
#: pass or fail by coincidentally matching a hostname or database name.
TEST_DB_PASSWORD = "test-db-password-Zq7xR2"

#: Port 1 is reserved and always refuses a connection. Unit tests point here
#: explicitly rather than relying on PostgreSQL happening to be absent, so the
#: suite behaves identically on a developer laptop, in CI, and on a machine
#: that is also running the integration database.
UNREACHABLE_DB_PORT = 1


def _default_db_port() -> int:
    return int(os.getenv("ACOP_TEST_POSTGRES_PORT", "5432"))


def _base_settings(**overrides: object) -> Settings:
    """Build settings for a test application without reading a .env file."""
    values: dict[str, object] = {
        "environment": Environment.TEST,
        "log_level": "WARNING",
        "log_format": "console",
        "postgres_host": os.getenv("ACOP_TEST_POSTGRES_HOST", "127.0.0.1"),
        "postgres_port": _default_db_port(),
        "postgres_user": os.getenv("ACOP_TEST_POSTGRES_USER", "acop"),
        "postgres_password": os.getenv("ACOP_TEST_POSTGRES_PASSWORD", TEST_DB_PASSWORD),
        "postgres_db": os.getenv("ACOP_TEST_POSTGRES_DB", "acop_test"),
        "ollama_base_url": OLLAMA_BASE_URL,
        "ollama_model": "qwen3:32b",
        "ollama_control_timeout_seconds": 1.0,
        "ollama_generate_timeout_seconds": 5.0,
        "db_connect_timeout_seconds": 1.0,
        "health_cache_ttl_seconds": 0.0,
        "auth_enabled": True,
        "api_keys": [
            ApiKeyPrincipalConfig(
                subject=TEST_SUBJECT,
                secret=TEST_API_SECRET,
                display_name="Test Operator",
                roles=["operator"],
                principal_type="human",
            )
        ],
    }
    values.update(overrides)
    # _env_file=None stops pydantic-settings from picking up a developer's real
    # .env and making test results machine-dependent.
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.fixture
def settings() -> Settings:
    """Settings pointing at the integration database.

    Used by tests that expect a live PostgreSQL. Unit tests use
    ``offline_settings``.
    """
    return _base_settings()


@pytest.fixture
def offline_settings() -> Settings:
    """Settings whose database is guaranteed to be unreachable.

    Unit tests use these so that their results never depend on what happens to
    be listening on port 5432.
    """
    return _base_settings(postgres_port=UNREACHABLE_DB_PORT)


@pytest.fixture
def make_settings():
    """Factory so a test can build settings with specific overrides."""
    return _base_settings


@pytest.fixture
def app(offline_settings: Settings) -> FastAPI:
    """The default application for unit tests: no reachable dependencies."""
    return create_app(offline_settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client bound to the application, with lifespan executed."""
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://acop.test"
        ) as http_client:
            yield http_client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-ACOP-API-Key": TEST_API_SECRET}


# ---------------------------------------------------------------------------
# Integration gating
# ---------------------------------------------------------------------------
def _database_enabled() -> bool:
    return os.getenv("ACOP_TEST_DATABASE") == "1"


requires_database = pytest.mark.skipif(
    not _database_enabled(),
    reason="Set ACOP_TEST_DATABASE=1 and provide a reachable PostgreSQL to run.",
)

requires_live_ollama = pytest.mark.skipif(
    os.getenv("ACOP_TEST_OLLAMA") != "1",
    reason="Set ACOP_TEST_OLLAMA=1 to run against the real Ollama host.",
)


# ---------------------------------------------------------------------------
# CMDB fixtures (Milestone 2)
# ---------------------------------------------------------------------------
#
# Addresses and hardware identifiers below come from the documentation ranges
# reserved for exactly this purpose - RFC 5737 for IPv4 and RFC 7042 for MAC -
# because this repository is public and lab-shaped fixtures have a way of
# becoming lab-accurate fixtures.
DOC_IPV4 = "192.0.2.10"
DOC_MAC = "00:00:5E:00:53:01"
DOC_MAC_ALT = "00:00:5E:00:53:02"
DOC_SERIAL = "DOCSERIAL0001"

#: 12 GiB, 16 GiB and 24 GiB in bytes - the walkthrough values.
GIB = 1024**3
MEM_12 = 12 * GIB
MEM_16 = 16 * GIB
MEM_24 = 24 * GIB


@pytest.fixture
def operator_principal():
    """An operator: may create assets and assert facts, may not verify."""
    from acop.auth import AuthMethod, Principal, PrincipalType, Role

    return Principal(
        subject="acop:user:operator",
        principal_type=PrincipalType.HUMAN,
        issuer="acop:api-key",
        auth_method=AuthMethod.API_KEY,
        display_name="Test Operator",
        roles=frozenset({Role.OPERATOR.value}),
    )


@pytest.fixture
def approver_principal():
    """Principal A in the revocation scenario: verifies."""
    from acop.auth import AuthMethod, Principal, PrincipalType, Role

    return Principal(
        subject="acop:user:approver-a",
        principal_type=PrincipalType.HUMAN,
        issuer="acop:api-key",
        auth_method=AuthMethod.API_KEY,
        display_name="Approver A",
        roles=frozenset({Role.APPROVER.value}),
    )


@pytest.fixture
def second_approver_principal():
    """Principal B in the revocation scenario: revokes A's verification."""
    from acop.auth import AuthMethod, Principal, PrincipalType, Role

    return Principal(
        subject="acop:user:approver-b",
        principal_type=PrincipalType.HUMAN,
        issuer="acop:api-key",
        auth_method=AuthMethod.API_KEY,
        display_name="Approver B",
        roles=frozenset({Role.APPROVER.value}),
    )
