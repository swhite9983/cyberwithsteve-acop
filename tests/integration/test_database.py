"""Integration tests requiring a live PostgreSQL.

Run with:
    ACOP_TEST_DATABASE=1 pytest tests/integration

These tests apply the real Alembic migrations rather than
``Base.metadata.create_all``. Creating tables from metadata would test the
models and leave the migrations - the thing that actually runs in production -
unverified.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import respx
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.auth import SYSTEM_PRINCIPAL, AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.db import Database
from acop.main import create_app
from acop.models.audit import AuditEvent, AuditOutcome, AuditSeverity
from acop.schemas.audit import AuditEventCreate
from acop.services import AuditService
from tests.conftest import (
    OLLAMA_BASE_URL,
    TEST_API_SECRET,
    TEST_SUBJECT,
    requires_database,
)

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(settings: Settings) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


@pytest.fixture
async def migrated_database(settings: Settings):
    """Apply migrations to a clean schema, then tear it down."""
    database = Database(settings)

    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))

    config = _alembic_config(settings)
    # Alembic's env.py runs its own asyncio.run(), so it cannot be called from
    # inside a running loop. Off-thread keeps the real migration path intact.
    await asyncio.to_thread(command.upgrade, config, "head")

    try:
        yield database
    finally:
        await database.dispose()


class TestMigrations:
    async def test_upgrade_creates_the_audit_table(self, migrated_database) -> None:
        async with migrated_database.engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' ORDER BY table_name"
                )
            )
            tables = {row[0] for row in result}
        assert "audit_event" in tables
        assert "alembic_version" in tables

    async def test_milestone_2_creates_exactly_the_expected_tables(
        self, migrated_database
    ) -> None:
        # Scope guard: no speculative Milestone 3+ tables.
        async with migrated_database.engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
                )
            )
            tables = {row[0] for row in result}
        assert tables == {
            "audit_event",
            "asset",
            "asset_identifier",
            "asset_fact",
            "fact_attestation",
            "asset_relationship",
        }

    async def test_timestamps_are_timezone_aware(self, migrated_database) -> None:
        async with migrated_database.engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_name = 'audit_event' "
                    "AND column_name IN ('occurred_at', 'recorded_at')"
                )
            )
            types = dict(result.all())
        assert types["occurred_at"] == "timestamp with time zone"
        assert types["recorded_at"] == "timestamp with time zone"

    async def test_downgrade_then_upgrade_is_clean(self, settings: Settings) -> None:
        config = _alembic_config(settings)
        await asyncio.to_thread(command.downgrade, config, "base")
        await asyncio.to_thread(command.upgrade, config, "head")


class TestAuditService:
    async def test_record_persists_the_neutral_identity_fields(
        self, migrated_database
    ) -> None:
        principal = Principal(
            subject="acop:user:steve",
            principal_type=PrincipalType.HUMAN,
            issuer="acop:api-key",
            auth_method=AuthMethod.API_KEY,
            display_name="Steve White",
            roles=frozenset({"admin"}),
            claims={"provider_internal": "must-not-persist"},
        )

        async with migrated_database.session() as session:
            await AuditService(session).record(
                AuditEventCreate(
                    action="test.record",
                    outcome=AuditOutcome.SUCCESS,
                    severity=AuditSeverity.NOTICE,
                    resource_type="switch",
                    resource_id="CORE3850",
                    message="Test record.",
                    context={"interface": "Gi1/0/18"},
                ),
                principal,
                source_address="10.0.0.5",
            )

        async with migrated_database.session() as session:
            row = (await session.execute(select(AuditEvent))).scalars().one()

        assert row.principal_subject == "acop:user:steve"
        assert row.principal_type == "human"
        assert row.principal_issuer == "acop:api-key"
        assert row.auth_method == "api_key"
        assert row.action == "test.record"
        assert row.outcome == "SUCCESS"
        assert row.context == {"interface": "Gi1/0/18"}
        # Provider-specific claims must never reach the table.
        assert "must-not-persist" not in str(row.context)

    async def test_secrets_in_context_are_redacted_before_persistence(
        self, migrated_database
    ) -> None:
        async with migrated_database.session() as session:
            await AuditService(session).record(
                AuditEventCreate(
                    action="tool.execute",
                    outcome=AuditOutcome.SUCCESS,
                    context={
                        "device": "CORE3850",
                        "credentials": {"username": "acop", "password": "hunter2"},
                        "snmp_community": "public",
                    },
                ),
                SYSTEM_PRINCIPAL,
            )

        async with migrated_database.session() as session:
            row = (await session.execute(select(AuditEvent))).scalars().one()

        serialised = str(row.context)
        assert "hunter2" not in serialised
        assert "public" not in serialised
        assert "CORE3850" in serialised

    async def test_service_exposes_no_update_or_delete_path(self) -> None:
        # First of the three layers enforcing append-only semantics. The set is
        # closed rather than pattern-matched so that adding any method to this
        # service is a decision someone has to make deliberately. Milestone 2
        # added `record_denial`, which is still append-only - it differs from
        # `record` only in writing on its own connection so that a refusal
        # survives the rollback of the request that was refused.
        public_methods = {name for name in dir(AuditService) if not name.startswith("_")}
        assert public_methods == {"record", "record_denial"}
        assert not {
            name
            for name in public_methods
            if any(
                verb in name for verb in ("update", "delete", "modify", "purge", "amend")
            )
        }

    async def test_request_id_is_captured_for_correlation(
        self, migrated_database
    ) -> None:
        async with migrated_database.session() as session:
            await AuditService(session).record(
                AuditEventCreate(action="test.correlate", outcome=AuditOutcome.SUCCESS),
                SYSTEM_PRINCIPAL,
                request_id="req-abc-123",
            )
        async with migrated_database.session() as session:
            row = (await session.execute(select(AuditEvent))).scalars().one()
        assert row.request_id == "req-abc-123"


class TestHealthWithLiveDatabase:
    @respx.mock
    async def test_all_components_healthy(
        self, migrated_database, settings: Settings
    ) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json={"models": [{"name": "qwen3:32b"}]})
        )

        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as client:
                body = (await client.get("/health")).json()
                ready = await client.get("/health/ready")

        assert body["status"] == "healthy"
        assert body["components"] == {
            "api": "healthy",
            "database": "healthy",
            "ollama": "healthy",
            "model": "healthy",
        }
        assert body["details"]["database"]["latency_ms"] is not None
        assert ready.status_code == 200


class TestWhoAmIEndToEnd:
    @respx.mock
    async def test_authenticated_request_returns_identity_and_writes_audit(
        self, migrated_database, settings: Settings
    ) -> None:
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as client:
                response = await client.get(
                    "/whoami", headers={"X-ACOP-API-Key": TEST_API_SECRET}
                )

        assert response.status_code == 200
        identity = response.json()
        assert identity["subject"] == TEST_SUBJECT
        assert identity["issuer"] == "acop:api-key"
        assert identity["auth_method"] == "api_key"
        assert identity["roles"] == ["operator"]

        async with migrated_database.session() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "identity.whoami")
            )
            row = (
                (
                    await session.execute(
                        select(AuditEvent).where(AuditEvent.action == "identity.whoami")
                    )
                )
                .scalars()
                .one()
            )

        assert count == 1
        assert row.principal_subject == TEST_SUBJECT
        assert row.request_id == response.headers["X-Request-ID"]
        assert row.outcome == "SUCCESS"
