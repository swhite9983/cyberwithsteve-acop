"""The request-transaction boundary, proved over a real TCP server.

**Why these tests do not use httpx.ASGITransport.** Every other API test in
this suite does, and none of them could have caught the defect this module
guards. ``ASGITransport`` awaits the entire ASGI call - including FastAPI's
dependency-teardown stack - before returning the response object to the
client, so a commit placed in teardown *appears* to happen before the client
sees the status code. Over a real socket it does not: uvicorn writes the
response bytes inside ``await response(scope, receive, send)``, and the
teardown stack unwinds afterwards.

Measured against a real uvicorn server before the fix, an asset was still
invisible on an independent PostgreSQL connection in 116 of 150 requests that
had already returned 201, and the acceptance verifier failed with an
``ExclusionViolationError`` on ``ex_asset_fact_no_overlap``.

So these tests boot a real uvicorn server on a real port. They are slower than
the rest of the suite and that cost is the point: this is the only shape of
test that can observe the property.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.config import ApiKeyPrincipalConfig, Settings
from acop.db import Database
from acop.main import create_app
from acop.models.asset import Asset
from acop.models.audit import AuditEvent
from acop.models.fact import AssetFact, FactAttestation
from tests.conftest import MEM_16, MEM_24, requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR_KEY = "operator-key-tx-0000000000000"
APPROVER_KEY = "approver-key-tx-0000000000000"
OPERATOR = {"X-ACOP-API-Key": OPERATOR_KEY}
APPROVER = {"X-ACOP-API-Key": APPROVER_KEY}


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def tx_settings(make_settings) -> Settings:
    return make_settings(
        api_keys=[
            ApiKeyPrincipalConfig(
                subject="acop:user:operator", secret=OPERATOR_KEY, roles=["operator"]
            ),
            ApiKeyPrincipalConfig(
                subject="acop:user:approver", secret=APPROVER_KEY, roles=["approver"]
            ),
        ]
    )


@pytest.fixture
async def live_api(tx_settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    """A real uvicorn server on a real port, against a freshly migrated schema."""
    database = Database(tx_settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", tx_settings.database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    await database.dispose()

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(tx_settings),
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
        )
    )
    task = asyncio.create_task(server.serve())
    for _ in range(200):  # up to ~10s, in 50ms steps
        if server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started, "uvicorn did not start"

    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=30.0
        ) as client:
            yield client
    finally:
        server.should_exit = True
        await task


@pytest.fixture
async def observer(tx_settings: Settings) -> AsyncIterator[Database]:
    """An independent connection, used to see what the server has committed.

    Separate from the server's engine on purpose: a second session on the same
    engine would still be a different transaction, but using a different
    Database makes the independence obvious to a reader.
    """
    database = Database(tx_settings)
    try:
        yield database
    finally:
        await database.dispose()


async def _count(database: Database, model: type, *where: object) -> int:
    async with database.session() as session:
        statement = select(func.count()).select_from(model)
        for clause in where:
            statement = statement.where(clause)  # type: ignore[arg-type]
        return int((await session.execute(statement)).scalar_one())


def _memory(value: int, source_id: str) -> dict[str, object]:
    return {
        "predicate": "memory.total_bytes",
        "value_type": "NUMBER",
        "value_number": value,
        "source_type": "LIVE_DISCOVERY",
        "source_id": source_id,
    }


async def _create_asset(api: httpx.AsyncClient, tag: str) -> str:
    response = await api.post(
        "/cmdb/assets",
        headers=OPERATOR,
        json={
            "asset_type": "VM",
            "display_name": f"tx-{tag}",
            "identifiers": [{"namespace": "serial", "value": f"TX-{tag}"}],
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


class TestCommitBeforeResponse:
    """A. and B. - the two failures the acceptance verifier reported."""

    async def test_immediate_identical_assert_returns_touched(
        self, live_api: httpx.AsyncClient
    ) -> None:
        """A. Create, assert, then re-assert with no pause at all.

        Before the fix this raised ExclusionViolationError: the second request
        could not see the live claim the first had created, took the CREATED
        branch, and tried to insert a second overlapping live row. The
        exclusion constraint did its job; the transaction boundary had not.
        """
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        first = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        assert first.status_code == 201
        assert first.json()["outcome"] == "CREATED"

        second = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        assert second.status_code == 200, second.text
        assert second.json()["outcome"] == "TOUCHED"

    async def test_immediate_revoke_after_verify_succeeds(
        self, live_api: httpx.AsyncClient
    ) -> None:
        """B. Verify, then revoke with no pause.

        Before the fix the revoke read ``DISCOVERED`` and returned 409, because
        the verify had not committed yet - trust-state logic was never the
        problem.
        """
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        created = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        fact_id = created.json()["fact"]["id"]

        verified = await live_api.post(
            f"/cmdb/facts/{fact_id}/verify", headers=APPROVER, json={"reason": "ok"}
        )
        assert verified.status_code == 200
        assert verified.json()["verification_status"] == "VERIFIED"

        revoked = await live_api.post(
            f"/cmdb/facts/{fact_id}/revoke", headers=APPROVER, json={"reason": "undo"}
        )
        assert revoked.status_code == 200, revoked.text

    async def test_supersede_then_immediate_reassert(
        self, live_api: httpx.AsyncClient
    ) -> None:
        """The same guarantee across a value change, not only an unchanged one."""
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        changed = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_24, "a")
        )
        assert changed.status_code == 201
        assert changed.json()["outcome"] == "SUPERSEDED"

        again = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_24, "a")
        )
        assert again.status_code == 200
        assert again.json()["outcome"] == "TOUCHED"

    async def test_committed_state_is_visible_on_an_independent_connection(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """The invariant itself, observed from outside the server entirely.

        This is the measurement that failed 116 times in 150 before the fix.
        Repeated because the pre-fix race did not fail every time - a single
        pass would have proved nothing.
        """
        for _ in range(15):
            tag = uuid.uuid4().hex[:8]
            response = await live_api.post(
                "/cmdb/assets",
                headers=OPERATOR,
                json={
                    "asset_type": "VM",
                    "display_name": f"tx-{tag}",
                    "identifiers": [{"namespace": "serial", "value": f"TX-{tag}"}],
                },
            )
            assert response.status_code == 201
            asset_id = uuid.UUID(response.json()["id"])
            assert await _count(observer, Asset, Asset.id == asset_id) == 1, (
                "asset was not committed when its 201 reached the client"
            )


class TestAtomicity:
    """C. and D. - success is atomic, failure rolls back."""

    async def test_mutation_and_success_audit_commit_together(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """C. The fact row and its audit row become visible together.

        Both are flushed into the same session and released by one commit, so
        an outside observer can never see one without the other.
        """
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        created = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        assert created.status_code == 201
        fact_id = uuid.UUID(created.json()["fact"]["id"])

        assert await _count(observer, AssetFact, AssetFact.id == fact_id) == 1
        assert (
            await _count(
                observer,
                AuditEvent,
                AuditEvent.action == "cmdb.fact.assert",
                AuditEvent.resource_id == str(fact_id),
            )
            == 1
        )

    async def test_a_failed_request_rolls_back_its_transaction(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """D. A refused request leaves nothing behind.

        A secret-bearing predicate is rejected after the asset exists, so the
        request has a live session; nothing from it may survive.
        """
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        before = await _count(observer, AssetFact)

        refused = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json={
                "predicate": "snmp.community",
                "value_type": "TEXT",
                "value_text": "rollback-probe-value",
                "source_type": "LIVE_DISCOVERY",
                "source_id": "a",
            },
        )
        assert refused.status_code == 422
        assert "rollback-probe-value" not in refused.text
        assert await _count(observer, AssetFact) == before

    async def test_conflicting_identifiers_roll_back_and_write_nothing(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """D. again, on the identity path: a 409 creates no asset."""
        tag_a, tag_b = uuid.uuid4().hex[:8], uuid.uuid4().hex[:8]
        await _create_asset(live_api, tag_a)
        await _create_asset(live_api, tag_b)
        before = await _count(observer, Asset)

        clash = await live_api.post(
            "/cmdb/assets/resolve",
            headers=OPERATOR,
            json={
                "asset_type": "VM",
                "display_name": "tx-merged",
                "identifiers": [
                    {"namespace": "serial", "value": f"TX-{tag_a}"},
                    {"namespace": "serial", "value": f"TX-{tag_b}"},
                ],
            },
        )
        assert clash.status_code == 409
        assert await _count(observer, Asset) == before


class TestDenialAuditingStillIndependent:
    """E. - the Milestone 2 denial guarantee survives the new boundary."""

    async def test_denial_survives_the_request_rollback(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """E. The DENIED row is committed on its own connection.

        The route's rollback now happens inside the endpoint wrapper rather
        than in teardown, which is exactly the moment this could have
        regressed: the denial must already be committed elsewhere by then.
        """
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        refused = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json={
                "predicate": "snmp.community",
                "value_type": "TEXT",
                "value_text": "never-stored",
                "source_type": "LIVE_DISCOVERY",
                "source_id": "a",
            },
        )
        assert refused.status_code == 422

        assert (
            await _count(
                observer,
                AuditEvent,
                AuditEvent.action == "cmdb.fact.secret_rejected",
            )
            == 1
        )
        async with observer.session() as session:
            row = (
                (
                    await session.execute(
                        select(AuditEvent).where(
                            AuditEvent.action == "cmdb.fact.secret_rejected"
                        )
                    )
                )
                .scalars()
                .one()
            )
        assert row.outcome == "DENIED"
        assert row.principal_subject == "acop:user:operator"
        assert "never-stored" not in str(row.context)

    async def test_identity_conflict_denial_survives(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """E. on the other denial path, which also rolls back a live session."""
        tag_a, tag_b = uuid.uuid4().hex[:8], uuid.uuid4().hex[:8]
        await _create_asset(live_api, tag_a)
        await _create_asset(live_api, tag_b)

        clash = await live_api.post(
            "/cmdb/assets/resolve",
            headers=OPERATOR,
            json={
                "asset_type": "VM",
                "display_name": "tx-merged",
                "identifiers": [
                    {"namespace": "serial", "value": f"TX-{tag_a}"},
                    {"namespace": "serial", "value": f"TX-{tag_b}"},
                ],
            },
        )
        assert clash.status_code == 409
        assert (
            await _count(
                observer, AuditEvent, AuditEvent.action == "cmdb.identity.conflict"
            )
            == 1
        )


class TestReadOnlyRequestsDoNotCommit:
    """A GET that writes nothing must not issue a commit."""

    async def test_get_does_not_write(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        before = await _count(observer, AuditEvent)
        for _ in range(3):
            listed = await live_api.get(
                f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR
            )
            assert listed.status_code == 200
        assert await _count(observer, AuditEvent) == before

    async def test_whoami_still_commits_its_audit_row(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        """A GET that *does* write must still commit.

        ``/whoami`` is a Milestone 1 endpoint that writes an audit record on a
        GET. It is the reason the commit trigger is "this session flushed a
        write", not "this is a POST".
        """
        before = await _count(
            observer, AuditEvent, AuditEvent.action == "identity.whoami"
        )
        response = await live_api.get("/whoami", headers=OPERATOR)
        assert response.status_code == 200
        after = await _count(observer, AuditEvent, AuditEvent.action == "identity.whoami")
        assert after == before + 1


class TestRevocationTrailAfterFix:
    """Section 4 of the correction: prove the attestation pair now persists."""

    async def test_verify_then_revoke_leaves_both_attestations(
        self, live_api: httpx.AsyncClient, observer: Database
    ) -> None:
        asset_id = await _create_asset(live_api, uuid.uuid4().hex[:8])
        created = await live_api.post(
            f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR, json=_memory(MEM_16, "a")
        )
        fact_id = created.json()["fact"]["id"]

        await live_api.post(
            f"/cmdb/facts/{fact_id}/verify", headers=APPROVER, json={"reason": "seen"}
        )
        await live_api.post(
            f"/cmdb/facts/{fact_id}/revoke", headers=APPROVER, json={"reason": "undo"}
        )

        listed = await live_api.get(
            f"/cmdb/facts/{fact_id}/attestations", headers=OPERATOR
        )
        rows = listed.json()
        transitions = {
            (row["action"], row["from_status"], row["to_status"]) for row in rows
        }
        assert ("VERIFY", "DISCOVERED", "VERIFIED") in transitions
        assert ("REVOKE", "VERIFIED", "DISCOVERED") in transitions
        assert all(row["principal_subject"] == "acop:user:approver" for row in rows)

        # The value, provenance and supersession history are untouched.
        current = await live_api.get(f"/cmdb/assets/{asset_id}/facts", headers=OPERATOR)
        fact = current.json()[0]
        assert fact["value_number"] == MEM_16
        assert fact["source_id"] == "a"
        assert fact["verification_status"] == "DISCOVERED"
        assert fact["verified_by_subject"] is None

        async with observer.session() as session:
            persisted = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(FactAttestation)
                        .where(FactAttestation.fact_id == uuid.UUID(fact_id))
                    )
                ).scalar_one()
            )
        assert persisted == 2
