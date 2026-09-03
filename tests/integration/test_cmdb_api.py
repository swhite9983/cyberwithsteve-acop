"""The CMDB HTTP surface, end to end against a live database.

Covers what the service-level tests cannot: authentication, role gating, status
codes, and that a mutation and its audit row really do commit together through
the request-scoped session.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.config import ApiKeyPrincipalConfig, Settings
from acop.db import Database
from acop.main import create_app
from acop.models.audit import AuditEvent
from tests.conftest import DOC_SERIAL, MEM_12, MEM_16, requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

VIEWER_KEY = "viewer-key-000000000000000000000"
OPERATOR_KEY = "operator-key-00000000000000000"
APPROVER_KEY = "approver-key-00000000000000000"

VIEWER = {"X-ACOP-API-Key": VIEWER_KEY}
OPERATOR = {"X-ACOP-API-Key": OPERATOR_KEY}
APPROVER = {"X-ACOP-API-Key": APPROVER_KEY}


@pytest.fixture
def api_settings(make_settings) -> Settings:
    return make_settings(
        api_keys=[
            ApiKeyPrincipalConfig(
                subject="acop:user:viewer", secret=VIEWER_KEY, roles=["viewer"]
            ),
            ApiKeyPrincipalConfig(
                subject="acop:user:operator", secret=OPERATOR_KEY, roles=["operator"]
            ),
            ApiKeyPrincipalConfig(
                subject="acop:user:approver", secret=APPROVER_KEY, roles=["approver"]
            ),
        ]
    )


@pytest.fixture
async def api(api_settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    database = Database(api_settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", api_settings.database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    await database.dispose()

    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://acop.test"
        ) as client:
            yield client


async def _create_vm(api: httpx.AsyncClient, name: str, serial: str) -> str:
    response = await api.post(
        "/cmdb/assets",
        headers=OPERATOR,
        json={
            "asset_type": "VM",
            "display_name": name,
            "identifiers": [{"namespace": "serial", "value": serial}],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _memory(value: int, source_id: str, source_type: str = "LIVE_DISCOVERY") -> dict:
    return {
        "predicate": "memory.total_bytes",
        "value_type": "NUMBER",
        "value_number": value,
        "source_type": source_type,
        "source_id": source_id,
    }


class TestRoleGating:
    async def test_anonymous_is_401_not_403(self, api: httpx.AsyncClient) -> None:
        response = await api.get("/cmdb/assets")
        assert response.status_code == 401

    async def test_viewer_can_read(self, api: httpx.AsyncClient) -> None:
        assert (await api.get("/cmdb/assets", headers=VIEWER)).status_code == 200

    async def test_viewer_cannot_write(self, api: httpx.AsyncClient) -> None:
        response = await api.post(
            "/cmdb/assets",
            headers=VIEWER,
            json={"asset_type": "VM", "display_name": "vm-doc-denied"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "not_authorized"

    async def test_operator_cannot_verify(self, api: httpx.AsyncClient) -> None:
        asset_id = await _create_vm(api, "vm-doc-roles", "DOC-ROLES-1")
        created = await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:pve-doc-01"),
        )
        fact_id = created.json()["fact"]["id"]
        response = await api.post(
            f"/cmdb/facts/{fact_id}/verify", headers=OPERATOR, json={}
        )
        assert response.status_code == 403

    async def test_approver_can_verify(self, api: httpx.AsyncClient) -> None:
        asset_id = await _create_vm(api, "vm-doc-approve", "DOC-ROLES-2")
        created = await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:pve-doc-01"),
        )
        fact_id = created.json()["fact"]["id"]
        response = await api.post(
            f"/cmdb/facts/{fact_id}/verify",
            headers=APPROVER,
            json={"reason": "Checked against the hypervisor."},
        )
        assert response.status_code == 200
        assert response.json()["verification_status"] == "VERIFIED"
        assert response.json()["verified_by_subject"] == "acop:user:approver"


class TestFactHttpLifecycle:
    async def test_assert_touch_supersede_status_codes(
        self, api: httpx.AsyncClient
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-http", "DOC-HTTP-1")
        url = f"/cmdb/assets/{asset_id}/facts"

        first = await api.post(url, headers=OPERATOR, json=_memory(MEM_12, "proxmox:a"))
        assert first.status_code == 201
        assert first.json()["outcome"] == "CREATED"

        # Unchanged rediscovery: 200, not 201, and no new row.
        again = await api.post(url, headers=OPERATOR, json=_memory(MEM_12, "proxmox:a"))
        assert again.status_code == 200
        assert again.json()["outcome"] == "TOUCHED"
        assert again.json()["fact"]["id"] == first.json()["fact"]["id"]

        changed = await api.post(url, headers=OPERATOR, json=_memory(MEM_16, "proxmox:a"))
        assert changed.status_code == 201
        assert changed.json()["outcome"] == "SUPERSEDED"
        assert changed.json()["superseded_fact_id"] == first.json()["fact"]["id"]

        live = await api.get(url, headers=VIEWER)
        assert len(live.json()) == 1

        history = await api.get(f"{url}/memory.total_bytes/history", headers=VIEWER)
        assert len(history.json()["intervals"]) == 2

    async def test_conflict_is_visible_and_effective_value_is_honest(
        self, api: httpx.AsyncClient
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-conflict", "DOC-HTTP-2")
        url = f"/cmdb/assets/{asset_id}/facts"
        await api.post(url, headers=OPERATOR, json=_memory(MEM_16, "proxmox:a"))
        await api.post(
            url,
            headers=OPERATOR,
            json=_memory(MEM_12, "acop:user:steve", "MANUAL_ENTRY"),
        )

        conflicts = await api.get(f"/cmdb/assets/{asset_id}/conflicts", headers=VIEWER)
        assert conflicts.status_code == 200
        assert len(conflicts.json()) == 1
        assert conflicts.json()[0]["distinct_values"] == 2

        effective = await api.get(f"{url}/memory.total_bytes/effective", headers=VIEWER)
        assert effective.json()["basis"] == "UNRESOLVED"
        assert effective.json()["resolution_required"] is True

    async def test_secret_predicate_is_rejected_with_422(
        self, api: httpx.AsyncClient, api_settings: Settings
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-secret-http", "DOC-HTTP-3")
        response = await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json={
                "predicate": "snmp.community",
                "value_type": "TEXT",
                "value_text": "public",
                "source_type": "LIVE_DISCOVERY",
                "source_id": "cisco:doc-switch-01",
            },
        )
        assert response.status_code == 422
        # The rejected value must not be echoed back to the caller.
        assert "public" not in response.text

        # The rejection itself is the event a reviewer most wants, and the
        # request that produced it was rolled back. It has to have been written
        # outside that transaction to still be here.
        database = Database(api_settings)
        try:
            async with database.session() as session:
                denied = (
                    (
                        await session.execute(
                            select(AuditEvent).where(
                                AuditEvent.action == "cmdb.fact.secret_rejected"
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
        finally:
            await database.dispose()

        assert len(denied) == 1
        assert denied[0].outcome == "DENIED"
        assert denied[0].principal_subject == "acop:user:operator"
        # The denial names the predicate but never carries the value.
        assert "public" not in str(denied[0].context)

    async def test_revocation_over_http_preserves_the_trail(
        self, api: httpx.AsyncClient
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-revoke-http", "DOC-HTTP-4")
        created = await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:a"),
        )
        fact_id = created.json()["fact"]["id"]

        await api.post(
            f"/cmdb/facts/{fact_id}/verify",
            headers=APPROVER,
            json={"reason": "Confirmed."},
        )
        revoked = await api.post(
            f"/cmdb/facts/{fact_id}/revoke",
            headers=APPROVER,
            json={"reason": "Taken mid-migration."},
        )
        assert revoked.status_code == 200
        assert revoked.json()["verification_status"] == "DISCOVERED"
        assert revoked.json()["verified_by_subject"] is None

        trail = await api.get(f"/cmdb/facts/{fact_id}/attestations", headers=VIEWER)
        actions = [item["action"] for item in trail.json()]
        assert actions == ["REVOKE", "VERIFY"]
        assert all(
            item["principal_subject"] == "acop:user:approver" for item in trail.json()
        )
        assert trail.json()[1]["reason"] == "Confirmed."


class TestIdentityAndRelationshipsOverHttp:
    async def test_resolve_conflict_returns_409_and_audits_denied(
        self, api: httpx.AsyncClient, api_settings: Settings
    ) -> None:
        await _create_vm(api, "vm-doc-a", "DOC-CONF-A")
        second = await api.post(
            "/cmdb/assets",
            headers=OPERATOR,
            json={
                "asset_type": "VM",
                "display_name": "vm-doc-b",
                "identifiers": [{"namespace": "smbios:uuid", "value": "doc-uuid-b"}],
            },
        )
        assert second.status_code == 201

        clash = await api.post(
            "/cmdb/assets/resolve",
            headers=OPERATOR,
            json={
                "asset_type": "VM",
                "display_name": "vm-doc-merged",
                "identifiers": [
                    {"namespace": "serial", "value": "DOC-CONF-A"},
                    {"namespace": "smbios:uuid", "value": "doc-uuid-b"},
                ],
            },
        )
        assert clash.status_code == 409
        assert clash.json()["error"]["code"] == "identity_conflict"

        database = Database(api_settings)
        try:
            async with database.session() as session:
                denied = (
                    (
                        await session.execute(
                            select(AuditEvent).where(
                                AuditEvent.action == "cmdb.identity.conflict"
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
        finally:
            await database.dispose()

        assert len(denied) == 1
        assert denied[0].outcome == "DENIED"
        assert denied[0].severity == "WARNING"
        assert denied[0].principal_subject == "acop:user:operator"

    async def test_traversal_shows_inverse_label_from_the_other_end(
        self, api: httpx.AsyncClient
    ) -> None:
        vm_id = await _create_vm(api, "vm-doc-guest", "DOC-REL-VM")
        host = await api.post(
            "/cmdb/assets",
            headers=OPERATOR,
            json={
                "asset_type": "HOST",
                "display_name": "host-doc-hv",
                "identifiers": [{"namespace": "serial", "value": "DOC-REL-HOST"}],
            },
        )
        host_id = host.json()["id"]

        edge = await api.post(
            "/cmdb/relationships",
            headers=OPERATOR,
            json={
                "relationship_type": "RUNS_ON",
                "source_asset_id": vm_id,
                "target_asset_id": host_id,
                "source_type": "LIVE_DISCOVERY",
                "source_id": "proxmox:pve-doc-01",
            },
        )
        assert edge.status_code == 201

        from_vm = await api.get(f"/cmdb/assets/{vm_id}/related", headers=VIEWER)
        from_host = await api.get(f"/cmdb/assets/{host_id}/related", headers=VIEWER)
        assert from_vm.json()["neighbours"][0]["label"] == "RUNS_ON"
        assert from_host.json()["neighbours"][0]["label"] == "HOSTS"

    async def test_retire_is_a_post_and_preserves_history(
        self, api: httpx.AsyncClient
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-retire-http", "DOC-RET-1")
        await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:a"),
        )
        retired = await api.post(f"/cmdb/assets/{asset_id}/retire", headers=OPERATOR)
        assert retired.status_code == 200
        assert retired.json()["lifecycle_state"] == "RETIRED"

        # DELETE is not routed at all.
        assert (
            await api.request("DELETE", f"/cmdb/assets/{asset_id}", headers=OPERATOR)
        ).status_code == 405

        history = await api.get(
            f"/cmdb/assets/{asset_id}/facts/memory.total_bytes/history",
            headers=VIEWER,
        )
        assert len(history.json()["intervals"]) == 1  # kept, just closed
        assert history.json()["intervals"][0]["valid_to"] is not None


class TestAuditCoverage:
    async def test_every_mutation_writes_exactly_one_audit_row(
        self, api: httpx.AsyncClient, api_settings: Settings
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-audit-http", "DOC-AUD-1")
        created = await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:a"),
        )
        fact_id = created.json()["fact"]["id"]
        # An unchanged re-assert is still an auditable mutation, under a
        # distinct action so it can be retention-tiered later.
        await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:a"),
        )
        await api.post(f"/cmdb/facts/{fact_id}/verify", headers=APPROVER, json={})

        database = Database(api_settings)
        try:
            async with database.session() as session:
                rows = (
                    await session.execute(
                        select(AuditEvent.action, func.count())
                        .group_by(AuditEvent.action)
                        .order_by(AuditEvent.action)
                    )
                ).all()
        finally:
            await database.dispose()

        counts = dict(rows)
        assert counts["cmdb.asset.create"] == 1
        assert counts["cmdb.fact.assert"] == 1
        assert counts["cmdb.fact.touch"] == 1
        assert counts["cmdb.fact.verify"] == 1

    async def test_audit_context_never_carries_the_fact_value(
        self, api: httpx.AsyncClient, api_settings: Settings
    ) -> None:
        asset_id = await _create_vm(api, "vm-doc-audit-value", "DOC-AUD-2")
        await api.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=OPERATOR,
            json=_memory(MEM_16, "proxmox:a"),
        )
        database = Database(api_settings)
        try:
            async with database.session() as session:
                row = (
                    (
                        await session.execute(
                            select(AuditEvent).where(
                                AuditEvent.action == "cmdb.fact.assert"
                            )
                        )
                    )
                    .scalars()
                    .one()
                )
        finally:
            await database.dispose()

        assert row.context["predicate"] == "memory.total_bytes"
        assert str(MEM_16) not in str(row.context)


class TestScopeOverHttp:
    async def test_no_infrastructure_endpoint_exists(
        self, api: httpx.AsyncClient
    ) -> None:
        schema = (await api.get("/openapi.json")).json()
        forbidden = ("tool", "execute", "command", "ssh", "remediat", "discover")
        for path in schema["paths"]:
            assert not any(word in path.lower() for word in forbidden), path

    async def test_unused_doc_constant_is_still_referenced(self) -> None:
        # Keeps the documentation-range constants honest: fixtures must not
        # drift back to lab-shaped values.
        assert DOC_SERIAL.startswith("DOC")
