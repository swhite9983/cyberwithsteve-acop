"""The Proxmox tools through the whole Milestone 4 path, against real PostgreSQL.

What the unit suite cannot reach is here: policy gates reading real
``tool_registration`` rows, targets resolved from real ``asset`` and
``asset_identifier`` rows through the dispatcher's own
``_resolved_target``, and the terminal state and ``result_summary`` actually
written to an append-only table.

The registered singleton adapter is exercised, not a test double. ``respx``
intercepts at the HTTP layer, so the real client builds the real request with
the real ``Authorization`` header and the real envelope parsing runs - only the
socket is replaced. That matters because the identifiers the adapter reads are
the ones the *dispatcher* selected, in the normalised form the database stores,
which is precisely where a case-folded node name would have gone wrong.

There is no live Proxmox credential anywhere in this file, and no request leaves
the process.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import respx
from alembic import command
from alembic.config import Config
from httpx import Response
from sqlalchemy import select

from acop.auth import AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.db import Database
from acop.models.asset import Asset, AssetIdentifier
from acop.models.provenance import SourceType
from acop.models.tool import ToolInvocation, ToolRegistration
from acop.models.tool_vocabulary import InvocationState, ToolErrorCategory
from acop.models.vocabulary import IDENTIFIER_NAMESPACES, AssetType, LifecycleState
from acop.services.tools.dispatcher import ExecutionDispatcher
from acop.services.tools.invocation import InvocationRequest, ToolInvocationService
from acop.tools.errors import InvalidTargetError, ToolInputError
from acop.tools.registry import ToolRegistryReconciler, get_definition
from tests.conftest import requires_database
from tests.integration.conftest import reset_test_database
from tests.proxmox_fixtures import (
    BASE_URL,
    CT_VMID,
    GUEST_LIST,
    INSTANCE_ID,
    NODE,
    NODE_LIST,
    STORAGE_LIST,
    TOKEN_ID,
    TOKEN_SECRET,
    VM_CONFIG,
    VM_STATUS,
    VM_UUID,
    VM_VMID,
    envelope,
    proxmox_settings,
)

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

VIEWER = Principal(
    subject="acop:user:viewer",
    principal_type=PrincipalType.HUMAN,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset({"viewer"}),
)


@pytest.fixture
def px_settings() -> Settings:
    """Integration-database settings with the Proxmox integration enabled."""
    return proxmox_settings()


@pytest.fixture
async def pxdb(px_settings: Settings) -> AsyncIterator[Database]:
    database = Database(px_settings)
    await reset_test_database(px_settings)
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", px_settings.alembic_database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    async with database.session() as session:
        await ToolRegistryReconciler(session).reconcile()
    try:
        yield database
    finally:
        await database.dispose()


async def _asset_with_identifier(
    database: Database,
    *,
    asset_type: AssetType,
    display_name: str,
    namespace: str,
    value: str,
) -> uuid.UUID:
    """An asset carrying one registered Proxmox identifier.

    The identifier is written through the namespace registry's own normaliser
    and ``unique_in_namespace`` flag rather than by hand, so what the adapter
    reads back is exactly what real discovery would have stored - including the
    case folding that makes live node resolution necessary.
    """
    spec = IDENTIFIER_NAMESPACES[namespace]
    async with database.session() as session:
        asset = Asset(
            asset_type=asset_type.value,
            display_name=display_name,
            lifecycle_state=LifecycleState.ACTIVE.value,
        )
        session.add(asset)
        await session.flush()
        session.add(
            AssetIdentifier(
                asset_id=asset.id,
                namespace=namespace,
                value_raw=value,
                value_normalized=spec.normalise(value),
                unique_in_namespace=spec.unique,
                source_type=SourceType.LIVE_DISCOVERY.value,
                source_id="tests.proxmox",
            )
        )
        await session.flush()
        return asset.id


async def _cluster_asset(database: Database) -> uuid.UUID:
    return await _asset_with_identifier(
        database,
        asset_type=AssetType.CLUSTER,
        display_name="docs-pve-instance",
        namespace="proxmox:instance",
        value=INSTANCE_ID,
    )


async def _vm_asset(database: Database, vmid: int = VM_VMID) -> uuid.UUID:
    return await _asset_with_identifier(
        database,
        asset_type=AssetType.VM,
        display_name=f"docs-vm-{vmid}",
        namespace="proxmox:guest",
        value=f"{INSTANCE_ID}/{vmid}",
    )


async def _invoke(
    database: Database,
    settings: Settings,
    *,
    tool_name: str,
    asset_id: uuid.UUID,
) -> ToolInvocation:
    invocations = ToolInvocationService(database, settings)
    dispatcher = ExecutionDispatcher(database, settings)
    invocation = await invocations.create(
        InvocationRequest(
            tool_name=tool_name,
            tool_version="1.0",
            arguments={},
            target_asset_id=asset_id,
        ),
        VIEWER,
    )
    await dispatcher.execute_once(invocation.id)
    async with database.session() as session:
        row = await session.get(ToolInvocation, invocation.id)
        assert row is not None
        return row


def _route(path: str, data: Any, *, status_code: int = 200) -> None:
    respx.get(f"{BASE_URL}{path}").mock(
        return_value=Response(status_code, content=envelope(data))
    )


# ---------------------------------------------------------------------------
class TestRegistration:
    async def test_all_ten_proxmox_tools_get_an_active_row(self, pxdb: Database) -> None:
        async with pxdb.session() as session:
            rows = (await session.execute(select(ToolRegistration))).scalars().all()
        names = {row.tool_name for row in rows if row.tool_name.startswith("proxmox.")}
        assert names == {
            "proxmox.cluster.status",
            "proxmox.node.list",
            "proxmox.node.status",
            "proxmox.node.network",
            "proxmox.guest.list",
            "proxmox.vm.status",
            "proxmox.vm.config",
            "proxmox.container.status",
            "proxmox.container.config",
            "proxmox.storage.list",
        }
        assert all(row.lifecycle_state == "ACTIVE" for row in rows)

    async def test_no_row_records_the_adapter_or_the_endpoint(
        self, pxdb: Database
    ) -> None:
        """The database owns lifecycle and nothing else about a capability.

        Milestone 4's F3 finding, re-asserted now that a tool's binding actually
        reaches infrastructure: a stored ``adapter_id`` would be a second copy of
        a security-significant value, and a column that exists is a column
        something eventually reads.
        """
        async with pxdb.session() as session:
            row = (
                await session.execute(
                    select(ToolRegistration).where(
                        ToolRegistration.tool_name == "proxmox.vm.config"
                    )
                )
            ).scalar_one()
        assert not hasattr(row, "adapter_id")
        assert not hasattr(row, "endpoint")


# ---------------------------------------------------------------------------
class TestTheHappyPathThroughTheWholeFramework:
    @respx.mock
    async def test_guest_list_succeeds_and_stores_a_typed_result(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        _route("/api2/json/cluster/resources", GUEST_LIST)
        asset_id = await _cluster_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.guest.list", asset_id=asset_id
        )

        assert row.state == InvocationState.SUCCEEDED.value
        assert row.error_category is None
        assert row.result_summary is not None
        assert row.result_digest is not None
        assert {guest["vmid"] for guest in row.result_summary["guests"]} == {
            VM_VMID,
            CT_VMID,
        }
        assert {guest["guest_type"] for guest in row.result_summary["guests"]} == {
            "qemu",
            "lxc",
        }

    @respx.mock
    async def test_the_stored_result_satisfies_the_declared_output_model(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """What ``SUCCEEDED`` now means, after ADR-0023.

        The framework validated this payload before writing it. Re-validating
        the *stored* row proves the guarantee survived sanitization and the JSONB
        round trip, which is the form every later consumer will read it in.
        """
        _route("/api2/json/cluster/resources", GUEST_LIST)
        asset_id = await _cluster_asset(pxdb)
        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.guest.list", asset_id=asset_id
        )
        definition = get_definition("proxmox.guest.list", "1.0")
        assert definition is not None
        definition.output_model.model_validate(row.result_summary)

    @respx.mock
    async def test_a_vm_read_resolves_its_node_from_live_inventory(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """Two requests, and the second one's node came from the first.

        The CMDB holds no ``RUNS_ON`` edge and no ``proxmox:node`` on the guest -
        by design - so this is the whole node-resolution chain running against
        rows the dispatcher selected.
        """
        _route("/api2/json/cluster/resources", GUEST_LIST)
        _route(f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/config", VM_CONFIG)
        asset_id = await _vm_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.vm.config", asset_id=asset_id
        )

        assert row.state == InvocationState.SUCCEEDED.value
        assert row.result_summary is not None
        assert row.result_summary["node"] == NODE
        assert row.result_summary["vmid"] == VM_VMID
        assert row.result_summary["smbios_uuid"] == VM_UUID
        called = [str(call.request.url.path) for call in respx.calls]
        assert called == [
            "/api2/json/cluster/resources",
            f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/config",
        ]

    @respx.mock
    async def test_the_request_carries_the_token_and_nothing_of_it_is_stored(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        _route("/api2/json/cluster/resources", GUEST_LIST)
        _route(f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/status/current", VM_STATUS)
        asset_id = await _vm_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.vm.status", asset_id=asset_id
        )

        sent = respx.calls[0].request.headers["authorization"]
        assert sent == f"PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}"
        stored = (
            f"{row.result_summary} {row.error_detail_sanitized} {row.input_canonical}"
        )
        assert TOKEN_SECRET not in stored
        assert TOKEN_ID not in stored
        assert "PVEAPIToken" not in stored

    @respx.mock
    async def test_storage_is_collected_per_online_node_with_its_source(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        _route("/api2/json/nodes", NODE_LIST)
        _route(f"/api2/json/nodes/{NODE}/storage", STORAGE_LIST)
        asset_id = await _cluster_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.storage.list", asset_id=asset_id
        )

        assert row.state == InvocationState.SUCCEEDED.value
        assert row.result_summary is not None
        assert row.result_summary["nodes_queried"] == [NODE]
        assert all(item["node"] == NODE for item in row.result_summary["storages"])


# ---------------------------------------------------------------------------
class TestRefusalsAreRecordedNotAbsorbed:
    @respx.mock
    async def test_an_instance_mismatch_fails_without_a_single_request(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """The check the ratified design puts before the first HTTP call.

        An asset correlated to another Proxmox instance must not be read against
        this one's base URL: a VMID that exists on both would return a confident
        answer about the wrong machine.
        """
        asset_id = await _asset_with_identifier(
            pxdb,
            asset_type=AssetType.VM,
            display_name="foreign-vm",
            namespace="proxmox:guest",
            value=f"other-pve/{VM_VMID}",
        )
        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.vm.status", asset_id=asset_id
        )
        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.INVALID_TARGET.value
        assert row.result_summary is None
        assert list(respx.calls) == []

    @respx.mock
    async def test_a_guest_with_no_proxmox_identifier_is_refused_not_guessed(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        async with pxdb.session() as session:
            asset = Asset(
                asset_type=AssetType.VM.value,
                display_name="docs-vm-01",
                lifecycle_state=LifecycleState.ACTIVE.value,
            )
            session.add(asset)
            await session.flush()
            asset_id = asset.id

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.vm.status", asset_id=asset_id
        )
        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.INVALID_TARGET.value
        assert list(respx.calls) == []

    @respx.mock
    async def test_a_malformed_response_fails_rather_than_storing_an_empty_result(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """The failure this whole design exists to make impossible.

        A ``SUCCEEDED`` row carrying ``{"guests": []}`` would be read by the
        discovery checkpoint as an instance with no guests, and its absence pass
        would retire every one of them.
        """
        respx.get(f"{BASE_URL}/api2/json/cluster/resources").mock(
            return_value=Response(200, content=b'{"result": []}')
        )
        asset_id = await _cluster_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.guest.list", asset_id=asset_id
        )

        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.EXECUTION_FAILED.value
        assert row.result_summary is None
        assert row.result_digest is None

    @respx.mock
    async def test_an_unauthenticated_read_fails_as_authentication(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        respx.get(f"{BASE_URL}/api2/json/cluster/status").mock(
            return_value=Response(401, content=b'{"errors":{}}')
        )
        asset_id = await _cluster_asset(pxdb)

        row = await _invoke(
            pxdb, px_settings, tool_name="proxmox.cluster.status", asset_id=asset_id
        )

        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.AUTHENTICATION.value
        assert row.error_detail_sanitized == "The caller could not be authenticated."
        # One attempt: AUTHENTICATION is not a retryable category, so the
        # framework did not try a rejected token twice.
        assert len(respx.calls) == 1

    @respx.mock
    async def test_a_wrongly_typed_target_is_refused_before_the_adapter(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """``target_asset_types`` is enforced by policy, not by the adapter.

        A ``VM`` handed to a cluster-scoped tool never reaches the transport, so
        the refusal costs no request and names the reason in the invocation row.
        """
        asset_id = await _vm_asset(pxdb)
        with pytest.raises(InvalidTargetError):
            await ToolInvocationService(pxdb, px_settings).create(
                InvocationRequest(
                    tool_name="proxmox.guest.list",
                    tool_version="1.0",
                    arguments={},
                    target_asset_id=asset_id,
                ),
                VIEWER,
            )
        assert list(respx.calls) == []

    async def test_a_caller_supplied_locator_never_becomes_an_invocation(
        self, pxdb: Database, px_settings: Settings
    ) -> None:
        """``extra="forbid"`` on a fieldless input model, at the request boundary.

        Refused at schema validation, so no invocation row is written and there
        is no canonical input carrying the value to sanitize later.
        """
        asset_id = await _cluster_asset(pxdb)
        for smuggled in ({"node": NODE}, {"api_path": "/api2/json/nodes"}, {"vmid": 1}):
            with pytest.raises(ToolInputError):
                await ToolInvocationService(pxdb, px_settings).create(
                    InvocationRequest(
                        tool_name="proxmox.guest.list",
                        tool_version="1.0",
                        arguments=smuggled,
                        target_asset_id=asset_id,
                    ),
                    VIEWER,
                )

    @respx.mock
    async def test_the_integration_being_disabled_fails_the_invocation(
        self, pxdb: Database
    ) -> None:
        """A read attempted against an unconfigured integration reaches nothing.

        ``ADAPTER_UNAVAILABLE`` rather than a silent empty answer: an operator
        reading this row is told to look at ``ACOP_PROXMOX_*``.
        """
        disabled = proxmox_settings(
            proxmox_enabled=False,
            proxmox_instance_id="",
            proxmox_base_url="",
            proxmox_token_id="",
            proxmox_token_secret="",
        )
        asset_id = await _cluster_asset(pxdb)
        row = await _invoke(
            pxdb, disabled, tool_name="proxmox.cluster.status", asset_id=asset_id
        )
        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.ADAPTER_UNAVAILABLE.value
        assert list(respx.calls) == []
