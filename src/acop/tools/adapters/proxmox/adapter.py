"""The Proxmox adapter: ten read-only tools, one allow-listed GET each.

This is the only component in ACOP permitted to speak to Proxmox, and the
narrowness is the security argument rather than a side effect of it. Read the
constructor and :meth:`ProxmoxAdapter.execute` together and the whole reachable
surface is visible: a tool name is matched against a fixed mapping, a path is
built from a template in :mod:`~acop.tools.adapters.proxmox.endpoints`, and the
segments that fill it come from a registered ACOP identifier or from Proxmox's
own inventory. There is no branch that takes a path, a host, a credential or a
method from anywhere else, because no such value exists in an
:class:`~acop.tools.adapters.base.AdapterRequest`.

**``validate`` still refuses, permanently.** All ten tools are
``CLASS_1_READ_ONLY``; import rule 2 forces ``validation_required`` only for
Class 2 and Class 3, so no read-only tool sets it and
``ExecutionDispatcher._after_execution`` never calls this. That was true in
Checkpoint 1C when the adapter was inert and it is still true now that it works:
a read makes no change, so there is nothing to independently confirm afterwards.

**The client is built per invocation.** A process-lifetime pool would save a TLS
handshake per call, and it would also need lifespan wiring in
:mod:`acop.main`, a shutdown path, and a decision about what happens to it when
settings are reloaded. For ten read-only tools invoked by a human that is
complexity bought with nothing. When the discovery checkpoint starts sweeping on
a timer, the trade changes and this is the paragraph to revisit - the seam is
already here, in ``client_factory``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from acop.core.logging import get_logger
from acop.models.tool_vocabulary import AdapterOutcome
from acop.tools.adapters.base import AdapterRequest, AdapterResult, register_adapter
from acop.tools.adapters.proxmox import projection
from acop.tools.adapters.proxmox.client import ProxmoxClient
from acop.tools.adapters.proxmox.errors import (
    ProxmoxNotConfiguredError,
    ProxmoxProtocolError,
)
from acop.tools.adapters.proxmox.identity import (
    GUEST_TYPE_LXC,
    GUEST_TYPE_QEMU,
    budget,
    online_nodes,
    require_instance,
    resolve_guest,
    resolve_node,
)
from acop.tools.errors import AdapterUnavailableError

logger = get_logger(__name__)

#: Every tool this adapter implements. A name absent from here is refused
#: loudly by :meth:`ProxmoxAdapter.execute` before anything else happens, which
#: is what makes "unsupported tool name fails loudly" structural rather than a
#: fall-through returning an empty success.
SUPPORTED_TOOLS: frozenset[str] = frozenset(
    {
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
)

ClientFactory = Callable[[Any], ProxmoxClient]


def _default_client_factory(settings: Any) -> ProxmoxClient:
    return ProxmoxClient(settings)


class ProxmoxAdapter:
    """Read-only Proxmox access, bound to ``adapter_id = "proxmox"``.

    A plain class rather than a subclass: ``ToolAdapter`` is a structural
    Protocol, so conformance is by shape, and ``adapter_id`` is a bare class
    attribute because :func:`register_adapter` keys the registry on it.
    """

    adapter_id = "proxmox"

    def __init__(self, client_factory: ClientFactory | None = None) -> None:
        """Args:
        client_factory: Builds the transport from settings. The seam exists
            for tests, which pass a factory returning a
            :class:`~acop.tools.adapters.proxmox.client.ProxmoxClient` over an
            ``httpx.MockTransport`` - so the real request building, error
            translation and envelope parsing run against a scripted upstream
            rather than being replaced by a stub that proves nothing.
        """
        self._client_factory: ClientFactory = client_factory or _default_client_factory

    # ------------------------------------------------------------------
    async def execute(self, request: AdapterRequest) -> AdapterResult:
        """Perform one read and report what was observed.

        Never returns a successful empty result for a failed read. Every failure
        path raises a :class:`~acop.tools.adapters.proxmox.errors.ProxmoxError`
        carrying an existing ``ToolErrorCategory``, which the dispatcher turns
        into ``FAILED`` with that category. An adapter that answered a broken
        read with ``{}`` would be recorded as ``SUCCEEDED`` with an empty
        inventory - the exact false statement ADR-0023 exists to prevent.
        """
        if request.tool_name not in SUPPORTED_TOOLS:
            raise AdapterUnavailableError(
                f"{self.adapter_id} implements no tool named {request.tool_name}. "
                "Only the ten declared read-only capabilities are reachable.",
                context={
                    "adapter_id": self.adapter_id,
                    "tool_name": request.tool_name,
                    "tool_version": request.tool_version,
                },
            )

        settings = request.services.settings
        if settings is None:  # pragma: no cover - the dispatcher always supplies
            raise ProxmoxNotConfiguredError(
                "The adapter was called without ACOP configuration.",
                context={"adapter_id": self.adapter_id},
            )

        deadline = budget(request.timeout_seconds)
        client = self._client_factory(settings)
        try:
            payload = await self._observe(request, client, deadline=deadline)
        finally:
            await client.aclose()

        return AdapterResult(outcome=AdapterOutcome.SUCCESS, payload=payload)

    async def validate(self, request: AdapterRequest) -> AdapterResult:
        """Refuse, and keep refusing. See this module's docstring."""
        raise AdapterUnavailableError(
            f"{self.adapter_id} tools are read-only and make no change, so "
            "there is nothing to validate.",
            context={
                "adapter_id": self.adapter_id,
                "tool_name": request.tool_name,
            },
        )

    # ------------------------------------------------------------------
    async def _observe(
        self, request: AdapterRequest, client: ProxmoxClient, *, deadline: float
    ) -> dict[str, Any]:
        """Route one supported tool to its read. Exhaustive by construction."""
        tool = request.tool_name
        target = request.target
        instance = client.instance_id

        if tool == "proxmox.cluster.status":
            require_instance(target, instance)
            data = await client.get_data(tool, deadline=deadline)
            return projection.cluster_status(data, instance_id=instance)

        if tool == "proxmox.node.list":
            require_instance(target, instance)
            data = await client.get_data(tool, deadline=deadline)
            return projection.node_list(data, instance_id=instance)

        if tool == "proxmox.guest.list":
            require_instance(target, instance)
            data = await client.get_data(tool, deadline=deadline)
            return projection.guest_list(data, instance_id=instance)

        if tool == "proxmox.storage.list":
            return await self._storage(client, request, deadline=deadline)

        if tool in {"proxmox.node.status", "proxmox.node.network"}:
            node = await resolve_node(client, target, instance, deadline=deadline)
            data = await client.get_data(tool, deadline=deadline, node=node)
            if tool == "proxmox.node.status":
                return projection.node_status(data, instance_id=instance, node=node)
            return projection.node_network(data, instance_id=instance, node=node)

        return await self._guest(client, request, deadline=deadline)

    # ------------------------------------------------------------------
    async def _guest(
        self, client: ProxmoxClient, request: AdapterRequest, *, deadline: float
    ) -> dict[str, Any]:
        """The four per-guest reads, all routed by live node resolution.

        The guest technology is a **constant of the tool**, not a caller
        argument: ``proxmox.vm.*`` looks for ``qemu`` and ``proxmox.container.*``
        for ``lxc``. Matching on it as well as the VMID is what stops a container
        from being read through the QEMU endpoint after a VMID was reused across
        technologies - the two share one VMID space.
        """
        tool = request.tool_name
        instance = client.instance_id
        guest_type = GUEST_TYPE_QEMU if tool.startswith("proxmox.vm.") else GUEST_TYPE_LXC

        location = await resolve_guest(
            client,
            request.target,
            instance,
            guest_type=guest_type,
            deadline=deadline,
        )
        data = await client.get_data(
            tool, deadline=deadline, node=location.node, vmid=str(location.vmid)
        )
        node, vmid = location.node, location.vmid
        if tool == "proxmox.vm.status":
            return projection.vm_status(data, instance_id=instance, node=node, vmid=vmid)
        if tool == "proxmox.vm.config":
            return projection.vm_config(data, instance_id=instance, node=node, vmid=vmid)
        if tool == "proxmox.container.status":
            return projection.container_status(
                data, instance_id=instance, node=node, vmid=vmid
            )
        if tool == "proxmox.container.config":
            return projection.container_config(
                data, instance_id=instance, node=node, vmid=vmid
            )
        raise ProxmoxProtocolError(  # pragma: no cover - SUPPORTED_TOOLS is exhaustive
            f"{tool} is supported but unrouted, which is a defect in this adapter.",
            context={"tool_name": tool},
        )

    async def _storage(
        self, client: ProxmoxClient, request: AdapterRequest, *, deadline: float
    ) -> dict[str, Any]:
        """Storage across every online node, as a union carrying the source node.

        ``1 + N`` requests, and the ratified reason for iterating rather than
        picking a node is that ``local`` and ``local-lvm`` are *different
        volumes* on each node under the same name. Reporting one node's figures
        as the instance's would overstate free space by a factor of the cluster
        size, and understate it for anything shared.

        The declared ``timeout_seconds`` on ``proxmox.storage.list`` is set for
        this fan-out, and the client's shared deadline is what keeps the total
        inside it: each request gets whatever is left, and running out produces a
        ``TIMEOUT`` naming the endpoint rather than an outside cancellation that
        names nothing.
        """
        instance = require_instance(request.target, client.instance_id)
        nodes = await online_nodes(client, deadline=deadline)
        rows: list[dict[str, Any]] = []
        for node in nodes:
            data = await client.get_data(
                "proxmox.storage.list", deadline=deadline, node=node
            )
            rows.extend(projection.storage_entries(data, node=node))
        logger.info(
            "proxmox.storage.collected",
            invocation_id=str(request.invocation_id),
            nodes=len(nodes),
            rows=len(rows),
        )
        return projection.storage_list(rows, instance_id=instance, nodes_queried=nodes)


PROXMOX_ADAPTER = register_adapter(ProxmoxAdapter())

__all__ = ["PROXMOX_ADAPTER", "SUPPORTED_TOOLS", "ClientFactory", "ProxmoxAdapter"]
