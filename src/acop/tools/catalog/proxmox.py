"""The ten Proxmox read-only capabilities.

``git log src/acop/tools/catalog/`` remains the complete capability change
history, and this file is the whole of what Milestone 5 adds to it: ten reads,
no writes, and no eleventh tool that could become one.

**What is absent is the design.** There is no ``proxmox.api.get``, and that is
not "not yet" - an arbitrary-path read tool would take a locator from a caller
through a field import rules 9, 10 and 11 do not inspect, and would undo the
static proof those rules exist to give. There is no start, stop, reboot,
shutdown, snapshot, migrate, clone or configuration change, because every one of
them is a Class 2 or Class 3 capability and this checkpoint declares none. There
is no shell, no SSH and no ``pvesh``: the prohibition registry refuses those as
*categories* at import, so a future declaration whose honest tag set includes
``arbitrary.shell`` fails the build rather than review.

**Every declaration below is built through :func:`_read_only`.** The fields that
must be identical across all ten - the permission class, the adapter, the
minimum role, no approval, no validation, natural idempotency - are set once
there rather than copied ten times. Ten copies is ten chances for one of them to
drift, and the one that drifts is the one nobody notices.

**Every input model is** :class:`~acop.tools.catalog.schemas.EmptyInput` - a
model with no fields. A caller supplies nothing at all: not a node, not a VMID,
not a path, not a filter. What to read comes from the tool name; what to read it
*from* comes from the resolved target's registered identifiers and from ACOP's
own configuration. See ``docs/proxmox/proxmox-transport.md``.

**Timeouts are declared per fan-out, not per taste.** With the default
``ACOP_PROXMOX_TIMEOUT_SECONDS`` of 15s: a single-request tool gets 20s; a tool
that must first resolve a node or a guest makes two requests and gets 35s;
``proxmox.storage.list`` makes ``1 + N`` and gets 90s, which covers a five-node
instance in the pathological case where every request uses its full timeout.
The adapter shares one deadline across the whole invocation, so exceeding the
budget produces a ``TIMEOUT`` that names the endpoint rather than an outside
cancellation that names nothing.
"""

from __future__ import annotations

from pydantic import BaseModel

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import IdempotencyKind, TargetKind, ToolErrorCategory
from acop.models.vocabulary import AssetType
from acop.tools.catalog.proxmox_schemas import (
    ClusterStatusOut,
    ContainerConfigOut,
    ContainerStatusOut,
    GuestListOut,
    NodeListOut,
    NodeNetworkOut,
    NodeStatusOut,
    StorageListOut,
    VmConfigOut,
    VmStatusOut,
)
from acop.tools.catalog.schemas import EmptyInput
from acop.tools.contract import RetryPolicy, ToolDefinition
from acop.tools.registry import register

#: Retry only where "it did not happen" is knowable. Import rule 8 refuses
#: anything wider, and a read that timed out is deliberately not retried: the
#: framework's timeout rule is one rule rather than one per permission class.
_RETRY = RetryPolicy(
    max_attempts=2,
    retry_on=frozenset(
        {
            ToolErrorCategory.ADAPTER_UNAVAILABLE,
            ToolErrorCategory.TARGET_UNAVAILABLE,
        }
    ),
)

#: One request. Resolution is not needed because the target is the instance.
_TIMEOUT_DIRECT = 20.0

#: Two requests: one to resolve the node or guest from live inventory, one to
#: perform the read. See ``identity.py`` for why the node is never taken from
#: the identifier itself.
_TIMEOUT_RESOLVED = 35.0

#: ``1 + N``. Sized for five online nodes at the default per-request timeout.
_TIMEOUT_FANOUT = 90.0


def _read_only(
    *,
    tool_name: str,
    description: str,
    output_model: type[BaseModel],
    asset_types: frozenset[str],
    capability_tags: frozenset[str],
    timeout_seconds: float,
) -> ToolDefinition:
    """Build one Class 1 Proxmox declaration.

    Everything this function pins is a property that must hold for all ten:

    * ``CLASS_1_READ_ONLY`` — the only class Milestone 5 declares.
    * ``TargetKind.ASSET`` — never ``EXTERNAL_REF``. Backlog B-11 records that
      ``target_ref`` is free-form and unprotected by the input rules, so no tool
      may use it until that is closed; a Class 1 read is not the place to spend
      that exemption.
    * ``adapter_id="proxmox"`` — resolved at import by rule 13.
    * ``{viewer}`` — the class minimum. Reading an inventory is not a privileged
      act, and raising the config reads to ``operator`` would conflate "may
      change" with "may see detail", which is the distinction Milestone 3 already
      drew for approval authority.
    * No approval policy and ``validation_required=False`` — import rule 2 forces
      both only for Class 2 and Class 3, and a read has no change to confirm.
    * ``NATURALLY_IDEMPOTENT`` with an idempotent adapter — repetition observes,
      it does not act.
    """
    return register(
        ToolDefinition(
            tool_name=tool_name,
            tool_version="1.0",
            permission_class=PermissionClass.CLASS_1_READ_ONLY,
            description=description,
            input_model=EmptyInput,
            output_model=output_model,
            adapter_id="proxmox",
            required_roles=frozenset({Role.VIEWER.value}),
            target_type=TargetKind.ASSET,
            target_asset_types=asset_types,
            capability_tags=capability_tags,
            timeout_seconds=timeout_seconds,
            idempotency=IdempotencyKind.NATURALLY_IDEMPOTENT,
            adapter_idempotent=True,
            retry_policy=_RETRY,
            sensitivity=Sensitivity.INTERNAL,
        )
    )


_CLUSTER = frozenset({AssetType.CLUSTER.value})
_HOST = frozenset({AssetType.HOST.value})
_VM = frozenset({AssetType.VM.value})
_CONTAINER = frozenset({AssetType.CONTAINER.value})


# ---------------------------------------------------------------------------
# Instance-scoped: the target is the CLUSTER asset carrying proxmox:instance
# ---------------------------------------------------------------------------

PROXMOX_CLUSTER_STATUS = _read_only(
    tool_name="proxmox.cluster.status",
    description=(
        "Report the Proxmox instance's own cluster membership and quorum state, "
        "including whether it is a standalone node."
    ),
    output_model=ClusterStatusOut,
    asset_types=_CLUSTER,
    capability_tags=frozenset({"proxmox.read", "cluster.status"}),
    timeout_seconds=_TIMEOUT_DIRECT,
)

PROXMOX_NODE_LIST = _read_only(
    tool_name="proxmox.node.list",
    description="List the nodes of a Proxmox instance with their coarse health.",
    output_model=NodeListOut,
    asset_types=_CLUSTER,
    capability_tags=frozenset({"proxmox.read", "node.inventory"}),
    timeout_seconds=_TIMEOUT_DIRECT,
)

PROXMOX_GUEST_LIST = _read_only(
    tool_name="proxmox.guest.list",
    description=(
        "List every guest on a Proxmox instance, QEMU and LXC together, with the "
        "node each one is running on."
    ),
    output_model=GuestListOut,
    asset_types=_CLUSTER,
    capability_tags=frozenset({"proxmox.read", "guest.inventory"}),
    timeout_seconds=_TIMEOUT_DIRECT,
)

PROXMOX_STORAGE_LIST = _read_only(
    tool_name="proxmox.storage.list",
    description=(
        "List storage as each online node sees it, carrying the source node so "
        "node-local and shared definitions stay distinguishable."
    ),
    output_model=StorageListOut,
    asset_types=_CLUSTER,
    capability_tags=frozenset({"proxmox.read", "storage.inventory"}),
    timeout_seconds=_TIMEOUT_FANOUT,
)


# ---------------------------------------------------------------------------
# Node-scoped: the target is the HOST asset carrying proxmox:node
# ---------------------------------------------------------------------------

PROXMOX_NODE_STATUS = _read_only(
    tool_name="proxmox.node.status",
    description="Report one Proxmox node's resource usage and software versions.",
    output_model=NodeStatusOut,
    asset_types=_HOST,
    capability_tags=frozenset({"proxmox.read", "node.status"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)

PROXMOX_NODE_NETWORK = _read_only(
    tool_name="proxmox.node.network",
    description="Report one Proxmox node's network interfaces, bridges and addresses.",
    output_model=NodeNetworkOut,
    asset_types=_HOST,
    capability_tags=frozenset({"proxmox.read", "network.read"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)


# ---------------------------------------------------------------------------
# Guest-scoped: the target is the VM or CONTAINER asset carrying proxmox:guest
# ---------------------------------------------------------------------------

PROXMOX_VM_STATUS = _read_only(
    tool_name="proxmox.vm.status",
    description="Report one QEMU guest's current run state and resource usage.",
    output_model=VmStatusOut,
    asset_types=_VM,
    capability_tags=frozenset({"proxmox.read", "vm.status"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)

PROXMOX_VM_CONFIG = _read_only(
    tool_name="proxmox.vm.config",
    description=(
        "Report one QEMU guest's configuration, including its SMBIOS UUID, "
        "vmgenid and configuration digest where Proxmox provides them."
    ),
    output_model=VmConfigOut,
    asset_types=_VM,
    capability_tags=frozenset({"proxmox.read", "vm.config.read"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)

PROXMOX_CONTAINER_STATUS = _read_only(
    tool_name="proxmox.container.status",
    description="Report one LXC container's current run state and resource usage.",
    output_model=ContainerStatusOut,
    asset_types=_CONTAINER,
    capability_tags=frozenset({"proxmox.read", "container.status"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)

PROXMOX_CONTAINER_CONFIG = _read_only(
    tool_name="proxmox.container.config",
    description=(
        "Report one LXC container's configuration. LXC exposes no durable "
        "lifecycle identifier and ACOP does not invent one."
    ),
    output_model=ContainerConfigOut,
    asset_types=_CONTAINER,
    capability_tags=frozenset({"proxmox.read", "container.config.read"}),
    timeout_seconds=_TIMEOUT_RESOLVED,
)


#: The ten, in the order the approved surface lists them.
PROXMOX_TOOLS = (
    PROXMOX_CLUSTER_STATUS,
    PROXMOX_NODE_LIST,
    PROXMOX_NODE_STATUS,
    PROXMOX_NODE_NETWORK,
    PROXMOX_GUEST_LIST,
    PROXMOX_VM_STATUS,
    PROXMOX_VM_CONFIG,
    PROXMOX_CONTAINER_STATUS,
    PROXMOX_CONTAINER_CONFIG,
    PROXMOX_STORAGE_LIST,
)

__all__ = [
    "PROXMOX_CLUSTER_STATUS",
    "PROXMOX_CONTAINER_CONFIG",
    "PROXMOX_CONTAINER_STATUS",
    "PROXMOX_GUEST_LIST",
    "PROXMOX_NODE_LIST",
    "PROXMOX_NODE_NETWORK",
    "PROXMOX_NODE_STATUS",
    "PROXMOX_STORAGE_LIST",
    "PROXMOX_TOOLS",
    "PROXMOX_VM_CONFIG",
    "PROXMOX_VM_STATUS",
]
