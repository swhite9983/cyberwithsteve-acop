"""Turning a resolved ACOP target into a trusted Proxmox address.

Nothing here reads caller input. The inputs are a
:class:`~acop.tools.adapters.base.ResolvedTarget` - identifiers ACOP looked up
itself, from rows the dispatcher selected - and live responses from Proxmox. A
caller supplies neither, and the ten Proxmox tools have no input fields at all,
so there is no third source to guard against.

The chain, and why each link is where it is:

1. The caller names an **asset**. Policy has already refused a retired asset or
   one of a type this tool does not accept.
2. The dispatcher hands the adapter that asset's live registered identifiers.
3. This module reads the ``proxmox:*`` one, parses ``<instance>/<object>``, and
   **refuses if the instance segment is not the configured one**. That check
   happens before the first HTTP request, because a VMID that exists on two
   instances would otherwise return a confident answer about the wrong machine.
4. The node that will appear in the URL is then taken from **Proxmox's own
   response**, never from the identifier.

Step 4 is the ratified design for guests, and this module applies the same rule
to nodes. That is a decision worth stating rather than hiding:

    ``AssetIdentifier.value_normalized`` for ``proxmox:node`` is
    ``value.strip().lower()``. Proxmox node names appear **literally** in API
    paths, so an instance whose node is ``PVE-01`` would be addressed as
    ``/nodes/pve-01`` if the identifier were used directly - a request for a node
    that, as far as the API is concerned, does not exist.

The identifier therefore selects *which* node, case-insensitively, and
``GET /api2/json/nodes`` supplies the spelling. One extra request per
node-scoped invocation, in exchange for the same property the guest design
already has: **every path segment ACOP sends came from Proxmox.**

Exactly-one matching is used everywhere. Zero is a target that no longer exists;
more than one is Proxmox reporting something that should be impossible. Both are
refused, and neither is resolved by picking a candidate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Final

from acop.tools.adapters.base import ResolvedTarget
from acop.tools.adapters.proxmox.client import ProxmoxClient
from acop.tools.adapters.proxmox.endpoints import GUEST_INVENTORY, NODE_INVENTORY
from acop.tools.adapters.proxmox.errors import (
    ProxmoxAmbiguousObjectError,
    ProxmoxIdentifierError,
    ProxmoxInstanceMismatchError,
    ProxmoxObjectNotFoundError,
    ProxmoxProtocolError,
)

#: Checkpoint 1C namespaces. Named here so a typo is a NameError at import
#: rather than a lookup that silently finds nothing at runtime.
NS_INSTANCE: Final = "proxmox:instance"
NS_NODE: Final = "proxmox:node"
NS_GUEST: Final = "proxmox:guest"

#: Proxmox's own word for each guest technology, as it appears in the ``type``
#: field of a ``/cluster/resources?type=vm`` record.
GUEST_TYPE_QEMU: Final = "qemu"
GUEST_TYPE_LXC: Final = "lxc"


@dataclass(frozen=True, slots=True)
class GuestLocation:
    """Where a guest is, according to Proxmox, right now."""

    vmid: int
    guest_type: str
    node: str
    record: dict[str, Any]


def _identifier(target: ResolvedTarget, namespace: str) -> str:
    """One registered identifier, or a refusal.

    Refusing rather than falling back is the whole point. An asset the CMDB
    calls a Proxmox guest but which carries no ``proxmox:guest`` identifier
    cannot be addressed, and deriving one from the display name, a fact, or a
    hostname would be exactly the substitution this architecture exists to
    prevent.
    """
    value = target.identifiers.get(namespace, "").strip()
    if not value:
        raise ProxmoxIdentifierError(
            f"The target carries no {namespace} identifier, so ACOP cannot "
            "address it without guessing.",
            context={
                "namespace": namespace,
                "asset_id": str(target.asset_id) if target.asset_id else None,
                # Namespace names only. An identifier value can name
                # infrastructure, and this error is reachable by a caller.
                "namespaces_present": sorted(target.identifiers),
            },
        )
    return value


def _scoped(target: ResolvedTarget, namespace: str, instance_id: str) -> str:
    """Split ``<instance>/<object>`` and verify the instance half.

    Returns:
        The object half, exactly as stored.

    Raises:
        ProxmoxIdentifierError: The value is not a two-part composite.
        ProxmoxInstanceMismatchError: It belongs to another configured instance.
    """
    value = _identifier(target, namespace)
    instance, separator, obj = value.partition("/")
    if not separator or not instance.strip() or not obj or "/" in obj:
        raise ProxmoxIdentifierError(
            f"A {namespace} identifier must be '<instance>/<object>'.",
            context={"namespace": namespace},
        )
    if instance.strip().lower() != instance_id.strip().lower():
        raise ProxmoxInstanceMismatchError(
            f"The target's {namespace} identifier belongs to a different "
            "Proxmox instance than this adapter is configured for.",
            # Both ids are ACOP-owned slugs, not credentials and not
            # infrastructure locators, and an operator needs both to see what
            # went wrong.
            context={
                "namespace": namespace,
                "identifier_instance": instance,
                "configured_instance": instance_id,
            },
        )
    return obj


def require_instance(target: ResolvedTarget, instance_id: str) -> str:
    """Verify a cluster-scoped target names this instance, and return its id.

    ``proxmox.cluster.status``, ``proxmox.node.list``, ``proxmox.guest.list`` and
    ``proxmox.storage.list`` act on the instance as a whole, so their target is
    the ``CLUSTER`` asset carrying ``proxmox:instance``. Without this check any
    cluster asset - including one correlated to a second Proxmox instance -
    would read against whichever base URL this process happens to hold.
    """
    value = _identifier(target, NS_INSTANCE)
    if value.strip().lower() != instance_id.strip().lower():
        raise ProxmoxInstanceMismatchError(
            "The target names a different Proxmox instance than this adapter is "
            "configured for.",
            context={
                "identifier_instance": value,
                "configured_instance": instance_id,
            },
        )
    return instance_id


def parse_vmid(target: ResolvedTarget, instance_id: str) -> int:
    """The VMID from ``proxmox:guest``, after the instance check.

    Raises:
        ProxmoxIdentifierError: The object half is not a positive integer.
    """
    raw = _scoped(target, NS_GUEST, instance_id)
    if not raw.isdigit() or raw.startswith("0"):
        raise ProxmoxIdentifierError(
            "A proxmox:guest identifier must end in a VMID.",
            context={"namespace": NS_GUEST},
        )
    return int(raw)


def _records(data: Any, path_hint: str) -> list[dict[str, Any]]:
    """A Proxmox collection response as a list of mappings, or a refusal."""
    if not isinstance(data, list):
        raise ProxmoxProtocolError(
            f"Proxmox returned a {type(data).__name__} where {path_hint} must be a list.",
            context={"endpoint": path_hint},
        )
    records: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ProxmoxProtocolError(
                f"A {path_hint} entry was not an object.",
                context={"endpoint": path_hint},
            )
        records.append(entry)
    return records


async def online_nodes(client: ProxmoxClient, *, deadline: float) -> list[str]:
    """Every online node's name, spelled as Proxmox spells it.

    ``status == "online"`` rather than "every node in the list": an offline node
    answers nothing, and including it would turn one unreachable member into a
    failed invocation for the whole cluster.
    """
    data = await client.get_data(NODE_INVENTORY, deadline=deadline)
    names: list[str] = []
    for record in _records(data, NODE_INVENTORY):
        name = str(record.get("node") or "").strip()
        if not name:
            raise ProxmoxProtocolError(
                "A node inventory record carried no node name.",
                context={"endpoint": NODE_INVENTORY},
            )
        if str(record.get("status") or "").strip().lower() == "online":
            names.append(name)
    return names


async def resolve_node(
    client: ProxmoxClient,
    target: ResolvedTarget,
    instance_id: str,
    *,
    deadline: float,
) -> str:
    """The node name to put in a URL, taken from Proxmox's own inventory.

    The registered ``proxmox:node`` identifier selects which node; the live
    listing supplies the spelling. See this module's docstring for why the
    identifier's own value cannot be used: it is case-folded by
    ``AssetIdentifier`` normalisation and Proxmox node names are used literally
    in API paths.
    """
    wanted = _scoped(target, NS_NODE, instance_id).strip().lower()
    data = await client.get_data(NODE_INVENTORY, deadline=deadline)
    matches = [
        str(record.get("node") or "").strip()
        for record in _records(data, NODE_INVENTORY)
        if str(record.get("node") or "").strip().lower() == wanted
    ]
    if not matches:
        raise ProxmoxObjectNotFoundError(
            "Proxmox reports no node matching this target's identifier.",
            context={"namespace": NS_NODE},
        )
    if len(matches) > 1:
        raise ProxmoxAmbiguousObjectError(
            "Proxmox reported more than one node with the same name.",
            context={"namespace": NS_NODE, "matches": len(matches)},
        )
    return matches[0]


async def resolve_guest(
    client: ProxmoxClient,
    target: ResolvedTarget,
    instance_id: str,
    *,
    guest_type: str,
    deadline: float,
) -> GuestLocation:
    """Locate a guest live, and take its node from the inventory record.

    Implements the ratified ten-step algorithm. Steps (a) to (e) - resolve the
    asset, read ``proxmox:guest``, parse ``<instance>/<vmid>``, verify the
    instance, fail before any HTTP request on mismatch - have already happened by
    the time the first request in this function is issued, because
    :func:`parse_vmid` runs first and raises.

    ``guest_type`` is a **constant from the tool declaration**, not caller input:
    ``proxmox.vm.*`` passes ``qemu`` and ``proxmox.container.*`` passes ``lxc``.
    Matching on it as well as the VMID is what stops a container from being read
    through the QEMU endpoint after a VMID was reused across technologies.

    Reading the node live rather than from a stored ``RUNS_ON`` edge is the point
    of the design: a guest that migrated since the last discovery sweep routes
    correctly on the first call instead of after the next one. On a standalone
    node that is theoretical; it stops being theoretical the day a second node
    joins, and the cost of being right now is one request that was going to be
    made anyway for ``proxmox.guest.list``.
    """
    vmid = parse_vmid(target, instance_id)
    data = await client.get_data(GUEST_INVENTORY, deadline=deadline)
    matches: list[dict[str, Any]] = []
    for record in _records(data, GUEST_INVENTORY):
        if str(record.get("type") or "").strip().lower() != guest_type:
            continue
        raw_vmid = record.get("vmid")
        if not isinstance(raw_vmid, int) or isinstance(raw_vmid, bool):
            try:
                raw_vmid = int(str(raw_vmid))
            except (TypeError, ValueError):
                continue
        if raw_vmid == vmid:
            matches.append(record)

    if not matches:
        raise ProxmoxObjectNotFoundError(
            "Proxmox live inventory contains no guest with this VMID and type.",
            context={"vmid": vmid, "guest_type": guest_type},
        )
    if len(matches) > 1:
        raise ProxmoxAmbiguousObjectError(
            "Proxmox reported more than one guest with the same VMID and type. "
            "ACOP will not choose between them.",
            context={"vmid": vmid, "guest_type": guest_type, "matches": len(matches)},
        )

    record = matches[0]
    node = str(record.get("node") or "").strip()
    if not node:
        raise ProxmoxProtocolError(
            "The guest inventory record carried no node, so ACOP cannot route the read.",
            context={"vmid": vmid, "guest_type": guest_type},
        )
    return GuestLocation(vmid=vmid, guest_type=guest_type, node=node, record=record)


def budget(timeout_seconds: float) -> float:
    """A monotonic deadline for one invocation's whole Proxmox conversation."""
    return time.monotonic() + float(timeout_seconds)


__all__ = [
    "GUEST_TYPE_LXC",
    "GUEST_TYPE_QEMU",
    "NS_GUEST",
    "NS_INSTANCE",
    "NS_NODE",
    "GuestLocation",
    "budget",
    "online_nodes",
    "parse_vmid",
    "require_instance",
    "resolve_guest",
    "resolve_node",
]
