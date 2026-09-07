"""Proxmox JSON to ACOP output. The narrowing happens here.

Ten functions, one per tool, each turning an upstream response into the exact
mapping the tool's declared ``output_model`` accepts. Nothing else crosses:
a field that is not named in a projection cannot reach ``result_summary``, and a
field that is named but absent upstream becomes ``None`` rather than being
invented.

**Why the adapter returns plain mappings rather than model instances.** That is
the Milestone 4 contract, followed rather than worked around: an adapter reports
what it observed, and the *framework* puts that report through the tool's
declared model in ``ExecutionDispatcher._declared_output``. An adapter that
validated its own output would be marking its own homework, and under ADR-0023
the framework's check is what turns a drifted projection into a failed
invocation instead of a silently empty success. A unit test closes the gap the
other way, by running every projection in this module over captured fixtures and
validating the result against the declared model.

**Coercion is deliberate and narrow.** The Proxmox API returns booleans as ``0``
and ``1``, and numbers sometimes as strings. :func:`_as_bool`, :func:`_as_int`
and :func:`_as_float` accept those forms and answer ``None`` for anything else -
never a default, never a zero. ``None`` means "Proxmox did not tell us", which
is a different statement from ``0`` and is one the discovery checkpoint will
need to keep apart.

**Where a projection raises.** Only where a field the *routing* depends on is
missing - a guest record with no node, a storage record with no id. Those are
``ProxmoxProtocolError``, so the invocation fails as "the upstream answered
wrongly" rather than as ``OUTPUT_CONTRACT_VIOLATION``, which ADR-0023 reserves
for ACOP's own code being wrong. Everything else degrades to ``None``.
"""

from __future__ import annotations

import uuid as uuid_module
from datetime import UTC, datetime
from typing import Any

from acop.tools.adapters.proxmox.errors import ProxmoxProtocolError

# ---------------------------------------------------------------------------
# Coercion
# ---------------------------------------------------------------------------


def _as_str(value: Any) -> str | None:
    """A non-empty string, or ``None``. Never the string ``"None"``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _as_bool(value: Any) -> bool | None:
    """Proxmox's ``0``/``1`` as a boolean, or ``None``.

    ``None`` rather than ``False`` for an absent flag. "Proxmox did not say" and
    "Proxmox said no" are different facts, and collapsing them here would make
    every unset flag look like a deliberate negative to whatever reads the
    stored result later.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    return None


def _now() -> datetime:
    return datetime.now(UTC)


def _record(entry: Any, endpoint: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise ProxmoxProtocolError(
            f"Proxmox returned a {type(entry).__name__} where {endpoint} must be "
            "an object.",
            context={"endpoint": endpoint},
        )
    return entry


def _nested(record: dict[str, Any], key: str) -> dict[str, Any]:
    """A nested object from a response, or an empty one.

    Empty rather than raising, because every field these feed is optional: a
    response whose shape differs from the documented one degrades to ``None``
    values instead of failing an invocation. That is the right severity for a
    read - fewer fields than hoped is still a true statement.
    """
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _entries(data: Any, endpoint: str) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise ProxmoxProtocolError(
            f"Proxmox returned a {type(data).__name__} where {endpoint} must be a list.",
            context={"endpoint": endpoint},
        )
    return [_record(entry, endpoint) for entry in data]


def _key_values(line: Any) -> dict[str, str]:
    """Parse a Proxmox ``key=value,key=value`` config line.

    Used for ``smbios1`` and ``meta``. Tolerant by design: an unparseable
    fragment is skipped rather than failing the read, because these lines are
    free-form and a future Proxmox may add a key in a shape this does not
    anticipate. Nothing downstream is required, so skipping degrades to ``None``.
    """
    text = _as_str(line)
    if text is None:
        return {}
    parsed: dict[str, str] = {}
    for fragment in text.split(","):
        key, separator, value = fragment.partition("=")
        if separator and key.strip():
            parsed[key.strip().lower()] = value.strip()
    return parsed


def _uuid_or_none(value: str | None) -> str | None:
    """A canonical UUID string, or ``None``. Never a partially valid one."""
    if not value:
        return None
    try:
        return str(uuid_module.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _epoch_or_none(value: str | None) -> datetime | None:
    seconds = _as_int(value)
    if seconds is None or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------


def cluster_status(data: Any, *, instance_id: str) -> dict[str, Any]:
    """``/cluster/status`` to :class:`ClusterStatusOut`.

    ``standalone`` is derived from the absence of a ``type: "cluster"`` member,
    which is exactly what the verified lab response looks like. The cluster
    name and quorum come from that member when it exists and stay ``None`` when
    it does not, so a standalone install is a first-class success rather than a
    degraded one.
    """
    entries = _entries(data, "/cluster/status")
    members: list[dict[str, Any]] = []
    cluster_name: str | None = None
    quorate: bool | None = None
    standalone = True

    for entry in entries:
        member_type = _as_str(entry.get("type")) or "unknown"
        if member_type == "cluster":
            standalone = False
            cluster_name = _as_str(entry.get("name"))
            quorate = _as_bool(entry.get("quorate"))
        members.append(
            {
                "id": _as_str(entry.get("id")) or f"{member_type}/unknown",
                "type": member_type,
                "name": _as_str(entry.get("name")),
                "node": _as_str(entry.get("name")) if member_type == "node" else None,
                "ip": _as_str(entry.get("ip")),
                "node_id": _as_int(entry.get("nodeid")),
                "online": _as_bool(entry.get("online")),
                "local": _as_bool(entry.get("local")),
                "quorate": _as_bool(entry.get("quorate")),
                "member_count": _as_int(entry.get("nodes")),
            }
        )

    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "standalone": standalone,
        "cluster_name": cluster_name,
        "quorate": quorate,
        "members": members,
    }


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def node_list(data: Any, *, instance_id: str) -> dict[str, Any]:
    """``/nodes`` to :class:`NodeListOut`."""
    nodes: list[dict[str, Any]] = []
    for entry in _entries(data, "/nodes"):
        name = _as_str(entry.get("node"))
        if name is None:
            raise ProxmoxProtocolError(
                "A node inventory record carried no node name.",
                context={"endpoint": "/nodes"},
            )
        nodes.append(
            {
                "node": name,
                "status": _as_str(entry.get("status")),
                "type": _as_str(entry.get("type")),
                "uptime_seconds": _as_int(entry.get("uptime")),
                "cpu_usage": _as_float(entry.get("cpu")),
                "cpu_count": _as_int(entry.get("maxcpu")),
                "memory_used_bytes": _as_int(entry.get("mem")),
                "memory_total_bytes": _as_int(entry.get("maxmem")),
                "disk_used_bytes": _as_int(entry.get("disk")),
                "disk_total_bytes": _as_int(entry.get("maxdisk")),
                "ssl_fingerprint": _as_str(
                    entry.get("ssl_fingerprint") or entry.get("fingerprint")
                ),
            }
        )
    return {"instance_id": instance_id, "observed_at": _now(), "nodes": nodes}


def node_status(data: Any, *, instance_id: str, node: str) -> dict[str, Any]:
    """``/nodes/{node}/status`` to :class:`NodeStatusOut`.

    Nested objects (``cpuinfo``, ``memory``, ``swap``, ``rootfs``) are read
    defensively: this endpoint was not captured during Checkpoint 0, so a shape
    that differs from the documented one degrades to ``None`` rather than
    raising. That is the right severity - a node status read that returns fewer
    fields than hoped is still a true statement, whereas a failed invocation
    would be a false one.
    """
    record = _record(data, "/nodes/{node}/status")
    cpuinfo = _nested(record, "cpuinfo")
    memory = _nested(record, "memory")
    swap = _nested(record, "swap")
    rootfs = _nested(record, "rootfs")

    load_raw = record.get("loadavg")
    load: list[float] | None = None
    if isinstance(load_raw, list):
        parsed = [_as_float(item) for item in load_raw]
        load = [item for item in parsed if item is not None] or None

    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "uptime_seconds": _as_int(record.get("uptime")),
        "cpu_usage": _as_float(record.get("cpu")),
        "cpu_count": _as_int(cpuinfo.get("cpus")),
        "cpu_sockets": _as_int(cpuinfo.get("sockets")),
        "cpu_model": _as_str(cpuinfo.get("model")),
        "load_average": load,
        "memory_total_bytes": _as_int(memory.get("total")),
        "memory_used_bytes": _as_int(memory.get("used")),
        "memory_free_bytes": _as_int(memory.get("free")),
        "swap_total_bytes": _as_int(swap.get("total")),
        "swap_used_bytes": _as_int(swap.get("used")),
        "rootfs_total_bytes": _as_int(rootfs.get("total")),
        "rootfs_used_bytes": _as_int(rootfs.get("used")),
        "rootfs_available_bytes": _as_int(rootfs.get("avail")),
        "pve_version": _as_str(record.get("pveversion")),
        "kernel_version": _as_str(record.get("current-kernel") or record.get("kversion")),
    }


def node_network(data: Any, *, instance_id: str, node: str) -> dict[str, Any]:
    """``/nodes/{node}/network`` to :class:`NodeNetworkOut`."""
    interfaces: list[dict[str, Any]] = []
    for entry in _entries(data, "/nodes/{node}/network"):
        iface = _as_str(entry.get("iface"))
        if iface is None:
            raise ProxmoxProtocolError(
                "A network record carried no interface name.",
                context={"endpoint": "/nodes/{node}/network"},
            )
        interfaces.append(
            {
                "iface": iface,
                "type": _as_str(entry.get("type")),
                "method": _as_str(entry.get("method")),
                "active": _as_bool(entry.get("active")),
                "autostart": _as_bool(entry.get("autostart")),
                "address": _as_str(entry.get("address")),
                "netmask": _as_str(entry.get("netmask")),
                "cidr": _as_str(entry.get("cidr")),
                "gateway": _as_str(entry.get("gateway")),
                "bridge_ports": _as_str(entry.get("bridge_ports")),
            }
        )
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "interfaces": interfaces,
    }


# ---------------------------------------------------------------------------
# Guests
# ---------------------------------------------------------------------------


def guest_list(data: Any, *, instance_id: str) -> dict[str, Any]:
    """``/cluster/resources?type=vm`` to :class:`GuestListOut`.

    The three fields that raise rather than degrade - ``vmid``, ``type`` and
    ``node`` - are the ones the adapter's own routing reads out of this same
    response. A record missing any of them is not a guest ACOP can address, and
    quietly dropping it would make the inventory silently short, which is the
    exact failure mode the discovery checkpoint's absence pass turns into mass
    retirement.
    """
    guests: list[dict[str, Any]] = []
    for entry in _entries(data, "/cluster/resources"):
        vmid = _as_int(entry.get("vmid"))
        guest_type = _as_str(entry.get("type"))
        node = _as_str(entry.get("node"))
        if vmid is None or guest_type is None or node is None:
            raise ProxmoxProtocolError(
                "A guest inventory record was missing its vmid, type or node.",
                context={
                    "endpoint": "/cluster/resources",
                    "vmid_present": vmid is not None,
                    "type_present": guest_type is not None,
                    "node_present": node is not None,
                },
            )
        guests.append(
            {
                "vmid": vmid,
                "guest_type": guest_type,
                "node": node,
                "name": _as_str(entry.get("name")),
                "status": _as_str(entry.get("status")),
                "uptime_seconds": _as_int(entry.get("uptime")),
                "template": _as_bool(entry.get("template")),
                "cpu_usage": _as_float(entry.get("cpu")),
                "cpu_count": _as_int(entry.get("maxcpu")),
                "memory_used_bytes": _as_int(entry.get("mem")),
                "memory_total_bytes": _as_int(entry.get("maxmem")),
                "disk_used_bytes": _as_int(entry.get("disk")),
                "disk_total_bytes": _as_int(entry.get("maxdisk")),
                "pool": _as_str(entry.get("pool")),
                "tags": _as_str(entry.get("tags")),
            }
        )
    return {"instance_id": instance_id, "observed_at": _now(), "guests": guests}


def vm_status(data: Any, *, instance_id: str, node: str, vmid: int) -> dict[str, Any]:
    """``/nodes/{node}/qemu/{vmid}/status/current`` to :class:`VmStatusOut`.

    ``node`` and ``vmid`` come from ACOP's own resolution rather than from the
    response, because they are what the request was *for*. Taking them from the
    body would mean a mislabelled response could relabel the result.
    """
    record = _record(data, "/nodes/{node}/qemu/{vmid}/status/current")
    agent = record.get("agent")
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "vmid": vmid,
        "name": _as_str(record.get("name")),
        "status": _as_str(record.get("status")),
        "qmp_status": _as_str(record.get("qmpstatus")),
        "uptime_seconds": _as_int(record.get("uptime")),
        "cpu_usage": _as_float(record.get("cpu")),
        "cpu_count": _as_int(record.get("cpus")),
        "memory_used_bytes": _as_int(record.get("mem")),
        "memory_total_bytes": _as_int(record.get("maxmem")),
        "disk_total_bytes": _as_int(record.get("maxdisk")),
        "running_machine": _as_str(record.get("running-machine")),
        "running_qemu": _as_str(record.get("running-qemu")),
        "agent_enabled": _as_bool(agent) if agent is not None else None,
        "template": _as_bool(record.get("template")),
        "tags": _as_str(record.get("tags")),
    }


def vm_config(data: Any, *, instance_id: str, node: str, vmid: int) -> dict[str, Any]:
    """``/nodes/{node}/qemu/{vmid}/config`` to :class:`VmConfigOut`.

    The SMBIOS UUID is the one field here with real identity weight, and it is
    treated accordingly: parsed out of the ``smbios1`` line, validated as a UUID,
    and answered as ``None`` if either step fails. A VM whose UUID ACOP cannot
    read is a VM with no strong correlator, which the identity design already
    accounts for - it is not an invitation to fall back to something weaker.

    Disk and network device lines are not read at all. They carry storage volume
    paths and MAC addresses, and both belong to decisions this checkpoint is
    explicitly not making.
    """
    record = _record(data, "/nodes/{node}/qemu/{vmid}/config")
    smbios = _key_values(record.get("smbios1"))
    meta = _key_values(record.get("meta"))
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "vmid": vmid,
        "name": _as_str(record.get("name")),
        "config_digest": _as_str(record.get("digest")),
        "smbios_uuid": _uuid_or_none(smbios.get("uuid")),
        "vmgenid": _as_str(record.get("vmgenid")),
        "creation_qemu_version": meta.get("creation-qemu") or None,
        "created_at": _epoch_or_none(meta.get("ctime")),
        "machine": _as_str(record.get("machine")),
        "bios": _as_str(record.get("bios")),
        "os_type": _as_str(record.get("ostype")),
        "cpu_type": _as_str(record.get("cpu")),
        "cores": _as_int(record.get("cores")),
        "sockets": _as_int(record.get("sockets")),
        "memory_mb": _as_int(record.get("memory")),
        "boot_order": _as_str(record.get("boot")),
        "agent": _as_str(record.get("agent")),
        "protection": _as_bool(record.get("protection")),
        "template": _as_bool(record.get("template")),
        "tags": _as_str(record.get("tags")),
    }


def container_status(
    data: Any, *, instance_id: str, node: str, vmid: int
) -> dict[str, Any]:
    """``/nodes/{node}/lxc/{vmid}/status/current`` to :class:`ContainerStatusOut`."""
    record = _record(data, "/nodes/{node}/lxc/{vmid}/status/current")
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "vmid": vmid,
        "name": _as_str(record.get("name")),
        "status": _as_str(record.get("status")),
        "uptime_seconds": _as_int(record.get("uptime")),
        "cpu_usage": _as_float(record.get("cpu")),
        "cpu_count": _as_int(record.get("cpus")),
        "memory_used_bytes": _as_int(record.get("mem")),
        "memory_total_bytes": _as_int(record.get("maxmem")),
        "swap_used_bytes": _as_int(record.get("swap")),
        "swap_total_bytes": _as_int(record.get("maxswap")),
        "disk_used_bytes": _as_int(record.get("disk")),
        "disk_total_bytes": _as_int(record.get("maxdisk")),
        "template": _as_bool(record.get("template")),
        "tags": _as_str(record.get("tags")),
    }


def container_config(
    data: Any, *, instance_id: str, node: str, vmid: int
) -> dict[str, Any]:
    """``/nodes/{node}/lxc/{vmid}/config`` to :class:`ContainerConfigOut`.

    Nothing in this function reads ``hostname``, ``net*``, ``rootfs`` or a MAC as
    identity, and nothing synthesises a UUID. ``config_digest`` is carried as a
    change detector: it answers "has this configuration changed since we last
    looked", and it cannot answer "is this the same container", because two
    identically configured containers share it.
    """
    record = _record(data, "/nodes/{node}/lxc/{vmid}/config")
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "node": node,
        "vmid": vmid,
        "hostname": _as_str(record.get("hostname")),
        "config_digest": _as_str(record.get("digest")),
        "os_type": _as_str(record.get("ostype")),
        "architecture": _as_str(record.get("arch")),
        "cores": _as_int(record.get("cores")),
        "memory_mb": _as_int(record.get("memory")),
        "swap_mb": _as_int(record.get("swap")),
        "unprivileged": _as_bool(record.get("unprivileged")),
        "protection": _as_bool(record.get("protection")),
        "start_on_boot": _as_bool(record.get("onboot")),
        "tags": _as_str(record.get("tags")),
    }


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def storage_entries(data: Any, *, node: str) -> list[dict[str, Any]]:
    """One node's ``/nodes/{node}/storage`` rows, tagged with that node.

    Returns a list rather than a whole output document because the tool's answer
    is the union across nodes; :func:`storage_list` assembles it.
    """
    rows: list[dict[str, Any]] = []
    for entry in _entries(data, "/nodes/{node}/storage"):
        storage = _as_str(entry.get("storage"))
        if storage is None:
            raise ProxmoxProtocolError(
                "A storage record carried no storage id.",
                context={"endpoint": "/nodes/{node}/storage", "node": node},
            )
        rows.append(
            {
                "node": node,
                "storage": storage,
                "storage_type": _as_str(entry.get("type")),
                "content": _as_str(entry.get("content")),
                "active": _as_bool(entry.get("active")),
                "enabled": _as_bool(entry.get("enabled")),
                "shared": _as_bool(entry.get("shared")),
                "total_bytes": _as_int(entry.get("total")),
                "used_bytes": _as_int(entry.get("used")),
                "available_bytes": _as_int(entry.get("avail")),
                "used_fraction": _as_float(entry.get("used_fraction")),
            }
        )
    return rows


def storage_list(
    rows: list[dict[str, Any]], *, instance_id: str, nodes_queried: list[str]
) -> dict[str, Any]:
    """Assemble the per-node rows into :class:`StorageListOut`."""
    return {
        "instance_id": instance_id,
        "observed_at": _now(),
        "nodes_queried": list(nodes_queried),
        "storages": rows,
    }


__all__ = [
    "cluster_status",
    "container_config",
    "container_status",
    "guest_list",
    "node_list",
    "node_network",
    "node_status",
    "storage_entries",
    "storage_list",
    "vm_config",
    "vm_status",
]
