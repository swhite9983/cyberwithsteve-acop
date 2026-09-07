"""Input and output models for the ten Proxmox read-only tools.

**Every one of the ten takes**
:class:`~acop.tools.catalog.schemas.EmptyInput` — a model with no declared
fields at all. That is a stronger statement than "no forbidden field names":
import rules 9, 10 and 11 refuse a schema that *names* a locator, a secret or a
command, but a schema with no fields cannot name anything, and ``extra="forbid"``
turns any attempt to supply ``node``, ``vmid``, ``endpoint`` or ``api_path``
into a 422 before policy has to think about it. There is nothing for a caller to
steer, which is why the endpoint allow-list is sufficient on its own.

**Output models are narrow by construction, and optional by default.** Two rules
governed every field below:

*Nothing that is not needed.* A Proxmox response carries far more than ACOP
should publish - block statistics, per-disk device strings, NIC lists with MAC
addresses, storage volume paths. "Extra upstream fields should not automatically
become ACOP output" is the ratified instruction, and the sanitizer enforces the
allow-list these models define. Disk and network *device* configuration is
deliberately absent from both config models: those lines carry storage volume
paths and MAC addresses, and Milestone 5's ratified position is that neither is
lifecycle identity. They belong to the discovery checkpoint's storage-identity
gate, not here.

*Anything not observed is optional.* ADR-0023 turned a declared field the
adapter cannot populate into a **failed invocation**, not a null. So a field is
required only where its absence would genuinely mean the response was not the
Proxmox API's documented shape - ``vmid``, ``node``, ``storage`` - and every
other field is ``| None``. Two areas are optional for a specific evidentiary
reason and are marked in place: ``proxmox.node.status`` and both container
models describe endpoints that Checkpoint 0 could not observe returning data
(``/nodes/{node}/status`` was not captured; the lab had no containers at all).

**No container model carries a UUID field of any kind.** LXC has no durable
lifecycle identifier - the reconnaissance looked and there is none, and
``--unique`` is a restore-time random MAC rather than an identity. Fabricating
one is prohibited, and a unit test asserts the absence structurally rather than
trusting this paragraph.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

_FORBID = ConfigDict(extra="forbid")


class _ProxmoxOut(BaseModel):
    """Common shape: which instance, and when it was observed.

    ``instance_id`` is on every output because a result read six months later
    must say which Proxmox it describes, and ``observed_at`` because a read-only
    tool's answer is a statement about a moment.
    """

    model_config = _FORBID

    instance_id: str
    observed_at: datetime


# ---------------------------------------------------------------------------
# proxmox.cluster.status
# ---------------------------------------------------------------------------


class ClusterMemberOut(BaseModel):
    """One entry of ``/cluster/status``.

    Proxmox returns a heterogeneous list: on a clustered install one entry has
    ``type: "cluster"`` and the rest are ``type: "node"``; on a standalone
    install there is only the local node. One model covers both, with everything
    but ``id`` and ``type`` optional, because insisting on a cluster-shaped field
    would fail on exactly the installation this was verified against.
    """

    model_config = _FORBID

    id: str
    type: str
    name: str | None = None
    node: str | None = None
    ip: str | None = None
    node_id: int | None = None
    online: bool | None = None
    local: bool | None = None
    quorate: bool | None = None
    member_count: int | None = None


class ClusterStatusOut(_ProxmoxOut):
    """The instance's own view of itself.

    ``standalone`` is derived - no member of type ``cluster`` - rather than
    reported by Proxmox, and it is the field the discovery checkpoint should read
    instead of inferring from a missing ``cluster_name``. ``cluster_name`` and
    ``quorate`` are optional precisely because the verified standalone response
    carries neither, and a required field there would make ACOP unable to read
    the lab it was built for.
    """

    standalone: bool
    cluster_name: str | None = None
    quorate: bool | None = None
    members: list[ClusterMemberOut]


# ---------------------------------------------------------------------------
# proxmox.node.list
# ---------------------------------------------------------------------------


class NodeSummaryOut(BaseModel):
    """One entry of ``/nodes``.

    ``ssl_fingerprint`` is the node's certificate fingerprint. It is a public
    value - it is what a client checks a certificate *against* - and it is the
    only stable identifier a node exposes that survives a rename, which makes it
    worth carrying for correlation.
    """

    model_config = _FORBID

    node: str
    status: str | None = None
    type: str | None = None
    uptime_seconds: int | None = None
    cpu_usage: float | None = None
    cpu_count: int | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None
    disk_used_bytes: int | None = None
    disk_total_bytes: int | None = None
    ssl_fingerprint: str | None = None


class NodeListOut(_ProxmoxOut):
    nodes: list[NodeSummaryOut]


# ---------------------------------------------------------------------------
# proxmox.node.status
# ---------------------------------------------------------------------------


class NodeStatusOut(_ProxmoxOut):
    """``/nodes/{node}/status``.

    **Every field but ``node`` is optional, and that is evidentiary rather than
    defensive.** Checkpoint 0 verified ``/version``, ``/cluster/status``,
    ``/nodes``, ``/cluster/resources``, ``/nodes/{node}/network``, the QEMU
    status and config endpoints, the LXC listing and the storage listing. It did
    **not** capture ``/nodes/{node}/status``. The fields below come from the
    Proxmox API's documented shape, which is a good source but not an observed
    one, and under ADR-0023 a required field the adapter cannot populate fails
    the invocation. Optional is the honest declaration until this endpoint is
    captured.
    """

    node: str
    uptime_seconds: int | None = None
    cpu_usage: float | None = None
    cpu_count: int | None = None
    cpu_sockets: int | None = None
    cpu_model: str | None = None
    load_average: list[float] | None = None
    memory_total_bytes: int | None = None
    memory_used_bytes: int | None = None
    memory_free_bytes: int | None = None
    swap_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    rootfs_total_bytes: int | None = None
    rootfs_used_bytes: int | None = None
    rootfs_available_bytes: int | None = None
    pve_version: str | None = None
    kernel_version: str | None = None


# ---------------------------------------------------------------------------
# proxmox.node.network
# ---------------------------------------------------------------------------


class NetworkInterfaceOut(BaseModel):
    """One entry of ``/nodes/{node}/network``.

    Verified against the lab: ``nic0``/``nic1`` and a ``vmbr0`` bridge carrying
    a CIDR, a gateway and ``bridge_ports``. ``iface`` is the only required field
    - an interface entry with no name is not an interface entry.
    """

    model_config = _FORBID

    iface: str
    type: str | None = None
    method: str | None = None
    active: bool | None = None
    autostart: bool | None = None
    address: str | None = None
    netmask: str | None = None
    cidr: str | None = None
    gateway: str | None = None
    bridge_ports: str | None = None


class NodeNetworkOut(_ProxmoxOut):
    node: str
    interfaces: list[NetworkInterfaceOut]


# ---------------------------------------------------------------------------
# proxmox.guest.list
# ---------------------------------------------------------------------------


class GuestSummaryOut(BaseModel):
    """One entry of ``/cluster/resources?type=vm``.

    ``vmid``, ``guest_type`` and ``node`` are required, and they are the only
    required fields in this file that are required for a *routing* reason rather
    than an identity one: the adapter takes a guest's node from exactly this
    record, so a record without one is a response ACOP cannot use. The adapter
    raises a protocol error before the model is ever reached, so that the failure
    reads as "Proxmox answered wrongly" rather than as ACOP's own contract
    violation - a distinction ADR-0023 makes load-bearing.
    """

    model_config = _FORBID

    vmid: int
    guest_type: str
    node: str
    name: str | None = None
    status: str | None = None
    uptime_seconds: int | None = None
    template: bool | None = None
    cpu_usage: float | None = None
    cpu_count: int | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None
    disk_used_bytes: int | None = None
    disk_total_bytes: int | None = None
    pool: str | None = None
    tags: str | None = None


class GuestListOut(_ProxmoxOut):
    """The unified QEMU + LXC inventory.

    An empty ``guests`` list is a **valid, successful** result meaning the
    instance has no guests. It is distinguishable from a malformed response
    because a malformed one never reaches this model: the transport raises, the
    invocation is ``FAILED``, and ``result_summary`` is NULL. That distinction is
    what stops the discovery checkpoint's absence pass from retiring every guest
    the first time a response cannot be parsed.
    """

    guests: list[GuestSummaryOut]


# ---------------------------------------------------------------------------
# proxmox.vm.status / proxmox.vm.config
# ---------------------------------------------------------------------------


class VmStatusOut(_ProxmoxOut):
    """``/nodes/{node}/qemu/{vmid}/status/current``. Verified in Checkpoint 0.

    ``pid`` and ``blockstat`` are deliberately absent: a host process id is of no
    use to ACOP and per-disk statistics are volume-shaped data belonging to the
    storage-identity gate. ``nics`` is absent for a stronger reason - it carries
    MAC addresses, and the ratified LXC position is that a MAC is not identity.
    """

    node: str
    vmid: int
    name: str | None = None
    status: str | None = None
    qmp_status: str | None = None
    uptime_seconds: int | None = None
    cpu_usage: float | None = None
    cpu_count: int | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None
    disk_total_bytes: int | None = None
    running_machine: str | None = None
    running_qemu: str | None = None
    agent_enabled: bool | None = None
    template: bool | None = None
    tags: str | None = None


class VmConfigOut(_ProxmoxOut):
    """``/nodes/{node}/qemu/{vmid}/config``. Verified in Checkpoint 0.

    The three fields the next checkpoint actually needs are ``smbios_uuid``,
    ``vmgenid`` and ``config_digest``, and all three are optional:

    * ``smbios_uuid`` is parsed out of the ``smbios1`` line, which is a
      comma-separated ``key=value`` string. It is returned only if the ``uuid``
      key is present **and** parses as a UUID. A VM whose config ACOP cannot read
      a UUID from gets ``None`` — never a synthesised value.
    * ``vmgenid`` changes when a VM is restored or cloned, which makes it
      evidence about lifecycle rather than identity. It is carried for that, not
      as a correlator.
    * ``config_digest`` is Proxmox's own hash of the configuration. It is the
      cheapest possible change detector for a later sweep.

    ``created_at`` is derived from the ``ctime`` key of the ``meta`` line, which
    the lab returned for both VMs. Absent on a guest created by an older
    Proxmox, hence optional.
    """

    node: str
    vmid: int
    name: str | None = None
    config_digest: str | None = None
    smbios_uuid: str | None = None
    vmgenid: str | None = None
    creation_qemu_version: str | None = None
    created_at: datetime | None = None
    machine: str | None = None
    bios: str | None = None
    os_type: str | None = None
    cpu_type: str | None = None
    cores: int | None = None
    sockets: int | None = None
    memory_mb: int | None = None
    boot_order: str | None = None
    agent: str | None = None
    protection: bool | None = None
    template: bool | None = None
    tags: str | None = None


# ---------------------------------------------------------------------------
# proxmox.container.status / proxmox.container.config
# ---------------------------------------------------------------------------


class ContainerStatusOut(_ProxmoxOut):
    """``/nodes/{node}/lxc/{vmid}/status/current``.

    Checkpoint 0 verified that ``GET /nodes/{node}/lxc`` answers, and it answered
    ``[]``: the lab has no containers. So no container response payload has ever
    been observed, and every field but ``node`` and ``vmid`` is optional for that
    reason. Under ADR-0023 a required field the adapter cannot fill fails the
    invocation, so guessing at the shape of an unobserved response would produce
    a tool that fails the first time it is genuinely used.
    """

    node: str
    vmid: int
    name: str | None = None
    status: str | None = None
    uptime_seconds: int | None = None
    cpu_usage: float | None = None
    cpu_count: int | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    swap_total_bytes: int | None = None
    disk_used_bytes: int | None = None
    disk_total_bytes: int | None = None
    template: bool | None = None
    tags: str | None = None


class ContainerConfigOut(_ProxmoxOut):
    """``/nodes/{node}/lxc/{vmid}/config``.

    **There is no UUID field here, and there must never be one.** A container has
    no SMBIOS UUID and no durable lifecycle identifier; Checkpoint 0 looked and
    found none, and ``--unique`` is a restore-time random MAC rather than an
    identity. ``config_digest`` is a change detector, not a correlator: it
    changes when the configuration changes and is identical between two
    containers configured the same way, so it can say *this differs from what we
    saw* and can never say *this is the same container*.

    ``rootfs`` and ``mp*`` mount points are excluded along with ``net*``: they
    carry storage volume paths, and storage identity is an explicit Checkpoint 3
    architecture gate rather than something to settle by putting the string in an
    output model now.
    """

    node: str
    vmid: int
    hostname: str | None = None
    config_digest: str | None = None
    os_type: str | None = None
    architecture: str | None = None
    cores: int | None = None
    memory_mb: int | None = None
    swap_mb: int | None = None
    unprivileged: bool | None = None
    protection: bool | None = None
    start_on_boot: bool | None = None
    tags: str | None = None


# ---------------------------------------------------------------------------
# proxmox.storage.list
# ---------------------------------------------------------------------------


class StorageSummaryOut(BaseModel):
    """One entry of ``/nodes/{node}/storage``, tagged with the node it came from.

    ``node`` is required and is the field that makes this model correct on a
    cluster. Proxmox's node-scoped storage listing reports each node's view, and
    a non-shared definition such as ``local`` or ``local-lvm`` is a *different*
    volume on each node under the same name. Returning these without the node
    would present one node's free space as the instance's.
    """

    model_config = _FORBID

    node: str
    storage: str
    storage_type: str | None = None
    content: str | None = None
    active: bool | None = None
    enabled: bool | None = None
    shared: bool | None = None
    total_bytes: int | None = None
    used_bytes: int | None = None
    available_bytes: int | None = None
    used_fraction: float | None = None


class StorageListOut(_ProxmoxOut):
    """The union across every online node.

    ``nodes_queried`` is not decoration. Without it an empty ``storages`` list is
    ambiguous between "no storage is defined" and "no node was online to ask",
    and those need different human responses. With it, the two are distinct in
    the stored result.
    """

    nodes_queried: list[str]
    storages: list[StorageSummaryOut]


__all__ = [
    "ClusterMemberOut",
    "ClusterStatusOut",
    "ContainerConfigOut",
    "ContainerStatusOut",
    "GuestListOut",
    "GuestSummaryOut",
    "NetworkInterfaceOut",
    "NodeListOut",
    "NodeNetworkOut",
    "NodeStatusOut",
    "NodeSummaryOut",
    "StorageListOut",
    "StorageSummaryOut",
    "VmConfigOut",
    "VmStatusOut",
]
