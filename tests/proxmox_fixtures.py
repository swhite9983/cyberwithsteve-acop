"""Scripted Proxmox responses, shaped like the real ones and safe to publish.

**Nothing here is lab-accurate, and that is deliberate.** The reconnaissance that
established these shapes ran against a real hypervisor, and this repository is
public. Following the convention Milestone 2 set in ``tests/conftest.py``, every
value below comes from a documentation range or is invented: addresses from
RFC 5737, the ``.invalid`` TLD reserved by RFC 2606, node and guest names that
exist nowhere, and UUIDs generated for this file. What is preserved is the
*shape* - which keys exist, what types they carry, and which of them Proxmox
omits - because that is the only part the code under test can see.

No credential appears here either. The token id and secret are obviously fake
strings, and they are distinctive precisely so that "did this leak?" assertions
cannot pass by coincidentally matching a hostname.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from acop.config import Settings
from tests.conftest import _base_settings

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INSTANCE_ID = "docs-pve"
BASE_URL = "https://pve.example.invalid:8006"
TOKEN_ID = "acop@pve!doctest"

#: Distinctive on purpose. A leak assertion that searched for "secret" could
#: pass against unrelated prose; one that searches for this string cannot.
TOKEN_SECRET = "proxmox-token-secret-Wq9zK4"

NODE = "pve-doc-01"
NODE_B = "pve-doc-02"
NODE_IP = "192.0.2.11"
NODE_B_IP = "192.0.2.12"

VM_VMID = 200
VM_NAME = "docs-vm-01"
VM_UUID = "3f2b7c18-5d64-4c0a-9f2e-71a5c0d3e480"
VM_GENID = "9c4e1a77-2b30-4de6-8f11-6d0b9a5c72f3"

CT_VMID = 310
CT_HOSTNAME = "docs-ct-01"


def proxmox_settings(**overrides: object) -> Settings:
    """Settings with the Proxmox integration enabled and pointed nowhere real."""
    values: dict[str, object] = {
        "proxmox_enabled": True,
        "proxmox_instance_id": INSTANCE_ID,
        "proxmox_base_url": BASE_URL,
        "proxmox_token_id": TOKEN_ID,
        "proxmox_token_secret": TOKEN_SECRET,
        "proxmox_verify_tls": True,
        "proxmox_timeout_seconds": 5.0,
    }
    values.update(overrides)
    return _base_settings(**values)


# ---------------------------------------------------------------------------
# Response bodies
# ---------------------------------------------------------------------------


def envelope(data: Any) -> bytes:
    """Wrap a payload the way every Proxmox API response is wrapped."""
    return json.dumps({"data": data}).encode("utf-8")


#: ``/cluster/status`` on a standalone node: one member, type ``node``, no
#: cluster object, no quorum. Exactly the shape Checkpoint 0 verified, and the
#: one that would fail an output model requiring a cluster name.
CLUSTER_STATUS_STANDALONE: list[dict[str, Any]] = [
    {
        "id": f"node/{NODE}",
        "name": NODE,
        "type": "node",
        "ip": NODE_IP,
        "nodeid": 0,
        "local": 1,
        "online": 1,
    }
]

#: The same endpoint on a two-node cluster, for the fields a standalone install
#: can never exercise.
CLUSTER_STATUS_CLUSTERED: list[dict[str, Any]] = [
    {
        "id": "cluster",
        "type": "cluster",
        "name": "docs-cluster",
        "quorate": 1,
        "nodes": 2,
    },
    {
        "id": f"node/{NODE}",
        "name": NODE,
        "type": "node",
        "ip": NODE_IP,
        "nodeid": 1,
        "local": 1,
        "online": 1,
    },
    {
        "id": f"node/{NODE_B}",
        "name": NODE_B,
        "type": "node",
        "ip": NODE_B_IP,
        "nodeid": 2,
        "local": 0,
        "online": 1,
    },
]

NODE_LIST: list[dict[str, Any]] = [
    {
        "node": NODE,
        "status": "online",
        "type": "node",
        "uptime": 864000,
        "cpu": 0.0412,
        "maxcpu": 12,
        "mem": 34359738368,
        "maxmem": 68719476736,
        "disk": 10737418240,
        "maxdisk": 107374182400,
        "ssl_fingerprint": "AA:BB:CC:DD:EE:FF",
    }
]

NODE_LIST_TWO: list[dict[str, Any]] = [
    *NODE_LIST,
    {
        "node": NODE_B,
        "status": "online",
        "type": "node",
        "uptime": 432000,
        "cpu": 0.0219,
        "maxcpu": 8,
        "mem": 8589934592,
        "maxmem": 34359738368,
    },
]

#: One node offline. The adapter must skip it rather than fail the whole read.
NODE_LIST_ONE_OFFLINE: list[dict[str, Any]] = [
    *NODE_LIST,
    {"node": NODE_B, "status": "offline", "type": "node"},
]

NODE_STATUS: dict[str, Any] = {
    "uptime": 864000,
    "cpu": 0.0412,
    "loadavg": ["0.31", "0.28", "0.24"],
    "cpuinfo": {"cpus": 12, "sockets": 1, "model": "Documentation CPU 0000"},
    "memory": {"total": 68719476736, "used": 34359738368, "free": 34359738368},
    "swap": {"total": 8589934592, "used": 0},
    "rootfs": {"total": 107374182400, "used": 10737418240, "avail": 96636764160},
    "pveversion": "pve-manager/9.2.4",
    "current-kernel": "6.14.0-2-pve",
}

NODE_NETWORK: list[dict[str, Any]] = [
    {"iface": "nic0", "type": "eth", "active": 1, "autostart": 1, "method": "manual"},
    {"iface": "nic1", "type": "eth", "active": 0, "method": "manual"},
    {
        "iface": "vmbr0",
        "type": "bridge",
        "active": 1,
        "autostart": 1,
        "method": "static",
        "address": NODE_IP,
        "netmask": "255.255.255.0",
        "cidr": f"{NODE_IP}/24",
        "gateway": "192.0.2.1",
        "bridge_ports": "nic0",
    },
]

#: ``/cluster/resources?type=vm``: QEMU and LXC in one list, each carrying the
#: node that hosts it. This is the record the adapter routes from.
GUEST_LIST: list[dict[str, Any]] = [
    {
        "id": f"qemu/{VM_VMID}",
        "type": "qemu",
        "vmid": VM_VMID,
        "name": VM_NAME,
        "node": NODE,
        "status": "running",
        "uptime": 432000,
        "cpu": 0.0184,
        "maxcpu": 4,
        "mem": 4294967296,
        "maxmem": 8589934592,
        "disk": 0,
        "maxdisk": 68719476736,
        "template": 0,
    },
    {
        "id": f"lxc/{CT_VMID}",
        "type": "lxc",
        "vmid": CT_VMID,
        "name": CT_HOSTNAME,
        "node": NODE,
        "status": "running",
        "uptime": 86400,
        "cpu": 0.0031,
        "maxcpu": 2,
        "mem": 268435456,
        "maxmem": 1073741824,
        "disk": 2147483648,
        "maxdisk": 8589934592,
    },
]

VM_STATUS: dict[str, Any] = {
    "vmid": VM_VMID,
    "name": VM_NAME,
    "status": "running",
    "qmpstatus": "running",
    "uptime": 432000,
    "cpu": 0.0184,
    "cpus": 4,
    "mem": 4294967296,
    "maxmem": 8589934592,
    "maxdisk": 68719476736,
    "running-machine": "pc-i440fx-10.1+pve1",
    "running-qemu": "10.1.2",
    "agent": 1,
    "pid": 12345,
    "blockstat": {"scsi0": {"rd_bytes": 1}},
    "nics": {"tap200i0": {"netin": 1, "netout": 2}},
}

#: The verified config shape: ``smbios1`` carrying ``uuid=``, a ``vmgenid``, a
#: ``meta`` line with ``creation-qemu`` and ``ctime``, and a digest. The disk and
#: net device lines are present here precisely so a test can prove they do
#: **not** appear in the output.
VM_CONFIG: dict[str, Any] = {
    "name": VM_NAME,
    "smbios1": f"uuid={VM_UUID}",
    "vmgenid": VM_GENID,
    "meta": "creation-qemu=10.1.2,ctime=1782563168",
    "digest": "0123456789abcdef0123456789abcdef01234567",
    "machine": "q35",
    "bios": "ovmf",
    "ostype": "l26",
    "cpu": "host",
    "cores": 4,
    "sockets": 1,
    "memory": 8192,
    "boot": "order=scsi0;net0",
    "agent": "1",
    "protection": 0,
    "scsi0": "zfs-doc:vm-200-disk-0,size=64G",
    "net0": "virtio=00:00:5E:00:53:10,bridge=vmbr0",
    "efidisk0": "zfs-doc:vm-200-disk-1,size=1M",
}

#: No live container ever existed in the lab, so this is the documented shape
#: rather than an observed one - which is exactly why every field it feeds is
#: optional in ``ContainerStatusOut``/``ContainerConfigOut``.
CONTAINER_STATUS: dict[str, Any] = {
    "vmid": CT_VMID,
    "name": CT_HOSTNAME,
    "status": "running",
    "uptime": 86400,
    "cpu": 0.0031,
    "cpus": 2,
    "mem": 268435456,
    "maxmem": 1073741824,
    "swap": 0,
    "maxswap": 536870912,
    "disk": 2147483648,
    "maxdisk": 8589934592,
}

CONTAINER_CONFIG: dict[str, Any] = {
    "hostname": CT_HOSTNAME,
    "digest": "fedcba9876543210fedcba9876543210fedcba98",
    "ostype": "debian",
    "arch": "amd64",
    "cores": 2,
    "memory": 1024,
    "swap": 512,
    "unprivileged": 1,
    "onboot": 1,
    "rootfs": "zfs-doc:subvol-310-disk-0,size=8G",
    "net0": "name=eth0,bridge=vmbr0,hwaddr=00:00:5E:00:53:11,ip=dhcp",
}

#: Seven definitions, matching the field set Checkpoint 0 captured. ``local`` and
#: ``local-lvm`` are node-local; the rest are shared - which is the whole reason
#: the storage tool carries its source node.
STORAGE_LIST: list[dict[str, Any]] = [
    {
        "storage": "local",
        "type": "dir",
        "content": "vztmpl,iso,backup",
        "active": 1,
        "enabled": 1,
        "shared": 0,
        "total": 107374182400,
        "used": 10737418240,
        "avail": 96636764160,
        "used_fraction": 0.1,
    },
    {
        "storage": "local-lvm",
        "type": "lvmthin",
        "content": "rootdir,images",
        "active": 1,
        "enabled": 1,
        "shared": 0,
        "total": 214748364800,
        "used": 21474836480,
        "avail": 193273528320,
        "used_fraction": 0.1,
    },
    {
        "storage": "shared-docs",
        "type": "nfs",
        "content": "iso,backup",
        "active": 1,
        "enabled": 1,
        "shared": 1,
        "total": 1099511627776,
        "used": 549755813888,
        "avail": 549755813888,
        "used_fraction": 0.5,
    },
]


# ---------------------------------------------------------------------------
# Scripted transport
# ---------------------------------------------------------------------------


@dataclass
class ScriptedProxmox:
    """A route table plus a request log, over ``httpx.MockTransport``.

    Real client code runs against this: request construction, the
    ``Authorization`` header, status mapping, streaming and the size cap, the
    envelope check. Only the socket is replaced, which is the point - a stub that
    returned parsed objects would prove none of those.
    """

    routes: dict[str, Callable[[httpx.Request], httpx.Response]] = field(
        default_factory=dict
    )
    requests: list[httpx.Request] = field(default_factory=list)

    def json_route(self, path: str, data: Any, *, status_code: int = 200) -> None:
        """Answer ``path`` with ``data`` inside a Proxmox envelope."""
        body = envelope(data)

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code, content=body, headers={"content-type": "application/json"}
            )

        self.routes[path] = handler

    def raw_route(
        self, path: str, handler: Callable[[httpx.Request], httpx.Response]
    ) -> None:
        self.routes[path] = handler

    def status_route(self, path: str, status_code: int) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, content=b'{"errors":{}}')

        self.routes[path] = handler

    def error_route(self, path: str, exc: Exception) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise exc

        self.routes[path] = handler

    @property
    def paths(self) -> list[str]:
        return [request.url.path for request in self.requests]

    @property
    def methods(self) -> list[str]:
        return [request.method for request in self.requests]

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            route = self.routes.get(request.url.path)
            if route is None:
                # Loud rather than a 404: an unrouted path means the code under
                # test built a URL the test did not anticipate, which is the
                # thing worth failing on.
                raise AssertionError(f"unrouted Proxmox path: {request.url.path}")
            return route(request)

        return httpx.MockTransport(handler)


def standalone_instance() -> ScriptedProxmox:
    """A single online node with two guests, seven-ish storages, no cluster."""
    scripted = ScriptedProxmox()
    scripted.json_route("/api2/json/cluster/status", CLUSTER_STATUS_STANDALONE)
    scripted.json_route("/api2/json/nodes", NODE_LIST)
    scripted.json_route(f"/api2/json/nodes/{NODE}/status", NODE_STATUS)
    scripted.json_route(f"/api2/json/nodes/{NODE}/network", NODE_NETWORK)
    scripted.json_route("/api2/json/cluster/resources", GUEST_LIST)
    scripted.json_route(f"/api2/json/nodes/{NODE}/storage", STORAGE_LIST)
    scripted.json_route(
        f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/status/current", VM_STATUS
    )
    scripted.json_route(f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/config", VM_CONFIG)
    scripted.json_route(
        f"/api2/json/nodes/{NODE}/lxc/{CT_VMID}/status/current", CONTAINER_STATUS
    )
    scripted.json_route(f"/api2/json/nodes/{NODE}/lxc/{CT_VMID}/config", CONTAINER_CONFIG)
    return scripted


__all__ = [
    "BASE_URL",
    "CLUSTER_STATUS_CLUSTERED",
    "CLUSTER_STATUS_STANDALONE",
    "CONTAINER_CONFIG",
    "CONTAINER_STATUS",
    "CT_HOSTNAME",
    "CT_VMID",
    "GUEST_LIST",
    "INSTANCE_ID",
    "NODE",
    "NODE_B",
    "NODE_IP",
    "NODE_LIST",
    "NODE_LIST_ONE_OFFLINE",
    "NODE_LIST_TWO",
    "NODE_NETWORK",
    "NODE_STATUS",
    "STORAGE_LIST",
    "TOKEN_ID",
    "TOKEN_SECRET",
    "VM_CONFIG",
    "VM_GENID",
    "VM_NAME",
    "VM_STATUS",
    "VM_UUID",
    "VM_VMID",
    "ScriptedProxmox",
    "envelope",
    "proxmox_settings",
    "standalone_instance",
]
