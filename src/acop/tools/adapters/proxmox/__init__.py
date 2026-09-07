"""The Proxmox adapter package — transport, identity, projection, adapter.

Checkpoint 1C registered a binding that talked to nothing. This checkpoint fills
it in, and the module split is where the security properties live:

============== ============================================================
``endpoints``  The allow-list. Ten templates, three validation layers, and
               an import-time assertion. Nothing else may construct a path.
``client``     The only socket. ``GET`` only - there is no method parameter
               - HTTPS only, token auth only, bounded body, no redirects.
``identity``   Resolved target to trusted address. Instance verified before
               the first request; every node string taken from Proxmox.
``projection`` Proxmox JSON to the narrow mappings the tools declare.
``adapter``    Ten names, ten reads, and no eleventh branch.
``errors``     Transport failures mapped onto Milestone 4's taxonomy.
============== ============================================================

The package boundary is the point: ``httpx`` is imported by ``client`` and by
nothing else in ACOP's Proxmox path, so "which code can reach the hypervisor" is
answered by reading one file rather than by trusting a convention. A unit test
asserts exactly that, replacing the Checkpoint 1C assertion that no module here
imported ``httpx`` at all - which was the honest statement then and would be a
false one now.
"""

from acop.tools.adapters.proxmox.adapter import (
    PROXMOX_ADAPTER,
    SUPPORTED_TOOLS,
    ProxmoxAdapter,
)

__all__ = ["PROXMOX_ADAPTER", "SUPPORTED_TOOLS", "ProxmoxAdapter"]
