"""The endpoint allow-list — the security artifact of this checkpoint.

Ten tools, ten templates, and no way to express an eleventh. A caller supplies
no path, no fragment of one, and no value that reaches one: every Proxmox tool's
input model has **no fields at all**, so there is nothing in a request to steer.
What fills ``{node}`` and ``{vmid}`` comes from a registered ACOP identifier or
from Proxmox's own inventory response, never from the outside.

That is the difference between this and a generic ``proxmox.api.get``, and the
reason the latter is not "not yet" but never: an arbitrary-path read tool would
reintroduce every locator import rules 9, 10 and 11 exist to keep out, and would
do it through a field those rules do not inspect.

**Three checks, in ascending order of paranoia.**

1. Every template is a literal in this file, keyed by tool name. A tool name
   with no entry cannot be executed at all.
2. Every substituted segment must match a narrow pattern - digits for a VMID, a
   DNS-label-shaped string for a node - so a value that somehow arrived from a
   compromised upstream response cannot contain ``/`` or ``..``.
3. Every segment is then percent-encoded with ``safe=""``. Belt and braces: if
   the pattern were ever loosened, the encoder still prevents traversal.

And a fourth, at import: :func:`_assert_templates_are_sane` refuses any template
that does not begin with ``/api2/json/``, contains ``..``, or names a placeholder
this module cannot validate. It runs at module import, so a badly-written
template is a failed build rather than a runtime surprise - the same severity
the fourteen declaration rules are given, for the same reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import quote

from acop.tools.adapters.proxmox.errors import ProxmoxProtocolError

#: Every path this integration can produce starts here.
API_ROOT: Final = "/api2/json/"

#: A Proxmox node name. Shaped like a DNS label because that is what it is - PVE
#: derives it from the host's name - and bounded so a pathological value cannot
#: produce an unbounded URL. Case is preserved: node names are used literally in
#: API paths, which is why the adapter takes them from Proxmox's own response
#: rather than from the case-folded ``value_normalized`` of an identifier.
_NODE_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

#: A VMID. Proxmox allocates these from 100 upward; the lower bound here is 1
#: rather than 100 so that a legitimate hand-assigned id is not refused by a
#: rule ACOP invented.
_VMID_PATTERN: Final = re.compile(r"^[1-9][0-9]{0,8}$")

_SEGMENT_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "node": _NODE_PATTERN,
    "vmid": _VMID_PATTERN,
}


@dataclass(frozen=True, slots=True)
class EndpointTemplate:
    """One allowed GET, with the segments it needs and the query it carries.

    ``query`` is a tuple of pairs rather than a dict so the whole template is
    hashable and immutable. It is fixed per endpoint - ``type=vm`` for the
    unified guest inventory - and is not caller-influenced, which is why it can
    live in the template at all.
    """

    template: str
    segments: tuple[str, ...] = ()
    query: tuple[tuple[str, str], ...] = ()

    def build(self, **values: str) -> tuple[str, dict[str, str]]:
        """Return ``(path, query)`` for this endpoint.

        Raises:
            ProxmoxProtocolError: A required segment is missing, or a value does
                not satisfy its pattern. ``ProxmoxProtocolError`` rather than a
                bare ``ValueError`` because the only way an invalid value can
                reach here is a Proxmox response that named a node ACOP cannot
                represent - which is the upstream disagreeing with the API's own
                documented shape.
        """
        missing = [name for name in self.segments if not values.get(name)]
        if missing:
            raise ProxmoxProtocolError(
                f"Endpoint {self.template} needs {sorted(missing)} and none was "
                "derived from a trusted source.",
                context={"template": self.template, "missing": sorted(missing)},
            )
        rendered: dict[str, str] = {}
        for name in self.segments:
            value = values[name]
            pattern = _SEGMENT_PATTERNS[name]
            if not pattern.match(value):
                raise ProxmoxProtocolError(
                    f"Proxmox reported a {name} that ACOP will not put in a URL.",
                    # The value is *not* logged. It came from a response body,
                    # and this is the one path where that body is already known
                    # to be untrustworthy.
                    context={"template": self.template, "segment": name},
                )
            rendered[name] = quote(value, safe="")
        return self.template.format(**rendered), dict(self.query)


#: Tool name to the single GET it may perform.
#:
#: ``proxmox.storage.list`` is node-scoped while its tool targets the cluster.
#: That is not an error in the mapping: the adapter iterates the online nodes and
#: returns the union, because ``local`` on one node is not ``local`` on another
#: and reporting one node's free space as the cluster's would be a false
#: statement about capacity. See ``docs/proxmox/proxmox-transport.md``.
TOOL_ENDPOINTS: Final[dict[str, EndpointTemplate]] = {
    "proxmox.cluster.status": EndpointTemplate("/api2/json/cluster/status"),
    "proxmox.node.list": EndpointTemplate("/api2/json/nodes"),
    "proxmox.node.status": EndpointTemplate("/api2/json/nodes/{node}/status", ("node",)),
    "proxmox.node.network": EndpointTemplate(
        "/api2/json/nodes/{node}/network", ("node",)
    ),
    "proxmox.guest.list": EndpointTemplate(
        "/api2/json/cluster/resources", (), (("type", "vm"),)
    ),
    "proxmox.vm.status": EndpointTemplate(
        "/api2/json/nodes/{node}/qemu/{vmid}/status/current", ("node", "vmid")
    ),
    "proxmox.vm.config": EndpointTemplate(
        "/api2/json/nodes/{node}/qemu/{vmid}/config", ("node", "vmid")
    ),
    "proxmox.container.status": EndpointTemplate(
        "/api2/json/nodes/{node}/lxc/{vmid}/status/current", ("node", "vmid")
    ),
    "proxmox.container.config": EndpointTemplate(
        "/api2/json/nodes/{node}/lxc/{vmid}/config", ("node", "vmid")
    ),
    "proxmox.storage.list": EndpointTemplate(
        "/api2/json/nodes/{node}/storage", ("node",)
    ),
}

#: The two endpoints the adapter also calls for its own routing, named as
#: constants so the resolution code cannot reach a template by string literal.
#:
#: Both are already in :data:`TOOL_ENDPOINTS` because both are also tools. That
#: is the point: routing performs no read that an operator could not perform
#: through a declared, policy-gated capability, so there is no privileged
#: side-channel hiding behind the adapter.
GUEST_INVENTORY: Final = "proxmox.guest.list"
NODE_INVENTORY: Final = "proxmox.node.list"


def _assert_templates_are_sane() -> None:
    """Refuse at import a template that could produce an unintended path."""
    for tool_name, endpoint in TOOL_ENDPOINTS.items():
        if not endpoint.template.startswith(API_ROOT):
            raise AssertionError(
                f"{tool_name} names {endpoint.template!r}, which is outside {API_ROOT}."
            )
        if ".." in endpoint.template:
            raise AssertionError(f"{tool_name} names a traversing template.")
        placeholders = set(re.findall(r"{(\w+)}", endpoint.template))
        if placeholders != set(endpoint.segments):
            raise AssertionError(
                f"{tool_name} declares segments {sorted(endpoint.segments)} but "
                f"its template uses {sorted(placeholders)}."
            )
        unknown = placeholders - set(_SEGMENT_PATTERNS)
        if unknown:
            raise AssertionError(
                f"{tool_name} uses placeholder(s) {sorted(unknown)} that this "
                "module cannot validate. Add a pattern before adding the tool."
            )


_assert_templates_are_sane()

__all__ = [
    "API_ROOT",
    "GUEST_INVENTORY",
    "NODE_INVENTORY",
    "TOOL_ENDPOINTS",
    "EndpointTemplate",
]
