"""The Proxmox adapter — registered, bound, and deliberately inert.

This is Checkpoint 1C of Milestone 5. The adapter exists so that the binding
is real: ``adapter_id = "proxmox"`` resolves through
:func:`~acop.tools.adapters.base.resolve_adapter`, which is what import rule 13
consults when the first Proxmox tool is declared. Registering it now means that
declaration fails the build if the id is ever misspelt, rather than surfacing as
a confusing runtime denial.

**It talks to nothing.** There is no HTTP client here, no ``httpx`` import, no
URL, no credential read. ``execute`` refuses every tool name it is given,
because in this checkpoint every tool name is one it does not implement.

**It refuses to validate, permanently.** Every Milestone 5 tool is
``CLASS_1_READ_ONLY``. Import rule 2 only forces ``validation_required`` for
Class 2 and Class 3, so no read-only tool sets it and
:meth:`~acop.services.tools.dispatcher.ExecutionDispatcher._after_execution`
never calls ``validate``. Refusing is therefore not a placeholder to be filled
in later - it is the correct terminal answer, and it is the same answer
:class:`~acop.tools.adapters.local.LocalAdapter` gives for the same reason. A
read makes no change, so there is nothing to independently confirm afterwards.

**It does not consult ``proxmox_enabled``.** Settings reach adapters through
``request.services.settings`` and are available here, but no tool is bound to
this adapter yet, so there is no reachable path for that flag to gate. Checking
it now would be a guard over a door that has no room behind it. It becomes
load-bearing in the checkpoint that adds the client.
"""

from __future__ import annotations

from acop.tools.adapters.base import (
    AdapterRequest,
    AdapterResult,
    register_adapter,
)
from acop.tools.errors import AdapterUnavailableError


class ProxmoxAdapter:
    """The single component permitted to speak to Proxmox. It cannot yet.

    A plain class rather than a subclass: ``ToolAdapter`` is a structural
    Protocol, so conformance is by shape. ``adapter_id`` is a bare class
    attribute for the same reason the other adapters use one -
    :func:`register_adapter` keys the registry on it.
    """

    adapter_id = "proxmox"

    async def execute(self, request: AdapterRequest) -> AdapterResult:
        """Refuse, naming the tool.

        Loudly, and with the tool name in the message, because the only way to
        reach this method is for a tool declaration to name this adapter - and
        in Checkpoint 1C no such declaration exists. If one appears before the
        client does, the error should say exactly which tool arrived early
        rather than fail as a generic unavailability.
        """
        raise AdapterUnavailableError(
            f"{self.adapter_id} implements no tool yet, so it cannot execute "
            f"{request.tool_name}@{request.tool_version}. Milestone 5 "
            "Checkpoint 1C registers the binding and adds no capability.",
            context={
                "adapter_id": self.adapter_id,
                "tool_name": request.tool_name,
                "tool_version": request.tool_version,
            },
        )

    async def validate(self, request: AdapterRequest) -> AdapterResult:
        """Refuse, and keep refusing.

        Unlike :meth:`execute` this does not become an implementation later.
        Every Milestone 5 tool is read-only; a read has no change to confirm.
        """
        raise AdapterUnavailableError(
            f"{self.adapter_id} tools are read-only and make no change, so "
            "there is nothing to validate.",
            context={
                "adapter_id": self.adapter_id,
                "tool_name": request.tool_name,
            },
        )


PROXMOX_ADAPTER = register_adapter(ProxmoxAdapter())

__all__ = ["PROXMOX_ADAPTER", "ProxmoxAdapter"]
