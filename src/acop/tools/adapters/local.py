"""The ``acop.local`` adapter: ACOP reporting on itself.

The only adapter that touches nothing outside the process. It exists so that
Class 0 has a real implementation rather than a stub, and so the framework's
inline execution path is exercised against something that genuinely does work
rather than a function that returns a constant.

It performs no I/O of its own beyond what :class:`HealthService` already does,
opens no socket, spawns nothing, and has no notion of a target - Class 0 and
``TargetKind.NONE`` coincide by import rule 7.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from acop.models.tool_vocabulary import AdapterOutcome
from acop.tools.adapters.base import AdapterRequest, AdapterResult, register_adapter
from acop.tools.errors import AdapterUnavailableError

_HEALTH_TOOL = "acop.system.health"
_ECHO_TOOL = "acop.test.echo_metadata"


class LocalAdapter:
    """Answers questions about ACOP itself.

    Dispatch is on ``tool_name`` rather than a registry of callables because
    there are two of them and a dict of one-line lambdas would obscure rather
    than clarify. A third tool would justify the indirection; two do not.
    """

    adapter_id = "acop.local"

    async def execute(self, request: AdapterRequest) -> AdapterResult:
        if request.tool_name == _HEALTH_TOOL:
            return await self._health(request)
        if request.tool_name == _ECHO_TOOL:
            return self._echo(request)
        # Unreachable through the framework: import rule 13 binds tools to
        # adapters at startup. Raising rather than returning a failure makes a
        # future mis-binding loud instead of silently empty.
        raise AdapterUnavailableError(
            f"{self.adapter_id} has no implementation for {request.tool_name!r}."
        )

    async def validate(self, request: AdapterRequest) -> AdapterResult:
        """Neither local tool changes anything, so neither is ever validated.

        Import rule 2 already guarantees this is unreachable: only Class 2 and
        Class 3 require validation, and both local tools are Class 0.
        """
        raise AdapterUnavailableError(
            f"{self.adapter_id} tools make no change and cannot be validated."
        )

    # ------------------------------------------------------------------
    async def _health(self, request: AdapterRequest) -> AdapterResult:
        service = request.services.health
        if service is None:
            # An honest unavailable, not a fabricated "healthy". A health tool
            # that reports success when it could not check is worse than one
            # that fails.
            raise AdapterUnavailableError(
                "The health service is not bound to this adapter.",
            )
        report = await service.report(use_cache=True)
        components = [
            {
                "name": name,
                "status": str(detail.status),
                "latency_ms": detail.latency_ms,
            }
            for name, detail in sorted(report.details.items())
        ]
        return AdapterResult(
            outcome=AdapterOutcome.SUCCESS,
            payload={
                "status": str(report.status),
                "environment": report.environment,
                "checked_at": report.checked_at,
                "components": components,
            },
        )

    def _echo(self, request: AdapterRequest) -> AdapterResult:
        """Return the invocation's own metadata.

        Useful precisely because it is boring: it proves the invocation record,
        the envelope and the response agree with each other, and it gives the
        acceptance suite something whose correct output is fully determined.
        """
        payload: dict[str, Any] = {
            "note": request.payload.get("note", ""),
            "tool_name": request.tool_name,
            "tool_version": request.tool_version,
            "invocation_id": str(request.invocation_id),
            "observed_at": datetime.now(UTC),
        }
        return AdapterResult(outcome=AdapterOutcome.SUCCESS, payload=payload)


LOCAL_ADAPTER = register_adapter(LocalAdapter())

__all__ = ["LOCAL_ADAPTER", "LocalAdapter"]
