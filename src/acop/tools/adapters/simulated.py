"""The ``test.simulated`` adapter: a real framework exercise with no real host.

Every behaviour the milestone must prove - a change that succeeds, one that
succeeds but cannot be confirmed, one that cannot be reached, one that runs
past its deadline, and one that must never run at all - is reachable here
without a device, a socket, a subprocess, or a credential.

**What this module may not import**, asserted by a static test rather than left
to habit: ``subprocess``, ``os.system``, ``socket``, ``asyncssh``,
``paramiko``, ``pexpect``, ``winrm``. If a future contributor needs one of
those, they are no longer writing a simulation.

**State lives in a module-level dict guarded by a lock.** No table, no file, no
process. A table would make simulated state indistinguishable from real
inventory in a backup; a file would survive a test run. The lock is real
because the dispatcher runs concurrently and a torn read here would look like a
framework bug.

**Behaviour is selected by the target asset's ``display_name``.** That keeps
the *input schema* free of any field that steers execution - a caller cannot
ask for the failure path, because there is nowhere in the request to ask. The
acceptance suite creates an asset named ``sim-stays-down`` instead.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from acop.models.tool_vocabulary import AdapterOutcome
from acop.tools.adapters.base import AdapterRequest, AdapterResult, register_adapter
from acop.tools.errors import (
    AdapterUnavailableError,
    ProhibitedCapabilityError,
    TargetUnavailableError,
)

_DEVICE_STATUS_TOOL = "test.device.status"
_SERVICE_RESTART_TOOL = "test.service.restart"
_ROTATE_KEY_TOOL = "test.security.rotate_key"
_PROHIBITED_TOOL = "test.prohibited.shell_exec"

#: Display names that select a non-default behaviour. Named constants rather
#: than string literals so the acceptance suite and the adapter cannot drift.
SIM_STAYS_DOWN = "sim-stays-down"
SIM_UNREACHABLE = "sim-unreachable"
SIM_SLOW = "sim-slow"


@dataclass
class SimulatedService:
    """The pretend state of one simulated service."""

    running: bool = True
    pid: int = 4242
    restarts: int = 0
    last_restarted_at: datetime | None = None
    key_slots: dict[str, str] = field(default_factory=dict)


_STATE: dict[uuid.UUID, SimulatedService] = {}
_LOCK = asyncio.Lock()


async def reset_simulation() -> None:
    """Clear all simulated state. Called between tests."""
    async with _LOCK:
        _STATE.clear()


async def simulated_state(asset_id: uuid.UUID) -> SimulatedService:
    """Read (creating on first touch) the simulated state for an asset."""
    async with _LOCK:
        return _STATE.setdefault(asset_id, SimulatedService())


class SimulatedAdapter:
    """A deterministic stand-in for real infrastructure."""

    adapter_id = "test.simulated"

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------
    async def execute(self, request: AdapterRequest) -> AdapterResult:
        if request.tool_name == _PROHIBITED_TOOL:
            # Reaching this line means a policy bug let a prohibited capability
            # through. Raising is the point: a loud failure, never a shell.
            raise ProhibitedCapabilityError(
                "A prohibited tool reached its adapter. This is a policy defect.",
                context={"tool": request.tool_name},
            )
        if request.tool_name == _DEVICE_STATUS_TOOL:
            return await self._device_status(request)
        if request.tool_name == _SERVICE_RESTART_TOOL:
            return await self._restart(request)
        if request.tool_name == _ROTATE_KEY_TOOL:
            return await self._rotate_key(request)
        raise AdapterUnavailableError(
            f"{self.adapter_id} has no implementation for {request.tool_name!r}."
        )

    # ------------------------------------------------------------------
    # validate — a separate observation, never a re-read of execute's return
    # ------------------------------------------------------------------
    async def validate(self, request: AdapterRequest) -> AdapterResult:
        """Look at the simulated world and report what is actually there.

        This does not consult what :meth:`execute` returned. That separation is
        the whole reason ``EXECUTED`` and ``SUCCEEDED`` are different states:
        an adapter that validated by echoing its own return value would confirm
        nothing at all.
        """
        asset_id = request.target.asset_id
        if asset_id is None:  # pragma: no cover - import rule 7 prevents this
            raise TargetUnavailableError("Validation requires a resolved asset.")

        if request.tool_name == _SERVICE_RESTART_TOOL:
            state = await simulated_state(asset_id)
            return AdapterResult(
                outcome=(
                    AdapterOutcome.SUCCESS if state.running else AdapterOutcome.FAILURE
                ),
                payload={"running": state.running, "pid": state.pid},
            )
        if request.tool_name == _ROTATE_KEY_TOOL:
            state = await simulated_state(asset_id)
            slot = str(request.payload.get("key_slot", "primary"))
            present = slot in state.key_slots
            return AdapterResult(
                outcome=(AdapterOutcome.SUCCESS if present else AdapterOutcome.FAILURE),
                # The slot name and whether a key exists. Never key material,
                # and never the identifier's derivation.
                payload={"key_slot": slot, "rotated": present},
            )
        raise AdapterUnavailableError(
            f"{self.adapter_id} cannot validate {request.tool_name!r}."
        )

    # ------------------------------------------------------------------
    async def _device_status(self, request: AdapterRequest) -> AdapterResult:
        """Report an asset's status from ACOP's own CMDB.

        Reads M2 rather than inventing a reply, so the Class 1 path is proven
        against real data and a retired or wrongly typed asset produces a
        genuine ``INVALID_TARGET`` from the policy engine rather than a
        fabricated success here.
        """
        target = request.target
        if target.asset_id is None:  # pragma: no cover - rule 7 prevents this
            raise TargetUnavailableError("A device status needs a resolved asset.")
        if target.display_name == SIM_UNREACHABLE:
            raise TargetUnavailableError(
                "The simulated target refused the connection.",
                context={"asset_id": str(target.asset_id)},
            )

        facts: list[dict[str, Any]] | None = None
        if request.payload.get("include_facts"):
            facts = await self._current_facts(request, target.asset_id)

        return AdapterResult(
            outcome=AdapterOutcome.SUCCESS,
            payload={
                "asset_id": str(target.asset_id),
                "display_name": target.display_name,
                "asset_type": target.asset_type,
                "reachable": True,
                "facts": facts,
                "observed_at": datetime.now(UTC),
            },
        )

    async def _current_facts(
        self, request: AdapterRequest, asset_id: uuid.UUID
    ) -> list[dict[str, Any]]:
        """Live facts for an asset, as predicate/status pairs.

        Values are deliberately *not* returned. A fact value can be anything a
        collector saw, including a configuration line; the summary a tool
        returns names what is known, and the CMDB API is where values are read
        under their own authorization.
        """
        database = request.services.database
        if database is None:
            return []
        from acop.models.fact import AssetFact

        async with database.session() as session:
            rows = (
                await session.execute(
                    select(AssetFact.predicate, AssetFact.verification_status)
                    .where(
                        AssetFact.asset_id == asset_id,
                        AssetFact.valid_to.is_(None),
                    )
                    .order_by(AssetFact.predicate)
                )
            ).all()
        return [
            {"predicate": predicate, "verification_status": status}
            for predicate, status in rows
        ]

    # ------------------------------------------------------------------
    async def _restart(self, request: AdapterRequest) -> AdapterResult:
        target = request.target
        if target.asset_id is None:  # pragma: no cover - rule 7 prevents this
            raise TargetUnavailableError("A restart needs a resolved asset.")

        if target.display_name == SIM_UNREACHABLE:
            raise AdapterUnavailableError(
                "The simulated service manager did not respond.",
                context={"asset_id": str(target.asset_id)},
            )
        if target.display_name == SIM_SLOW:
            # Deliberately longer than the tool's declared timeout. The
            # dispatcher cancels from outside, which is the point: an adapter
            # cannot extend its own deadline.
            await asyncio.sleep(request.timeout_seconds + 5)

        drain = int(request.payload.get("drain_seconds", 0))
        if drain:
            # Bounded to 30 by the input schema, and scaled down so the
            # acceptance suite is not slow. The behaviour under test is that
            # the parameter reaches the adapter, not real draining.
            await asyncio.sleep(min(drain, 30) / 1000)

        async with _LOCK:
            state = _STATE.setdefault(target.asset_id, SimulatedService())
            previous = "running" if state.running else "stopped"
            state.restarts += 1
            state.pid += 1
            state.last_restarted_at = datetime.now(UTC)
            # The one interesting case: the adapter reports success and the
            # service is nevertheless not running afterwards. Exactly the gap
            # between EXECUTED and SUCCEEDED that validation exists to catch.
            state.running = target.display_name != SIM_STAYS_DOWN
            pid = state.pid

        return AdapterResult(
            outcome=AdapterOutcome.SUCCESS,
            payload={
                "asset_id": str(target.asset_id),
                "restart_initiated": True,
                "previous_state": previous,
                "simulated_pid": pid,
                "initiated_at": datetime.now(UTC),
            },
            rollback_hint={
                "previous_state": previous,
                "note": (
                    "ACOP performs no automatic rollback. Restore the previous "
                    "state through the service's own management path."
                ),
            },
        )

    async def _rotate_key(self, request: AdapterRequest) -> AdapterResult:
        target = request.target
        if target.asset_id is None:  # pragma: no cover - rule 7 prevents this
            raise TargetUnavailableError("A rotation needs a resolved asset.")
        if target.display_name == SIM_UNREACHABLE:
            raise AdapterUnavailableError("The simulated key store did not respond.")

        slot = str(request.payload["key_slot"])
        # An opaque identifier, generated here and never derived from anything
        # secret. There is no key material in this adapter to leak, which is
        # the strongest form of "no key material appears in output".
        identifier = f"simkey-{uuid.uuid4().hex[:16]}"
        async with _LOCK:
            state = _STATE.setdefault(target.asset_id, SimulatedService())
            state.key_slots[slot] = identifier

        return AdapterResult(
            outcome=AdapterOutcome.SUCCESS,
            payload={
                "asset_id": str(target.asset_id),
                "key_slot": slot,
                "key_identifier": identifier,
                "rotated_at": datetime.now(UTC),
            },
        )


SIMULATED_ADAPTER = register_adapter(SimulatedAdapter())

__all__ = [
    "SIMULATED_ADAPTER",
    "SIM_SLOW",
    "SIM_STAYS_DOWN",
    "SIM_UNREACHABLE",
    "SimulatedAdapter",
    "SimulatedService",
    "reset_simulation",
    "simulated_state",
]
