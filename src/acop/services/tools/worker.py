"""The background worker: polls for ``READY``, reaps, sweeps.

A single asyncio task per process, started in the application lifespan. It owns
no execution logic of its own - it calls
:meth:`~acop.services.tools.dispatcher.ExecutionDispatcher.execute_once`, the
same method an inline Class 0 request awaits. That is the F2 decision made
concrete: the worker is a *scheduler*, not a second execution path.

**Polling rather than LISTEN/NOTIFY.** At this scale a one-second poll on a
partial index over ``state = 'READY'`` costs almost nothing and has no failure
mode more interesting than a one-second delay. ``LISTEN/NOTIFY`` would add a
dedicated connection, a reconnect path, and a class of missed-notification bug
that only appears under load. If the queue ever justifies it, the change is
local to this file.

**Concurrency is safe by construction, not by coordination.** Several processes
may run this loop. Each tries to claim rows with a compare-and-set UPDATE, and
PostgreSQL's row-level locking means exactly one wins. No leader election, no
advisory lock, no distributed queue.

**The loop never dies of one bad invocation.** An exception from any single
iteration is logged and swallowed; the alternative is a worker that stops
dispatching everything because one tool misbehaved.
"""

from __future__ import annotations

import asyncio
import contextlib

from sqlalchemy import select

from acop.config.settings import Settings
from acop.core.logging import get_logger
from acop.db.session import Database
from acop.models.tool import ToolInvocation
from acop.models.tool_vocabulary import InvocationState
from acop.services.tools.dispatcher import ExecutionDispatcher
from acop.services.tools.reaper import ApprovalSweeper, InvocationReaper

logger = get_logger(__name__)


class ToolWorker:
    """Drives the dispatcher, the reaper and the sweeper on a timer."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        dispatcher: ExecutionDispatcher,
    ) -> None:
        self._database = database
        self._settings = settings
        self._dispatcher = dispatcher
        self._reaper = InvocationReaper(database)
        self._sweeper = ApprovalSweeper(database)
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        """Begin polling, unless the deployment disabled it."""
        if not self._settings.tools_dispatcher_enabled:
            logger.info("tools.worker.disabled")
            return
        if self._task is not None:  # pragma: no cover - defensive
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="acop-tool-worker")
        logger.info(
            "tools.worker.started",
            poll_seconds=self._settings.tools_dispatcher_poll_seconds,
        )

    async def stop(self) -> None:
        """Ask the loop to finish and wait briefly for it.

        Deliberately does not cancel an in-flight execution: an adapter that is
        mid-change should be allowed to finish and record its outcome. If the
        process is killed anyway, the lease expires and the reaper records
        ``EXECUTION_INDETERMINATE`` - which is exactly what happened.
        """
        self._stopping.set()
        task, self._task = self._task, None
        if task is None:
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(task, timeout=5.0)
        if not task.done():  # pragma: no cover - shutdown race
            task.cancel()
        logger.info("tools.worker.stopped")

    # ------------------------------------------------------------------
    async def _loop(self) -> None:
        interval = self._settings.tools_dispatcher_poll_seconds
        reap_every = max(
            1, int(self._settings.tools_reaper_interval_seconds / max(interval, 0.01))
        )
        tick = 0
        while not self._stopping.is_set():
            tick += 1
            try:
                await self._dispatch_ready()
                if tick % reap_every == 0:
                    await self._reaper.reap_expired_leases()
                    await self._sweeper.expire_stale()
            except Exception:
                # One bad invocation must not stop the worker dispatching
                # everything else.
                logger.exception("tools.worker.iteration_failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)

    async def _dispatch_ready(self, *, limit: int = 10) -> int:
        """Claim and run whatever is ready. Returns how many were attempted."""
        async with self._database.session() as session:
            ids = list(
                (
                    await session.execute(
                        select(ToolInvocation.id)
                        .where(ToolInvocation.state == InvocationState.READY.value)
                        .order_by(ToolInvocation.requested_at)
                        .limit(limit)
                    )
                ).scalars()
            )
        for invocation_id in ids:
            # Losing the claim is normal, not an error: another worker, or the
            # inline caller, got there first.
            await self._dispatcher.execute_once(invocation_id)
        return len(ids)


__all__ = ["ToolWorker"]
