"""The reaper and the approval sweeper: closing what nothing else will close.

Two background duties, deliberately separate because they mean different
things.

**The reaper** deals with a worker that is gone. An invocation in ``EXECUTING``
whose lease has expired is the one genuinely hard case in the milestone: the
adapter was called, the process died, and ACOP **does not know** whether the
change landed. There are three ways to record that and only one is honest.

* ``FAILED`` is false, and dangerous: it invites a retry that double-executes.
* ``SUCCEEDED`` is false in the other direction, and worse.
* ``EXECUTION_INDETERMINATE`` says exactly what is true.

So that is what it records, and such an invocation is **never retried
automatically**. It is closed by a human recording what they determined, in
:mod:`acop.services.tools.reconciliation` - an appended judgement beside the
execution record, never a rewrite of it.

A lost **validation** lease is different and gets a different answer. The
adapter already reported success, so the execution outcome is known; what is
unknown is the confirmation. That is ``VALIDATION_FAILED`` with
``validation_outcome = INDETERMINATE``, which is honest about both halves: it
happened, and nobody checked.

**The reaper is allowed to be wrong about a row, and must lose when it is.**
It selects candidates without locking them, so between that read and its write
the worker it had given up on can finish and record ``SUCCEEDED``. Its write is
therefore a compare-and-set on the state *and* the exact lease it judged
expired: a row that moved on matches zero rows, and the reaper leaves it
completely alone rather than relabelling a validated execution as an unknown
outcome that nothing retries and a human has to close by hand. Losing is per
row - it is logged, audited and counted out of the total, and the sweep
continues - because one live worker must not stop the reaper closing the
genuinely dead ones behind it.

**The sweeper** deals with time passing. An approval that was never given, or
was given and never used, expires. It is deliberately *not* the authority on
expiry - the final execution gate is. A sweeper alone would let a dispatcher
that had been paused for a week execute last week's approval the moment it came
back. The sweeper is tidiness: it stops a queue filling with requests nobody
will ever approve.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import SYSTEM_PRINCIPAL
from acop.core.logging import get_logger
from acop.db.session import Database
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.tool import ToolInvocation
from acop.models.tool_vocabulary import (
    ERROR_PHRASES,
    InvocationState,
    PolicyReason,
    ToolErrorCategory,
    ValidationOutcome,
)
from acop.schemas.audit import AuditEventCreate
from acop.services.audit import AuditService
from acop.services.tools.state import release_lease, transition
from acop.tools.errors import StaleTransitionError

logger = get_logger(__name__)


class InvocationReaper:
    """Closes invocations whose worker or whose approval window is gone."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def reap_expired_leases(self, *, limit: int = 50) -> int:
        """Close in-flight invocations whose lease has elapsed.

        Returns:
            How many were closed. A candidate that finished under the reaper's
            feet is not counted, because it was not closed by this sweep and a
            count that said otherwise would report corruption as work done.
        """
        now = datetime.now(UTC)
        closed = 0
        async with self._database.session() as session:
            audit = AuditService(session, database=self._database)
            rows = (
                (
                    await session.execute(
                        select(ToolInvocation)
                        .where(
                            ToolInvocation.state.in_(
                                (
                                    InvocationState.EXECUTING.value,
                                    InvocationState.VALIDATING.value,
                                )
                            ),
                            ToolInvocation.lease_expires_at < now,
                        )
                        .order_by(ToolInvocation.lease_expires_at)
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            for invocation in rows:
                if await self._reap_one(session, audit, invocation, now):
                    closed += 1
        if closed:
            logger.warning("tools.reaper.closed", count=closed)
        return closed

    async def _reap_one(
        self,
        session: AsyncSession,
        audit: AuditService,
        invocation: ToolInvocation,
        now: datetime,
    ) -> bool:
        """Close one candidate, or stand down if it is no longer the reaper's.

        Returns:
            Whether this row was actually closed here.
        """
        # The lease the *candidate query* judged expired, asserted in the write
        # rather than trusted from the read. Between the two the worker can
        # finish, or a replacement can claim the row and mint a new lease; both
        # change these columns, and both mean this decision is out of date.
        held_lease = {
            "executor_lease_id": invocation.executor_lease_id,
            "lease_expires_at": invocation.lease_expires_at,
        }
        try:
            if invocation.state == InvocationState.EXECUTING.value:
                await release_lease(
                    session,
                    invocation,
                    to_state=InvocationState.EXECUTION_INDETERMINATE,
                    reason=ToolErrorCategory.EXECUTION_INDETERMINATE.value,
                    # Rendered, not the object: ``detail`` is JSONB and a
                    # datetime has no JSON form, so passing one would abort the
                    # very transaction that records the interruption.
                    detail={
                        "lease_expired_at": (
                            invocation.lease_expires_at.isoformat()
                            if invocation.lease_expires_at is not None
                            else None
                        )
                    },
                    expected=held_lease,
                    finished_at=now,
                    error_category=ToolErrorCategory.EXECUTION_INDETERMINATE.value,
                    error_detail_sanitized=ERROR_PHRASES[
                        ToolErrorCategory.EXECUTION_INDETERMINATE
                    ],
                )
                severity = AuditSeverity.CRITICAL
                message = (
                    f"{invocation.tool_name}@{invocation.tool_version} was "
                    "interrupted mid-execution. The outcome is unknown and a human "
                    "must determine it."
                )
            else:
                # VALIDATING. The change happened; the confirmation is what is
                # missing, and the two must not be conflated.
                await release_lease(
                    session,
                    invocation,
                    to_state=InvocationState.VALIDATION_FAILED,
                    reason=ToolErrorCategory.VALIDATION_FAILED.value,
                    expected=held_lease,
                    validation_outcome=ValidationOutcome.INDETERMINATE.value,
                    validated_at=now,
                    finished_at=now,
                    error_category=ToolErrorCategory.VALIDATION_FAILED.value,
                    error_detail_sanitized=ERROR_PHRASES[
                        ToolErrorCategory.VALIDATION_FAILED
                    ],
                )
                severity = AuditSeverity.WARNING
                message = (
                    f"{invocation.tool_name}@{invocation.tool_version} executed but "
                    "validation could not be completed."
                )
        except StaleTransitionError:
            await self._stood_down(audit, invocation)
            return False
        await audit.record(
            AuditEventCreate(
                action="tool.reap",
                outcome=AuditOutcome.FAILURE,
                severity=severity,
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=message,
                context={"state": invocation.state},
            ),
            SYSTEM_PRINCIPAL,
            request_id=invocation.request_id,
        )
        return True

    @staticmethod
    async def _stood_down(audit: AuditService, invocation: ToolInvocation) -> None:
        """Record that the reaper found the row already closed, and wrote nothing.

        Not a failure and not an error: the worker the reaper had written off
        came back and recorded a real outcome, which is the best available
        result. It is audited because the alternative reading - a reaper that
        silently skipped a row - is indistinguishable from a reaper that is not
        running, and only one of those needs somebody paged.

        ``transition`` has already refreshed the instance, so the state named
        here is the one PostgreSQL holds rather than the one the candidate
        query returned.
        """
        logger.info(
            "tools.reaper.stood_down",
            invocation_id=str(invocation.id),
            state=invocation.state,
        )
        await audit.record(
            AuditEventCreate(
                action="tool.reap",
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.NOTICE,
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"{invocation.tool_name}@{invocation.tool_version} completed "
                    "before it could be reaped; its recorded outcome was left "
                    "untouched."
                ),
                context={"state": invocation.state},
            ),
            SYSTEM_PRINCIPAL,
            request_id=invocation.request_id,
        )


class ApprovalSweeper:
    """Expires approvals that were never given, or never used."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def expire_stale(self, *, limit: int = 100) -> int:
        """Expire pending and approved-but-unexecuted invocations.

        Both windows are measured against the invocation's **snapshotted**
        ``approval_ttl_seconds``, not the tool's current value. Shortening a
        tool's TTL tomorrow must not retroactively expire an approval granted
        under yesterday's rules, and lengthening it must not extend one.
        """
        now = datetime.now(UTC)
        expired = 0
        async with self._database.session() as session:
            audit = AuditService(session, database=self._database)
            candidates = (
                (
                    await session.execute(
                        select(ToolInvocation)
                        .where(
                            ToolInvocation.state.in_(
                                (
                                    InvocationState.AWAITING_APPROVAL.value,
                                    InvocationState.READY.value,
                                )
                            ),
                            ToolInvocation.approval_required.is_(True),
                        )
                        .order_by(ToolInvocation.requested_at)
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            for invocation in candidates:
                anchor = invocation.approved_at or invocation.requested_at
                if anchor + timedelta(seconds=invocation.approval_ttl_seconds) > now:
                    continue
                try:
                    await transition(
                        session,
                        invocation,
                        to_state=InvocationState.EXPIRED,
                        reason=PolicyReason.APPROVAL_EXPIRED.value,
                        finished_at=now,
                        error_category=ToolErrorCategory.APPROVAL_EXPIRED.value,
                        error_detail_sanitized=ERROR_PHRASES[
                            ToolErrorCategory.APPROVAL_EXPIRED
                        ],
                    )
                except StaleTransitionError:
                    # The candidates were read without a lock, so an approval or
                    # a cancellation can land on one mid-sweep. Skipping it is
                    # the whole correction: expiring a row that has since been
                    # approved would revoke a decision a person actually made.
                    # Per candidate rather than per sweep, because one such row
                    # must not stop the others being expired.
                    logger.info(
                        "tools.sweeper.stood_down",
                        invocation_id=str(invocation.id),
                        state=invocation.state,
                    )
                    continue
                await audit.record(
                    AuditEventCreate(
                        action="tool.expire",
                        outcome=AuditOutcome.FAILURE,
                        severity=AuditSeverity.NOTICE,
                        resource_type="tool_invocation",
                        resource_id=str(invocation.id),
                        permission_class=invocation.permission_class,
                        message=(
                            f"{invocation.tool_name}@{invocation.tool_version} "
                            "expired before it was executed."
                        ),
                        context={"ttl_seconds": invocation.approval_ttl_seconds},
                    ),
                    SYSTEM_PRINCIPAL,
                    request_id=invocation.request_id,
                )
                expired += 1
        if expired:
            logger.info("tools.sweeper.expired", count=expired)
        return expired


__all__ = ["ApprovalSweeper", "InvocationReaper"]
