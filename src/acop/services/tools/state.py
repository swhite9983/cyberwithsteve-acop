"""State transitions, enforced twice.

Every move an invocation makes is checked in two independent places:

1. **In Python**, against
   :data:`~acop.models.tool_vocabulary.LEGAL_TRANSITIONS`. This catches a bug
   during development with a clear error naming the attempted move.
2. **In PostgreSQL**, by a ``WHERE state = :expected`` predicate on the UPDATE.
   This catches the case Python cannot: two workers racing, where both read
   ``READY`` and both believe the move is legal.

The second is the one that matters operationally, and it is why **no function
in this module writes ``state`` by mutating the ORM object**. Every one of them
emits an explicit ``UPDATE ... WHERE id = :id AND state = :source``, so the
predicate is evaluated by the database against the row as it is *now*, not
against what this process last read. Under READ COMMITTED the second writer
blocks on the row lock and, when it wakes, PostgreSQL re-evaluates the WHERE
clause against the *new* committed row version - which no longer says
``READY``. It matches zero rows. That is EvalPlanQual, and it is why a claim
needs no advisory lock, no ``SELECT FOR UPDATE`` round trip and no retry loop:
one writer gets the row, and the loser learns so immediately.

The same statement shape says the second thing a claim cannot say by itself -
that the winner *still* holds what it won. A claim commits and the dispatcher
then works in a new transaction, so the lease can be reaped in between; see
:func:`record_final_gate_if_owned`, which re-asserts ownership as the write of
the final-gate decision rather than as a read the reaper could overtake.
:func:`transition` accepts the same kind of assertion through ``expected``, so
a caller whose right to move the row rests on more than its state - the reaper,
whose right rests on a specific expired lease - can say so in the predicate
instead of trusting a value it read seconds ago.

**Losing means writing nothing.** A transition that matches zero rows raises
:class:`~acop.tools.errors.StaleTransitionError` without touching the outcome
columns, because the row now holds somebody else's newer and truer answer.
Repairing it, retrying it or forcing it would replace a completed execution
with an older worker's guess. The attempt is appended to the event history as a
no-op instead, so the history records that a second writer arrived and was
refused. That evidence survives only for a caller that catches the error and
commits; a caller that lets it propagate is rolled back with it, which is the
correct trade for a request path where a stale write is a defect.

None of this is exactly-once. It is at most one writer per state, which is a
different and weaker claim: a transition can be lost, and when it is, the loser
is told rather than allowed to overwrite.

**Every transition appends an event.** The event table is gap-free per
invocation, ordered by a counter rather than a timestamp, because two
transitions can share a millisecond and "what happened first" must not depend
on clock resolution.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ColumnElement, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.logging import get_logger
from acop.core.redaction import redact
from acop.models.tool import ToolInvocation, ToolInvocationEvent
from acop.models.tool_vocabulary import (
    GateDecision,
    InvocationState,
    PolicyReason,
    is_legal_transition,
)
from acop.tools.errors import InvalidStateTransitionError, StaleTransitionError

logger = get_logger(__name__)


async def next_sequence(session: AsyncSession, invocation_id: uuid.UUID) -> int:
    """The next event sequence number for an invocation.

    ``MAX + 1`` rather than a counter column, because the unique constraint on
    ``(invocation_id, sequence)`` is what actually guarantees correctness: if
    two writers compute the same number, one of them fails the insert rather
    than silently reordering history.
    """
    highest = await session.scalar(
        select(func.max(ToolInvocationEvent.sequence)).where(
            ToolInvocationEvent.invocation_id == invocation_id
        )
    )
    return int(highest or 0) + 1


async def append_event(
    session: AsyncSession,
    *,
    invocation_id: uuid.UUID,
    from_state: InvocationState | None,
    to_state: InvocationState,
    reason: str,
    actor_subject: str | None = None,
    detail: dict[str, Any] | None = None,
) -> ToolInvocationEvent:
    """Record one transition.

    ``detail`` is passed through M1's :func:`redact` as defence in depth. It
    should already be secret-free - import rule 9 makes tool input incapable of
    carrying a secret, and adapter text never reaches here - so a redaction
    that actually changes something indicates a bug upstream rather than a
    save. It costs a dictionary walk and removes a whole class of accident.
    """
    event = ToolInvocationEvent(
        invocation_id=invocation_id,
        sequence=await next_sequence(session, invocation_id),
        from_state=from_state.value if from_state is not None else None,
        to_state=to_state.value,
        actor_subject=actor_subject,
        reason=reason,
        detail=redact(detail or {}),
    )
    session.add(event)
    await session.flush()
    return event


async def transition(
    session: AsyncSession,
    invocation: ToolInvocation,
    *,
    to_state: InvocationState,
    reason: str,
    actor_subject: str | None = None,
    detail: dict[str, Any] | None = None,
    expected: Mapping[str, Any] | None = None,
    **columns: Any,
) -> None:
    """Move an invocation in the caller's session, compare-and-set.

    The source state is the one the caller is holding, and it goes into the
    predicate rather than being assumed: the ORM object was read at some earlier
    point in the transaction and a background sweeper may have moved the row
    since. ``expected`` adds any further column the caller's right to write
    depends on - the reaper's lease id and expiry - so that "the row I looked
    at" is asserted by the database rather than by this process's memory.

    The ORM object is deliberately **not** mutated. Assigning attributes and
    flushing is what produced an ``UPDATE ... WHERE id = :id`` with no state
    predicate, and it would also leave the instance dirty after a lost race, so
    the session's commit would re-issue the write the CAS just refused. It is
    refreshed from the row instead, won or lost, so every caller that goes on to
    audit, serialise or transition it again sees what PostgreSQL holds.

    Raises:
        InvalidStateTransitionError: The move is not in ``LEGAL_TRANSITIONS``.
        StaleTransitionError: The row no longer matches the predicate. Nothing
            was written, and the caller must not write anything either.
    """
    source = InvocationState(invocation.state)
    if not is_legal_transition(source, to_state):
        raise InvalidStateTransitionError(
            f"{source.value} -> {to_state.value} is not a legal transition.",
            context={
                "invocation_id": str(invocation.id),
                "from_state": source.value,
                "to_state": to_state.value,
            },
        )
    predicates: list[ColumnElement[bool]] = [
        ToolInvocation.id == invocation.id,
        ToolInvocation.state == source.value,
    ]
    predicates.extend(
        getattr(ToolInvocation, name) == value for name, value in (expected or {}).items()
    )
    result = await session.execute(
        update(ToolInvocation)
        .where(*predicates)
        .values(state=to_state.value, **columns)
        .returning(ToolInvocation.id)
    )
    won = result.scalar_one_or_none() is not None
    await session.refresh(invocation)
    if not won:
        observed = InvocationState(invocation.state)
        logger.warning(
            "tools.state.stale_transition",
            invocation_id=str(invocation.id),
            expected_state=source.value,
            observed_state=observed.value,
            to_state=to_state.value,
        )
        # Appended as a no-op - ``from_state`` equals ``to_state`` - for the
        # same reason the dispatcher appends a gate evaluation it went on to
        # lose: the attempt happened, and the only record that a second writer
        # was ever here would otherwise be a log line.
        await append_event(
            session,
            invocation_id=invocation.id,
            from_state=observed,
            to_state=observed,
            reason=reason,
            actor_subject=actor_subject,
            detail={
                "stale_transition": True,
                "expected_state": source.value,
                "attempted_to_state": to_state.value,
            },
        )
        raise StaleTransitionError(
            f"{invocation.id} is {observed.value}, not {source.value}: "
            f"the move to {to_state.value} was not applied.",
            context={
                "invocation_id": str(invocation.id),
                "expected_state": source.value,
                "observed_state": observed.value,
                "to_state": to_state.value,
            },
        )
    await append_event(
        session,
        invocation_id=invocation.id,
        from_state=source,
        to_state=to_state,
        reason=reason,
        actor_subject=actor_subject,
        detail=detail,
    )


async def claim_for_execution(
    session: AsyncSession,
    invocation_id: uuid.UUID,
    *,
    lease_id: uuid.UUID,
    lease_expires_at: datetime,
    deadline_at: datetime,
) -> bool:
    """Atomically move ``READY -> EXECUTING``, returning whether we won.

    One statement, no read-then-write, no lock taken by hand. The
    ``state = 'READY'`` predicate is the whole concurrency control: a second
    worker's UPDATE matches zero rows and it returns ``False`` without having
    touched an adapter.

    ``attempt_count`` is incremented in the same statement so that a lease
    obtained is always an attempt recorded - a separate UPDATE could be lost to
    a crash between the two and leave an execution unaccounted for.
    """
    result = await session.execute(
        update(ToolInvocation)
        .where(
            ToolInvocation.id == invocation_id,
            ToolInvocation.state == InvocationState.READY.value,
        )
        .values(
            state=InvocationState.EXECUTING.value,
            executor_lease_id=lease_id,
            lease_expires_at=lease_expires_at,
            deadline_at=deadline_at,
            started_at=datetime.now(UTC),
            attempt_count=ToolInvocation.attempt_count + 1,
        )
        .returning(ToolInvocation.id)
    )
    won = result.scalar_one_or_none() is not None
    if won:
        await append_event(
            session,
            invocation_id=invocation_id,
            from_state=InvocationState.READY,
            to_state=InvocationState.EXECUTING,
            reason=PolicyReason.ALLOWED.value,
            detail={"lease_id": str(lease_id)},
        )
    return won


async def record_final_gate_if_owned(
    session: AsyncSession,
    invocation_id: uuid.UUID,
    *,
    lease_id: uuid.UUID,
    decision: GateDecision,
    reason: str,
    event_id: uuid.UUID,
) -> bool:
    """Write the final-gate decision, but only while the lease is still ours.

    The other half of :func:`claim_for_execution`, and deliberately the same
    mechanism: the predicate is the concurrency control and the write is what
    proves it held. The claim commits and the dispatcher then opens a *second*
    transaction to gate and dispatch, so in between the reaper can find the
    lease expired, move the row to ``EXECUTION_INDETERMINATE`` and clear it.
    A worker that did not notice would call the adapter for an execution
    somebody else has already recorded as interrupted.

    Re-reading the row and comparing the lease in Python does not close that:
    the reaper can commit between the SELECT and the dispatch, which is the
    identical window moved one layer down. Only a compare-and-set closes it.
    Under READ COMMITTED this UPDATE takes the row lock, and if it had to wait
    for a concurrent writer PostgreSQL re-evaluates this WHERE clause against
    the newly committed row version - EvalPlanQual - so a lease that was reaped
    or reclaimed matches zero rows. Winning also holds that row lock for the
    rest of the caller's transaction, which is what keeps the reaper out for
    the duration of the adapter call.

    ``now()`` is PostgreSQL's clock rather than the worker's, because a worker
    whose clock has drifted is exactly the worker whose lease is most likely to
    have been reaped underneath it, and it must not be the one deciding whether
    its own lease is still live.

    Returns:
        ``False`` when the row now belongs to someone else. The caller must not
        dispatch and must not write the invocation's state: this is at-most-once
        per claim, and overwriting the new owner's row is the corruption the
        assertion exists to prevent.
    """
    result = await session.execute(
        update(ToolInvocation)
        .where(
            ToolInvocation.id == invocation_id,
            ToolInvocation.state == InvocationState.EXECUTING.value,
            ToolInvocation.executor_lease_id == lease_id,
            ToolInvocation.lease_expires_at > func.now(),
        )
        .values(
            final_gate_decision=decision.value,
            final_gate_reason=reason,
            final_gate_at=func.now(),
            final_gate_event_id=event_id,
        )
        .returning(ToolInvocation.id)
    )
    return result.scalar_one_or_none() is not None


async def release_lease(
    session: AsyncSession,
    invocation: ToolInvocation,
    *,
    to_state: InvocationState,
    reason: str,
    detail: dict[str, Any] | None = None,
    expected: Mapping[str, Any] | None = None,
    **columns: Any,
) -> None:
    """Finish an in-flight invocation and drop its lease in one move.

    The lease columns must be cleared in the same statement that leaves an
    in-flight state, because a CHECK constraint ties them together: a row in
    ``EXECUTING`` or ``VALIDATING`` has a lease and no other row does. Clearing
    them separately would make the intermediate state unrepresentable and abort
    the transaction - which is the constraint doing its job.

    ``expected`` passes through to :func:`transition`, so a caller that is
    closing *a particular* lease can assert which one rather than clearing
    whichever lease it happens to find.
    """
    await transition(
        session,
        invocation,
        to_state=to_state,
        reason=reason,
        detail=detail,
        expected=expected,
        executor_lease_id=None,
        lease_expires_at=None,
        **columns,
    )


__all__ = [
    "append_event",
    "claim_for_execution",
    "next_sequence",
    "record_final_gate_if_owned",
    "release_lease",
    "transition",
]
