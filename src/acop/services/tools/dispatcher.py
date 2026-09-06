"""The one execution path, and the final gate that guards it.

**There is exactly one way an invocation executes**, and this is it. Class 0
and Class 1 do not have a fast path; Class 2 and Class 3 do not have a special
path. The approval *branch* differs - Class 2/3 pass through
``AWAITING_APPROVAL`` and ``APPROVED`` on their way to ``READY`` - but from
``READY`` onward every class travels the same code.

A Class 0 API request may *await* this dispatcher for a fast tool rather than
returning 202 immediately. That is waiting on the shared mechanism, not
bypassing it: the same claim, the same final gate, the same audit, the same
adapter dispatch. No endpoint anywhere calls an adapter directly.

**The final execution gate is the last word.** Request-time authorization is
necessary and not sufficient, because time passes between authorization and
execution - a tool can be disabled, a capability prohibited, an approval can
expire, and a request can be altered. So immediately after winning the claim
and before touching an adapter, the gate re-checks, in order:

1. capability binding, from the code registry - a tool removed from the catalog
   must not run from a stale row;
2. the tool's **current** lifecycle state, from the database;
3. the tool's **current** prohibition status, from the code registry;
4. **execution-envelope integrity** - the digest recomputed from the stored
   canonical input must equal the stored digest;
5. approval validity, where the invocation's snapshot requires it.

**Integrity is checked before approval, and that order is the right one.** If a
tampered input were reported as an approval failure, the recorded reason would
be ``approval_missing`` or ``approval_envelope_mismatch`` - which reads as a
process problem and invites someone to re-approve. Checking the digest first
means the same request is refused as ``envelope_integrity_failed``, which is
what it is: the stored request is not the one that was authorised, and nothing
an approver does makes it safe to run.

A failure at the gate is ``EXPIRED`` with ``final_gate_decision = DENY``, not
``FAILED``: nothing was attempted, and recording it as a failure would be a
false statement about the target.

**The gate also re-asserts that the claim is still ours.** Claiming commits, and
the gate then runs in a second transaction, so between the two the reaper can
find the lease expired, record ``EXECUTION_INDETERMINATE`` and clear it. The
write of the gate decision is therefore itself a compare-and-set on state, lease
id and expiry - see
:func:`~acop.services.tools.state.record_final_gate_if_owned` - and a worker
that matches zero rows dispatches nothing and writes nothing to the row. This is
at-most-once per claim; the assertion is what closes the window in which "per
claim" could otherwise be exceeded.

**Every gate evaluation leaves an event, and the decision names it.** The
evaluation is appended to ``tool_invocation_event`` before ownership is
asserted, so a stale worker's evaluation is recorded whether or not it won, and
``final_gate_event_id`` points at the one that produced the decision now on the
row. Nothing is deleted and no prior evaluation is rewritten: the history says
how many workers looked at this invocation and what each of them concluded.

**Timeouts are enforced from outside.** ``asyncio.wait_for`` cancels an adapter
that ignores its deadline; an adapter cannot extend its own timeout because it
is not the thing holding the clock.

**A timeout is not a retryable failure.** A request that timed out may still be
in flight on the far side, so retrying it could act twice. Only
``ADAPTER_UNAVAILABLE`` and ``TARGET_UNAVAILABLE`` - the categories where "it
did not happen" is knowable - are ever retried, and only when the tool also
declares its adapter idempotent.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import SYSTEM_PRINCIPAL
from acop.config.settings import Settings
from acop.core.logging import get_logger
from acop.db.session import Database
from acop.models.asset import Asset, AssetIdentifier
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.tool import ToolInvocation, ToolRegistration
from acop.models.tool_vocabulary import (
    ERROR_PHRASES,
    PROHIBITED_CAPABILITIES,
    AdapterOutcome,
    GateDecision,
    InvocationState,
    PolicyReason,
    TargetKind,
    ToolErrorCategory,
    ToolLifecycle,
    ValidationOutcome,
)
from acop.schemas.audit import AuditEventCreate
from acop.services.audit import AuditService
from acop.services.tools.approval import approval_failure, approved_rows
from acop.services.tools.sanitize import sanitize_output
from acop.services.tools.state import (
    append_event,
    claim_for_execution,
    record_final_gate_if_owned,
    release_lease,
    transition,
)
from acop.tools.adapters.base import (
    AdapterRequest,
    AdapterServices,
    ResolvedTarget,
    resolve_adapter,
)
from acop.tools.contract import ToolDefinition
from acop.tools.envelope import build_envelope, build_target_block, envelope_digest
from acop.tools.errors import (
    AdapterUnavailableError,
    TargetUnavailableError,
    ToolError,
    ToolTimeoutError,
)
from acop.tools.registry import get_definition

logger = get_logger(__name__)

_ACTION = "tool.execute"


@dataclass(frozen=True, slots=True)
class GateResult:
    """The final gate's verdict."""

    allowed: bool
    reason: PolicyReason
    definition: ToolDefinition | None = None

    @property
    def decision(self) -> GateDecision:
        return GateDecision.ALLOW if self.allowed else GateDecision.DENY


class ExecutionDispatcher:
    """Claims, gates, executes and validates. The only path to an adapter."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        *,
        services: AdapterServices | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._services = services or AdapterServices(database=database, settings=settings)

    # ------------------------------------------------------------------
    async def execute_once(self, invocation_id: uuid.UUID) -> InvocationState:
        """Take one invocation from ``READY`` to a terminal state.

        Idempotent against concurrency: if another worker already claimed the
        row, the claim fails and this returns the invocation's current state
        without having touched an adapter.
        """
        lease_id = uuid.uuid4()
        now = datetime.now(UTC)

        async with self._database.session() as session:
            invocation = await session.get(ToolInvocation, invocation_id)
            if invocation is None:
                raise LookupError(f"Invocation {invocation_id} does not exist.")
            if invocation.state != InvocationState.READY.value:
                return InvocationState(invocation.state)

            timeout = float(invocation.execution_parameters.get("timeout_seconds", 30.0))
            claimed = await claim_for_execution(
                session,
                invocation_id,
                lease_id=lease_id,
                lease_expires_at=now
                + timedelta(seconds=self._settings.tools_execution_lease_seconds),
                deadline_at=now + timedelta(seconds=timeout),
            )
            if not claimed:
                await session.refresh(invocation)
                logger.info(
                    "tools.dispatcher.claim_lost",
                    invocation_id=str(invocation_id),
                    state=invocation.state,
                )
                return InvocationState(invocation.state)

        # The claim is committed, and committing it is what ends this
        # transaction's hold on the row. The lease id travels on so that the
        # next transaction can prove the claim is still ours before it acts.
        return await self._run_claimed(invocation_id, lease_id)

    # ------------------------------------------------------------------
    async def _run_claimed(
        self, invocation_id: uuid.UUID, lease_id: uuid.UUID
    ) -> InvocationState:
        async with self._database.session() as session:
            audit = AuditService(session, database=self._database)
            invocation = await session.get(ToolInvocation, invocation_id)
            if invocation is None:  # pragma: no cover - we just claimed it
                raise LookupError(f"Invocation {invocation_id} vanished.")

            gate = await self._final_gate(session, invocation)
            # The evaluation is evidence before it is a decision, so it is
            # appended before anything is asserted about who owns the row and
            # whatever that assertion then says. A gate that ran and lost still
            # ran; recording only the winning evaluation would erase the sole
            # trace that a second worker was ever in here. ``from_state`` equals
            # ``to_state`` because evaluating the gate moves nothing.
            observed = InvocationState(invocation.state)
            event = await append_event(
                session,
                invocation_id=invocation.id,
                from_state=observed,
                to_state=observed,
                reason=gate.reason.value,
                detail={
                    "gate": "final",
                    "decision": gate.decision.value,
                    "reason": gate.reason.value,
                    "lease_id": str(lease_id),
                },
            )
            # Ownership is re-asserted by writing the decision, not by reading
            # the row first: a read leaves the reaper a window between the check
            # and the adapter call. Zero rows means the lease is gone.
            if not await record_final_gate_if_owned(
                session,
                invocation_id,
                lease_id=lease_id,
                decision=gate.decision,
                reason=gate.reason.value,
                event_id=event.id,
            ):
                return await self._abandon_lost_lease(
                    session, audit, invocation, lease_id
                )
            # The row's own values, since the CAS wrote them in SQL: the audit
            # record below must report what PostgreSQL holds, not what this
            # worker intended to put there.
            await session.refresh(invocation)

            if not gate.allowed or gate.definition is None:
                await release_lease(
                    session,
                    invocation,
                    to_state=InvocationState.EXPIRED,
                    reason=gate.reason.value,
                    detail={"gate": "final"},
                    finished_at=datetime.now(UTC),
                    error_category=ToolErrorCategory.POLICY_DENIED.value,
                    error_detail_sanitized=ERROR_PHRASES[ToolErrorCategory.POLICY_DENIED],
                )
                await self._audit_outcome(audit, invocation, AuditOutcome.DENIED)
                return InvocationState.EXPIRED

            state = await self._execute(session, invocation, gate.definition)
            if state is InvocationState.EXECUTED:
                state = await self._after_execution(session, invocation, gate.definition)
            await self._audit_outcome(
                audit,
                invocation,
                AuditOutcome.SUCCESS
                if state is InvocationState.SUCCEEDED
                else AuditOutcome.FAILURE,
            )
            return state

    # ------------------------------------------------------------------
    @staticmethod
    async def _abandon_lost_lease(
        session: AsyncSession,
        audit: AuditService,
        invocation: ToolInvocation,
        lease_id: uuid.UUID,
    ) -> InvocationState:
        """Leave without dispatching, and without writing the invocation.

        The lease was lost between the claim and the gate - reaped, reclaimed,
        cancelled or superseded - so the row is someone else's. Failing closed
        here means writing *nothing* to it: a state written now would overwrite
        the new owner's work, or overwrite the ``EXECUTION_INDETERMINATE`` the
        reaper recorded truthfully with an outcome this worker never observed.
        The lease columns are not cleared either, for the same reason - they
        describe the current owner, not this one.

        What is left behind is only append-only: the gate evaluation the caller
        already recorded, and this audit record naming the loss. Between them
        they say a second worker evaluated this invocation and stopped, which is
        the fact an incident review needs and the fact a silent return would
        have destroyed.
        """
        await session.refresh(invocation)
        current = InvocationState(invocation.state)
        logger.warning(
            "tools.dispatcher.lease_lost",
            invocation_id=str(invocation.id),
            lease_id=str(lease_id),
            state=current.value,
        )
        await audit.record(
            AuditEventCreate(
                action=_ACTION,
                outcome=AuditOutcome.FAILURE,
                severity=AuditSeverity.WARNING,
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"{invocation.tool_name}@{invocation.tool_version} was not "
                    "dispatched: this worker's executor lease was no longer held "
                    "when the final gate was recorded."
                ),
                context={
                    "state": current.value,
                    "held_lease_id": str(lease_id),
                    "current_lease_id": (
                        str(invocation.executor_lease_id)
                        if invocation.executor_lease_id is not None
                        else None
                    ),
                },
            ),
            SYSTEM_PRINCIPAL,
            request_id=invocation.request_id,
        )
        return current

    # ------------------------------------------------------------------
    # The final execution gate
    # ------------------------------------------------------------------
    async def _final_gate(
        self, session: AsyncSession, invocation: ToolInvocation
    ) -> GateResult:
        """Re-check everything that could have changed since authorization."""
        definition = get_definition(invocation.tool_name, invocation.tool_version)
        # 1. Capability binding, again. A tool removed from the catalog between
        #    authorization and execution must not run from a stale row.
        if definition is None:
            return GateResult(False, PolicyReason.CAPABILITY_NOT_BOUND)

        # 2. Current lifecycle, read now rather than trusted from request time.
        #    Disabling a misbehaving tool has to stop work already queued, or
        #    the control is useless during the incident it exists for.
        registration = await session.get(
            ToolRegistration, invocation.tool_registration_id
        )
        if registration is None:  # pragma: no cover - FK guarantees it
            return GateResult(False, PolicyReason.CAPABILITY_NOT_BOUND)
        lifecycle = ToolLifecycle(registration.lifecycle_state)
        if lifecycle is ToolLifecycle.RETIRED:
            return GateResult(False, PolicyReason.TOOL_RETIRED)
        if lifecycle is ToolLifecycle.DISABLED:
            return GateResult(False, PolicyReason.TOOL_DISABLED)

        # 3. Current prohibition. Adding a capability tag to PROHIBITED_CAPABILITIES
        #    stops queued work as well as new work.
        if definition.prohibited or (
            definition.capability_tags & PROHIBITED_CAPABILITIES
        ):
            return GateResult(False, PolicyReason.PROHIBITED_CAPABILITY)

        # 4. Envelope integrity, recomputed from what was stored. This is the
        #    check that makes an approval mean something: it proves the request
        #    is byte-for-byte what it was when it was authorised.
        target_block = build_target_block(
            TargetKind(invocation.target_kind),
            asset_id=invocation.target_asset_id,
            target_ref=invocation.target_ref,
        )
        recomputed = envelope_digest(
            build_envelope(
                definition,
                canonical_input=invocation.input_canonical,
                target=target_block,
            )
        )
        if recomputed != invocation.envelope_digest:
            # Either the stored input was tampered with, or the tool's contract
            # changed under a queued request. Both are refusals, not repairs.
            logger.error(
                "tools.gate.envelope_mismatch",
                invocation_id=str(invocation.id),
                stored=invocation.envelope_digest,
                recomputed=recomputed,
            )
            return GateResult(False, PolicyReason.ENVELOPE_INTEGRITY_FAILED)

        # 5. Approval, where the snapshot says it is required.
        if invocation.approval_required:
            failure = approval_failure(
                invocation, await approved_rows(session, invocation)
            )
            if failure is not None:
                return GateResult(False, failure)

        return GateResult(True, PolicyReason.ALLOWED, definition)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def _execute(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        definition: ToolDefinition,
    ) -> InvocationState:
        adapter = resolve_adapter(definition.adapter_id)
        if adapter is None:  # pragma: no cover - import rule 13 prevents this
            await release_lease(
                session,
                invocation,
                to_state=InvocationState.FAILED,
                reason=PolicyReason.CAPABILITY_NOT_BOUND.value,
                finished_at=datetime.now(UTC),
                error_category=ToolErrorCategory.CAPABILITY_NOT_BOUND.value,
                error_detail_sanitized=ERROR_PHRASES[
                    ToolErrorCategory.CAPABILITY_NOT_BOUND
                ],
            )
            return InvocationState.FAILED

        request = AdapterRequest(
            invocation_id=invocation.id,
            tool_name=invocation.tool_name,
            tool_version=invocation.tool_version,
            target=await self._resolved_target(session, invocation),
            payload=dict(invocation.input_canonical),
            timeout_seconds=definition.timeout_seconds,
            attempt=invocation.attempt_count,
            services=self._services,
        )

        max_attempts = int(definition.retry_policy.max_attempts)
        last: ToolErrorCategory = ToolErrorCategory.INTERNAL_ERROR
        for attempt in range(1, max_attempts + 1):
            try:
                result = await asyncio.wait_for(
                    adapter.execute(request), timeout=definition.timeout_seconds
                )
            except TimeoutError:
                # Never retried: the far side may still be acting on it.
                await release_lease(
                    session,
                    invocation,
                    to_state=InvocationState.TIMED_OUT,
                    reason=ToolErrorCategory.TIMEOUT.value,
                    finished_at=datetime.now(UTC),
                    error_category=ToolErrorCategory.TIMEOUT.value,
                    error_detail_sanitized=ERROR_PHRASES[ToolErrorCategory.TIMEOUT],
                )
                return InvocationState.TIMED_OUT
            except ToolError as exc:
                last = exc.category
                if (
                    attempt < max_attempts
                    and definition.adapter_idempotent
                    and last in definition.retry_policy.retry_on
                ):
                    logger.info(
                        "tools.dispatcher.retrying",
                        invocation_id=str(invocation.id),
                        attempt=attempt,
                        category=last.value,
                    )
                    await asyncio.sleep(definition.retry_policy.backoff_seconds)
                    continue
                break
            except Exception:
                # An adapter that raised something unclassified tells us
                # nothing about the target, so it is an internal error rather
                # than an execution failure. The traceback goes to the log,
                # keyed by invocation id, and never to the caller.
                logger.exception(
                    "tools.adapter.unhandled",
                    invocation_id=str(invocation.id),
                    tool=definition.qualified_name,
                )
                last = ToolErrorCategory.INTERNAL_ERROR
                break
            else:
                return await self._record_adapter_result(
                    session, invocation, definition, result
                )

        await release_lease(
            session,
            invocation,
            to_state=InvocationState.FAILED,
            reason=last.value,
            finished_at=datetime.now(UTC),
            error_category=last.value,
            error_detail_sanitized=ERROR_PHRASES[last],
        )
        return InvocationState.FAILED

    async def _record_adapter_result(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        definition: ToolDefinition,
        result: object,
    ) -> InvocationState:
        """Turn an adapter's report into a state. The adapter never chooses."""
        outcome = getattr(result, "outcome", AdapterOutcome.FAILURE)
        payload = dict(getattr(result, "payload", {}) or {})
        if outcome is not AdapterOutcome.SUCCESS:
            category = {
                AdapterOutcome.TIMEOUT: ToolErrorCategory.TIMEOUT,
                AdapterOutcome.UNAVAILABLE: ToolErrorCategory.ADAPTER_UNAVAILABLE,
            }.get(outcome, ToolErrorCategory.EXECUTION_FAILED)
            await release_lease(
                session,
                invocation,
                to_state=InvocationState.FAILED,
                reason=category.value,
                finished_at=datetime.now(UTC),
                error_category=category.value,
                error_detail_sanitized=ERROR_PHRASES[category],
            )
            return InvocationState.FAILED

        summary, digest = sanitize_output(
            definition, self._declared_output(definition, payload)
        )
        await release_lease(
            session,
            invocation,
            to_state=InvocationState.EXECUTED,
            reason=PolicyReason.ALLOWED.value,
            result_summary=summary,
            result_digest=digest,
            rollback_hint=dict(getattr(result, "rollback_hint", {}) or {}) or None,
        )
        return InvocationState.EXECUTED

    @staticmethod
    def _declared_output(
        definition: ToolDefinition, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Put the adapter's report through the tool's declared output model.

        ``mode="json"`` for the same reason
        :meth:`~acop.tools.policy.ToolPolicyEngine._validate_input` uses it: a
        ``datetime`` or a ``UUID`` has one textual representation, so the
        result digest is stable and the value is storable in JSONB at all. A
        raw ``datetime`` would abort the INSERT.

        A payload that does not satisfy the model is a defect in the adapter or
        the declaration, not a statement about the target. The execution still
        happened and is still recorded as such - saying otherwise would be a
        lie about a change that may have landed - but nothing unvalidated is
        published, because the allow-list exists precisely to stop that.
        """
        try:
            instance = definition.output_model.model_validate(payload)
        except PydanticValidationError:
            logger.error(
                "tools.output.contract_violation",
                tool=definition.qualified_name,
                fields=sorted(payload),
            )
            return {}
        return dict(instance.model_dump(mode="json"))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    async def _after_execution(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        definition: ToolDefinition,
    ) -> InvocationState:
        """``EXECUTED`` is not success. Decide what it becomes.

        Without validation, ``EXECUTED -> SUCCEEDED`` is immediate, and that is
        honest: the tool declared that there is nothing independent to observe.
        With validation, an entirely separate observation decides, and the
        adapter's own return value plays no part in it.
        """
        if not invocation.validation_required:
            await transition(
                session,
                invocation,
                to_state=InvocationState.SUCCEEDED,
                reason=PolicyReason.ALLOWED.value,
                finished_at=datetime.now(UTC),
            )
            return InvocationState.SUCCEEDED

        lease_id = uuid.uuid4()
        await transition(
            session,
            invocation,
            to_state=InvocationState.VALIDATING,
            reason=PolicyReason.ALLOWED.value,
            executor_lease_id=lease_id,
            lease_expires_at=datetime.now(UTC)
            + timedelta(seconds=self._settings.tools_execution_lease_seconds),
        )

        if definition.validation_delay_seconds:
            # A change often needs a moment to become observable. Waiting is
            # part of validating honestly; checking instantly and reporting
            # NOT_CONFIRMED would be a race dressed up as a finding.
            await asyncio.sleep(definition.validation_delay_seconds)

        adapter = resolve_adapter(definition.adapter_id)
        outcome = ValidationOutcome.INDETERMINATE
        detail: dict[str, object] = {}
        if adapter is not None:
            request = AdapterRequest(
                invocation_id=invocation.id,
                tool_name=invocation.tool_name,
                tool_version=invocation.tool_version,
                target=await self._resolved_target(session, invocation),
                payload=dict(invocation.input_canonical),
                timeout_seconds=definition.timeout_seconds,
                attempt=invocation.attempt_count,
                services=self._services,
            )
            try:
                observed = await asyncio.wait_for(
                    adapter.validate(request), timeout=definition.timeout_seconds
                )
            except (TimeoutError, AdapterUnavailableError, TargetUnavailableError):
                # "We could not check" is not "the change did not happen", and
                # the column keeps the difference even though both need a human.
                outcome = ValidationOutcome.INDETERMINATE
            except Exception:
                logger.exception(
                    "tools.validation.unhandled",
                    invocation_id=str(invocation.id),
                )
                outcome = ValidationOutcome.INDETERMINATE
            else:
                outcome = (
                    ValidationOutcome.CONFIRMED
                    if observed.outcome is AdapterOutcome.SUCCESS
                    else ValidationOutcome.NOT_CONFIRMED
                )
                detail = dict(observed.payload or {})

        now = datetime.now(UTC)
        if outcome is ValidationOutcome.CONFIRMED:
            await release_lease(
                session,
                invocation,
                to_state=InvocationState.SUCCEEDED,
                reason=PolicyReason.ALLOWED.value,
                validation_outcome=outcome.value,
                validation_detail=detail,
                validated_at=now,
                finished_at=now,
            )
            return InvocationState.SUCCEEDED

        await release_lease(
            session,
            invocation,
            to_state=InvocationState.VALIDATION_FAILED,
            reason=ToolErrorCategory.VALIDATION_FAILED.value,
            validation_outcome=outcome.value,
            validation_detail=detail,
            validated_at=now,
            finished_at=now,
            error_category=ToolErrorCategory.VALIDATION_FAILED.value,
            error_detail_sanitized=ERROR_PHRASES[ToolErrorCategory.VALIDATION_FAILED],
        )
        return InvocationState.VALIDATION_FAILED

    # ------------------------------------------------------------------
    @staticmethod
    async def _resolved_target(
        session: AsyncSession, invocation: ToolInvocation
    ) -> ResolvedTarget:
        """Hand the adapter identifiers ACOP looked up, never caller strings."""
        kind = TargetKind(invocation.target_kind)
        if kind is not TargetKind.ASSET or invocation.target_asset_id is None:
            return ResolvedTarget(
                kind=kind, external_ref=dict(invocation.target_ref or {})
            )
        asset = await session.get(Asset, invocation.target_asset_id)
        if asset is None:  # pragma: no cover - FK RESTRICT prevents this
            raise TargetUnavailableError("The target asset no longer exists.")
        # The normalised value, not the raw one: an adapter that must find a
        # thing should use the form ACOP resolved identity by, not the form
        # some collector happened to report it in.
        rows = (
            await session.execute(
                select(AssetIdentifier.namespace, AssetIdentifier.value_normalized).where(
                    AssetIdentifier.asset_id == asset.id,
                    AssetIdentifier.retired_at.is_(None),
                )
            )
        ).all()
        return ResolvedTarget(
            kind=kind,
            asset_id=asset.id,
            display_name=asset.display_name,
            asset_type=asset.asset_type,
            identifiers={str(namespace): str(value) for namespace, value in rows},
        )

    @staticmethod
    async def _audit_outcome(
        audit: AuditService, invocation: ToolInvocation, outcome: AuditOutcome
    ) -> None:
        await audit.record(
            AuditEventCreate(
                action=_ACTION,
                outcome=outcome,
                severity=(
                    AuditSeverity.WARNING
                    if outcome is not AuditOutcome.SUCCESS
                    else AuditSeverity.INFO
                ),
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"{invocation.tool_name}@{invocation.tool_version} "
                    f"finished {invocation.state}."
                ),
                context={
                    "state": invocation.state,
                    "final_gate_decision": invocation.final_gate_decision,
                    "final_gate_reason": invocation.final_gate_reason,
                    "error_category": invocation.error_category,
                    "validation_outcome": invocation.validation_outcome,
                },
            ),
            SYSTEM_PRINCIPAL,
            request_id=invocation.request_id,
        )

    # ------------------------------------------------------------------
    async def run_inline(
        self, invocation_id: uuid.UUID, *, wait_seconds: float | None = None
    ) -> InvocationState:
        """Execute now and wait for the result, for a fast synchronous tool.

        This is the Class 0/1 convenience, and it is *not* a second path: it
        calls :meth:`execute_once`, which claims the row, runs the final gate,
        and dispatches exactly as the background worker does. If the deadline
        elapses first, the caller gets the current state and can poll - the
        work continues under the same lease.
        """
        budget = (
            wait_seconds
            if wait_seconds is not None
            else self._settings.tools_inline_wait_seconds
        )
        try:
            return await asyncio.wait_for(
                self.execute_once(invocation_id), timeout=budget
            )
        except TimeoutError:
            async with self._database.session() as session:
                invocation = await session.get(ToolInvocation, invocation_id)
                if invocation is None:  # pragma: no cover
                    raise ToolTimeoutError("The invocation vanished.") from None
                return InvocationState(invocation.state)


__all__ = ["ExecutionDispatcher", "GateResult"]
