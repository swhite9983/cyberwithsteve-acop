"""Creating invocations: gates, envelope, idempotency, and the first states.

**Every invocation row is written on its own transaction**, not the request's.
Two reasons, and both are load-bearing:

* A *refusal* must survive. The request that was denied is about to roll back;
  the record that someone attempted it and was refused must not roll back with
  it. This is the same reasoning as M1's
  :meth:`~acop.services.audit.AuditService.record_denial`.
* The dispatcher runs on its own connection. If the invocation were written in
  the request's transaction, a Class 0 tool executing inline would have to wait
  for a commit that has not happened yet, and the dispatcher would find
  nothing. Writing independently means the row is visible the instant it
  exists, so **one execution path serves every class** - which is the whole
  point of the F2 decision. Class 0/1 requests await the same dispatcher the
  background poller uses; they do not bypass it and they never call an adapter
  directly.

**Order of operations is a security property, not a style.** Gates 1-4 run
before any target lookup, enforced by
:meth:`~acop.tools.policy.ToolPolicyEngine.evaluate_prerequisites` returning
early: a malformed request cannot cause a database query on attacker-controlled
input, because the code that would issue it has not been reached.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.config.settings import Settings
from acop.core.logging import get_logger
from acop.db.session import Database
from acop.models.asset import Asset
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.provenance import APPROVAL_REQUIRED_CLASSES
from acop.models.tool import ToolInvocation, ToolRegistration
from acop.models.tool_vocabulary import (
    TERMINAL_STATES,
    GateDecision,
    InvocationState,
    PolicyReason,
    TargetKind,
    ToolLifecycle,
)
from acop.schemas.audit import AuditEventCreate
from acop.services.audit import AuditService
from acop.services.tools.state import append_event, transition
from acop.tools.envelope import build_envelope, build_target_block, envelope_digest
from acop.tools.envelope import input_digest as compute_input_digest
from acop.tools.errors import (
    IdempotencyConflictError,
    InvalidTargetError,
    PolicyEngineFailureError,
    ProhibitedCapabilityError,
    ToolAuthorizationError,
    ToolDisabledError,
    ToolError,
    ToolInputError,
    ToolNotFoundError,
    ToolPolicyDeniedError,
)
from acop.tools.policy import PolicyContext, PolicyDecision, TargetFacts, ToolPolicyEngine
from acop.tools.registry import get_definition

logger = get_logger(__name__)

_ACTION = "tool.invoke"

#: A policy-engine malfunction is audited under its own action rather than as
#: one more ``tool.invoke`` denial. Every channel an operator actually watches -
#: status code, dashboard, alert rule - grouped a failed engine with ordinary
#: refusals, so a bad deploy that made ``evaluate`` throw presented as a spike
#: in denials and read as a permissions misconfiguration. A distinct action is
#: what makes "the engine is broken" queryable without grepping tracebacks.
_POLICY_FAILURE_ACTION = "tool.policy_failure"

#: Which error class describes each refusal, and therefore which status code
#: the caller sees.
#:
#: A single flat ``ToolPolicyDeniedError`` for every gate answered a malformed
#: body with 403, which sends an integrator to look at their credentials
#: instead of their payload - and left three declared classes unreachable. The
#: reason is already recorded on the invocation row; this table only lets the
#: response say the same thing the record says.
#:
#: What the table must **not** do is turn the reason into an oracle, and the
#: entry for ``PROHIBITED_CAPABILITY`` is where that is decided. It maps to its
#: own class rather than to ``ToolAuthorizationError``, so a prohibition is
#: never reported as a role problem; combined with gate 3 running before gate
#: 6, viewer, operator, approver and admin all receive this identical answer
#: and none of them learns which role would have worked.
#:
#: Total over :class:`~acop.models.tool_vocabulary.PolicyReason` on purpose, so
#: a new reason is a decision someone makes here rather than something that
#: silently inherits a 403. ``ALLOWED`` is listed only to keep it total; a
#: refusal is the only thing that reaches this table.
_REFUSAL_ERRORS: dict[PolicyReason, type[ToolError]] = {
    # The request itself is wrong: 422, naming the payload.
    PolicyReason.SCHEMA_INVALID: ToolInputError,
    PolicyReason.TARGET_INVALID: InvalidTargetError,
    PolicyReason.TARGET_OUT_OF_SCOPE: InvalidTargetError,
    PolicyReason.TARGET_RETIRED: InvalidTargetError,
    # The tool is real but not currently executable: 409, because retrying the
    # same request later is exactly the right thing to do.
    PolicyReason.TOOL_DISABLED: ToolDisabledError,
    PolicyReason.TOOL_RETIRED: ToolDisabledError,
    # The caller is wrong: 403 for a role, 404 for a name that no code binds -
    # from the outside, an unbound capability does not exist.
    PolicyReason.ROLE_INSUFFICIENT: ToolAuthorizationError,
    PolicyReason.CAPABILITY_NOT_BOUND: ToolNotFoundError,
    PolicyReason.PROHIBITED_CAPABILITY: ProhibitedCapabilityError,
    # Everything else is a policy refusal and stays a 403.
    PolicyReason.ENVIRONMENT_RESTRICTED: ToolPolicyDeniedError,
    PolicyReason.APPROVAL_MISSING: ToolPolicyDeniedError,
    PolicyReason.APPROVAL_EXPIRED: ToolPolicyDeniedError,
    PolicyReason.APPROVAL_ENVELOPE_MISMATCH: ToolPolicyDeniedError,
    PolicyReason.ENVELOPE_INTEGRITY_FAILED: ToolPolicyDeniedError,
    # An engine that failed to decide is still a 403 - it failed closed, and a
    # refusal is the truthful answer - but it is not the same *event* as a
    # denial, so it gets its own class and its own code. Sharing
    # ``tool_policy_denied`` made a broken engine indistinguishable from a
    # permissions problem in every channel anyone watches.
    PolicyReason.INTERNAL_ERROR: PolicyEngineFailureError,
    PolicyReason.ALLOWED: ToolPolicyDeniedError,
}


@dataclass(frozen=True, slots=True)
class InvocationRequest:
    """What a caller asked for.

    Notice what it cannot carry: no permission class, no approval flag, no
    timeout, no adapter id, no roles. Those are read from the code registry.
    The API schema refuses these names outright
    (:data:`~acop.models.tool_vocabulary.FORBIDDEN_INVOCATION_FIELDS`), so a
    caller has nowhere to put them and no chance to weaken policy.
    """

    tool_name: str
    tool_version: str
    arguments: dict[str, Any]
    target_asset_id: uuid.UUID | None = None
    target_ref: dict[str, Any] | None = None
    idempotency_key: str | None = None
    request_id: str | None = None


class ToolInvocationService:
    """Creates invocations and takes them as far as ``READY``."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        *,
        engine: ToolPolicyEngine | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._engine = engine or ToolPolicyEngine()

    # ------------------------------------------------------------------
    async def create(
        self, request: InvocationRequest, principal: Principal
    ) -> ToolInvocation:
        """Evaluate, record and advance one invocation.

        Returns:
            The committed invocation, in ``READY``, ``AWAITING_APPROVAL`` or
            ``REJECTED``.

        Raises:
            ToolNotFoundError: No registration row exists for that name and
                version. Distinct from ``capability_not_bound``, which is a row
                that exists with no code behind it.
            IdempotencyConflictError: The key was used for a different envelope.
            ToolError: A gate refused. Which subclass - and therefore which
                status code - is decided by :data:`_REFUSAL_ERRORS` from the
                gate's reason. The invocation row exists, in ``REJECTED``, and
                is committed either way.
        """
        refusal: ToolError | None = None
        async with self._database.session() as session:
            # AuditService is bound to *this* session, so the audit record and
            # the invocation it describes commit together or not at all.
            audit = AuditService(session, database=self._database)
            registration = await self._registration(
                session, request.tool_name, request.tool_version
            )
            definition = get_definition(request.tool_name, request.tool_version)

            context = PolicyContext(
                principal=principal,
                definition=definition,
                lifecycle_state=ToolLifecycle(registration.lifecycle_state),
                raw_input=request.arguments,
                target=TargetFacts(kind=self._requested_kind(request), exists=False),
                environment=self._settings.environment.value,
            )

            # Gates 1-4. Nothing below runs until this returns None, so a
            # malformed request cannot reach the target lookup at all.
            decision = self._engine.evaluate_prerequisites(context)
            if decision is None:
                # Only now is a database lookup on caller-supplied input safe.
                target = await self._resolve_target(session, request)
                context = PolicyContext(
                    principal=context.principal,
                    definition=context.definition,
                    lifecycle_state=context.lifecycle_state,
                    raw_input=context.raw_input,
                    target=target,
                    environment=context.environment,
                    request_time=context.request_time,
                )
                decision = self._engine.evaluate(context)

            if not decision.allowed:
                # Recorded, never raised from inside: raising here would roll
                # the session back and take the refusal record with it. The
                # error is carried out and thrown after the commit.
                invocation, refusal = await self._reject(
                    session, request, principal, registration, decision, audit
                )
            else:
                invocation = await self._accept(
                    session, request, principal, registration, decision, context, audit
                )

        if refusal is not None:
            raise refusal
        return invocation

    async def _accept(
        self,
        session: AsyncSession,
        request: InvocationRequest,
        principal: Principal,
        registration: ToolRegistration,
        decision: PolicyDecision,
        context: PolicyContext,
        audit: AuditService,
    ) -> ToolInvocation:
        """Freeze the envelope, resolve idempotency, persist, and advance."""
        definition = context.definition
        if definition is None:  # pragma: no cover - gate 1 guarantees this
            raise ToolNotFoundError(
                f"{request.tool_name}@{request.tool_version} is not bound to code."
            )
        envelope = build_envelope(
            definition,
            canonical_input=decision.canonical_input,
            target=build_target_block(
                context.target.kind,
                asset_id=context.target.asset_id,
                target_ref=request.target_ref,
            ),
        )
        digest = envelope_digest(envelope)

        replay = await self._existing_for_key(session, request, digest)
        if replay is not None:
            return replay

        invocation = await self._persist(
            session,
            request,
            principal,
            registration,
            decision,
            context.target,
            envelope,
            digest,
        )
        await self._advance(session, invocation, principal, decision)
        await self._audit_created(audit, invocation, principal, decision)
        return invocation

    # ------------------------------------------------------------------
    @staticmethod
    def _requested_kind(request: InvocationRequest) -> TargetKind:
        """What the caller named, before anything is looked up."""
        if request.target_asset_id is not None:
            return TargetKind.ASSET
        if request.target_ref:
            return TargetKind.EXTERNAL_REF
        return TargetKind.NONE

    @staticmethod
    async def _registration(
        session: AsyncSession, tool_name: str, tool_version: str
    ) -> ToolRegistration:
        row = (
            (
                await session.execute(
                    select(ToolRegistration).where(
                        ToolRegistration.tool_name == tool_name,
                        ToolRegistration.tool_version == tool_version,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            raise ToolNotFoundError(
                f"No registration exists for {tool_name}@{tool_version}.",
                context={"tool_name": tool_name, "tool_version": tool_version},
            )
        return row

    async def _resolve_target(
        self, session: AsyncSession, request: InvocationRequest
    ) -> TargetFacts:
        """Look the target up. Only ever called after gates 1-4 pass."""
        if request.target_asset_id is not None:
            asset = await session.get(Asset, request.target_asset_id)
            if asset is None:
                return TargetFacts(kind=TargetKind.ASSET, exists=False)
            return TargetFacts(
                kind=TargetKind.ASSET,
                exists=True,
                asset_id=asset.id,
                asset_type=asset.asset_type,
                lifecycle_state=asset.lifecycle_state,
                display_name=asset.display_name,
            )
        if request.target_ref:
            return TargetFacts(
                kind=TargetKind.EXTERNAL_REF,
                exists=True,
                external_ref=dict(request.target_ref),
            )
        return TargetFacts(kind=TargetKind.NONE, exists=True)

    async def _existing_for_key(
        self, session: AsyncSession, request: InvocationRequest, digest: str
    ) -> ToolInvocation | None:
        """Resolve an idempotency key against what it was used for before.

        Same envelope: the caller is retrying a request whose response they
        lost, so return the original. Different envelope: refuse, because
        executing a *different* request under a key that already means
        something would defeat the guarantee the key exists to provide.
        """
        if not request.idempotency_key:
            return None
        existing = (
            (
                await session.execute(
                    select(ToolInvocation).where(
                        ToolInvocation.idempotency_key == request.idempotency_key,
                        ToolInvocation.state != InvocationState.SUPERSEDED.value,
                    )
                )
            )
            .scalars()
            .first()
        )
        if existing is None:
            return None
        if existing.envelope_digest != digest:
            raise IdempotencyConflictError(
                "This idempotency key was already used for a different request.",
                context={
                    "idempotency_key": request.idempotency_key,
                    "existing_invocation_id": str(existing.id),
                },
            )
        logger.info(
            "tools.invocation.replayed",
            invocation_id=str(existing.id),
            tool=f"{existing.tool_name}@{existing.tool_version}",
        )
        return existing

    async def _persist(
        self,
        session: AsyncSession,
        request: InvocationRequest,
        principal: Principal,
        registration: ToolRegistration,
        decision: PolicyDecision,
        target: TargetFacts,
        envelope: dict[str, Any],
        digest: str,
    ) -> ToolInvocation:
        """Write the row, security snapshot and all."""
        policy = decision.approval_policy
        invocation = ToolInvocation(
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            tool_name=request.tool_name,
            tool_version=request.tool_version,
            tool_registration_id=registration.id,
            permission_class=decision.permission_class.value,
            approval_required=policy.approval_required,
            min_approvals=policy.min_approvals,
            distinct_approvers_required=policy.distinct_approvers_required,
            approval_ttl_seconds=policy.ttl_seconds,
            validation_required=decision.validation_required,
            effective_approval_policy=policy.as_snapshot(),
            execution_parameters=decision.execution_parameters,
            registry_contract_hash=decision.registry_contract_hash,
            envelope=envelope,
            envelope_digest=digest,
            input_digest=compute_input_digest(decision.canonical_input),
            input_canonical=decision.canonical_input,
            target_kind=target.kind.value,
            target_asset_id=target.asset_id,
            target_ref=dict(request.target_ref) if request.target_ref else None,
            authorization_decision=GateDecision.ALLOW.value,
            authorization_reason=decision.reason.value,
            authorized_at=decision.evaluated_at,
            state=InvocationState.REQUESTED.value,
            **principal.to_audit_fields(),
        )
        session.add(invocation)
        await session.flush()
        await append_event(
            session,
            invocation_id=invocation.id,
            from_state=None,
            to_state=InvocationState.REQUESTED,
            reason=PolicyReason.ALLOWED.value,
            actor_subject=principal.subject,
            detail={"envelope_digest": digest},
        )
        return invocation

    async def _advance(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        principal: Principal,
        decision: PolicyDecision,
    ) -> None:
        """``REQUESTED -> AUTHORIZED ->`` (approval branch or ``READY``).

        The two classes diverge here and only here. Below this point there is
        one path: both branches converge on ``READY`` and are executed by the
        same dispatcher through the same final gate.
        """
        await transition(
            session,
            invocation,
            to_state=InvocationState.AUTHORIZED,
            reason=decision.reason.value,
            actor_subject=principal.subject,
        )
        if decision.approval_policy.approval_required:
            await transition(
                session,
                invocation,
                to_state=InvocationState.AWAITING_APPROVAL,
                reason=PolicyReason.APPROVAL_MISSING.value,
                actor_subject=principal.subject,
                detail={"min_approvals": invocation.min_approvals},
            )
            return
        await transition(
            session,
            invocation,
            to_state=InvocationState.READY,
            reason=PolicyReason.ALLOWED.value,
            actor_subject=principal.subject,
        )

    async def _reject(
        self,
        session: AsyncSession,
        request: InvocationRequest,
        principal: Principal,
        registration: ToolRegistration,
        decision: PolicyDecision,
        audit: AuditService,
    ) -> tuple[ToolInvocation, ToolError]:
        """Record the refusal and hand back the error for the caller to raise.

        The row is written and committed on this independent session, so it
        outlives the request's rollback. It carries the full policy that was
        applied, because "denied, but we no longer know what the tool required
        at the time" is not an audit answer.

        The class of the returned error comes from :data:`_REFUSAL_ERRORS`, so
        the caller can tell "your request does not match the schema" from "you
        are not permitted" without reading a message.
        """
        invocation = ToolInvocation(
            request_id=request.request_id,
            # A rejected invocation does not consume an idempotency key: the
            # caller should be able to fix their request and retry with it.
            idempotency_key=None,
            tool_name=request.tool_name,
            tool_version=request.tool_version,
            tool_registration_id=registration.id,
            permission_class=decision.permission_class.value,
            approval_required=decision.approval_policy.approval_required,
            min_approvals=decision.approval_policy.min_approvals,
            distinct_approvers_required=(
                decision.approval_policy.distinct_approvers_required
            ),
            approval_ttl_seconds=decision.approval_policy.ttl_seconds,
            validation_required=decision.validation_required,
            effective_approval_policy=decision.approval_policy.as_snapshot(),
            execution_parameters=decision.execution_parameters,
            registry_contract_hash=decision.registry_contract_hash,
            # A refused request has no validated input, so there is nothing
            # honest to put in the envelope beyond what was refused and why.
            envelope={"refused": True, "reason": decision.reason.value},
            envelope_digest="0" * 64,
            input_digest="0" * 64,
            input_canonical={},
            target_kind=self._requested_kind(request).value,
            target_asset_id=(
                request.target_asset_id
                if self._requested_kind(request) is TargetKind.ASSET
                else None
            ),
            target_ref=dict(request.target_ref) if request.target_ref else None,
            authorization_decision=GateDecision.DENY.value,
            authorization_reason=decision.reason.value,
            authorized_at=decision.evaluated_at,
            state=InvocationState.REQUESTED.value,
            error_category=None,
            **principal.to_audit_fields(),
        )
        session.add(invocation)
        await session.flush()
        await append_event(
            session,
            invocation_id=invocation.id,
            from_state=None,
            to_state=InvocationState.REQUESTED,
            reason=decision.reason.value,
            actor_subject=principal.subject,
        )
        await transition(
            session,
            invocation,
            to_state=InvocationState.REJECTED,
            reason=decision.reason.value,
            actor_subject=principal.subject,
        )
        await self._audit_denied(audit, invocation, principal, decision)
        # ``get`` with a policy denial as the default rather than a bare index:
        # an unmapped reason must still refuse, never raise a KeyError that a
        # handler would turn into a 500 for a request policy already decided.
        error_class = _REFUSAL_ERRORS.get(decision.reason, ToolPolicyDeniedError)
        return invocation, error_class(
            f"{request.tool_name}@{request.tool_version} refused: "
            f"{decision.reason.value}.",
            context={
                "invocation_id": str(invocation.id),
                "reason": decision.reason.value,
            },
        )

    # ------------------------------------------------------------------
    @staticmethod
    async def _audit_created(
        audit: AuditService,
        invocation: ToolInvocation,
        principal: Principal,
        decision: PolicyDecision,
    ) -> None:
        await audit.record(
            AuditEventCreate(
                action=_ACTION,
                outcome=(
                    AuditOutcome.PENDING_APPROVAL
                    if invocation.approval_required
                    else AuditOutcome.SUCCESS
                ),
                severity=(
                    AuditSeverity.NOTICE
                    if decision.permission_class in APPROVAL_REQUIRED_CLASSES
                    else AuditSeverity.INFO
                ),
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=f"{invocation.tool_name}@{invocation.tool_version} requested.",
                context={
                    "state": invocation.state,
                    "envelope_digest": invocation.envelope_digest,
                    "target_kind": invocation.target_kind,
                },
            ),
            principal,
            request_id=invocation.request_id,
        )

    @staticmethod
    async def _audit_denied(
        audit: AuditService,
        invocation: ToolInvocation,
        principal: Principal,
        decision: PolicyDecision,
    ) -> None:
        # An engine that could not decide is a fault in ACOP, not a refusal of
        # the caller, and the durable record has to say which one happened.
        # ``authorization_reason`` on the row already did - but only to someone
        # who thought to query it, which is nobody at 03:00.
        engine_failed = decision.reason is PolicyReason.INTERNAL_ERROR
        await audit.record(
            AuditEventCreate(
                action=_POLICY_FAILURE_ACTION if engine_failed else _ACTION,
                outcome=AuditOutcome.DENIED,
                # A prohibited capability being attempted is the loudest thing
                # this milestone can record. It is not a routine refusal - and
                # neither is an engine that stopped working.
                severity=(
                    AuditSeverity.CRITICAL
                    if engine_failed
                    or decision.reason is PolicyReason.PROHIBITED_CAPABILITY
                    else AuditSeverity.WARNING
                ),
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"{invocation.tool_name}@{invocation.tool_version} denied: "
                    f"{decision.reason.value}."
                ),
                context={"reason": decision.reason.value},
            ),
            principal,
            request_id=invocation.request_id,
        )


async def load_invocation(
    session: AsyncSession, invocation_id: uuid.UUID
) -> ToolInvocation | None:
    """Fetch one invocation."""
    return await session.get(ToolInvocation, invocation_id)


def is_terminal(invocation: ToolInvocation) -> bool:
    """Whether nothing further will happen to this invocation on its own."""
    return InvocationState(invocation.state) in TERMINAL_STATES


__all__ = [
    "InvocationRequest",
    "ToolInvocationService",
    "is_terminal",
    "load_invocation",
]
