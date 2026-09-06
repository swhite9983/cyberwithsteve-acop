"""Invocations: request, review, approve, execute, inspect, reconcile.

**One entry point.** ``POST /tool-invocations`` is the only way anything
executes. There is no ``/execute``, no ``/run``, no command endpoint, and no
per-class shortcut - the class changes whether an approval is needed, never
which code runs.

**Status codes carry meaning.** A Class 0/1 tool executes inline and returns
200 with the result, because forcing a poll for ``acop.system.health`` would be
gratuitous. A Class 2/3 tool returns 202 and is polled, because a human has to
approve it first. In both cases the *same* dispatcher does the work: the inline
path awaits :meth:`~acop.services.tools.dispatcher.ExecutionDispatcher.run_inline`,
which calls the same ``execute_once`` a background worker calls, through the
same claim and the same final gate. No endpoint here touches an adapter.

**No DELETE.** Cancellation is a POST that moves an invocation to a terminal
state, leaving the record. Deleting one would strand its approvals and its
transition history, turning an auditable execution into an unexplained gap.
"""

from __future__ import annotations

import uuid
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.api.deps import (
    ApproverPrincipal,
    CurrentPrincipal,
    ViewerPrincipal,
    get_audit_service,
    get_dispatcher,
    get_reconciliation_service,
    get_session,
    get_tool_approval_service,
    get_tool_invocation_service,
)
from acop.api.transaction import TransactionalRoute
from acop.auth.principal import Principal, Role
from acop.core.exceptions import AuthorizationError, NotFoundError, ValidationError
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.provenance import APPROVAL_REQUIRED_CLASSES, PermissionClass
from acop.models.tool import ToolApproval, ToolInvocation, ToolInvocationEvent
from acop.models.tool_vocabulary import (
    ApprovalDecision,
    InvocationState,
    PolicyReason,
    ReconciliationDisposition,
)
from acop.schemas.audit import AuditEventCreate
from acop.schemas.tools import (
    ApprovalDecisionRequest,
    ApprovalRead,
    CancelRequest,
    EnvelopeRead,
    InvocationCreate,
    InvocationEventRead,
    InvocationRead,
    InvocationResultRead,
    ReconcileRequest,
    ReconciliationRead,
)
from acop.services import AuditService
from acop.services.tools.approval import ToolApprovalService
from acop.services.tools.dispatcher import ExecutionDispatcher
from acop.services.tools.invocation import InvocationRequest, ToolInvocationService
from acop.services.tools.reconciliation import ReconciliationService
from acop.services.tools.state import transition
from acop.tools.errors import InvocationStateConflictError, StaleTransitionError

router = APIRouter(
    prefix="/tool-invocations", tags=["tool-invocations"], route_class=TransactionalRoute
)

SessionDep = Annotated[AsyncSession, Depends(get_session)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]
InvocationsDep = Annotated[ToolInvocationService, Depends(get_tool_invocation_service)]
ApprovalsDep = Annotated[ToolApprovalService, Depends(get_tool_approval_service)]
DispatcherDep = Annotated[ExecutionDispatcher, Depends(get_dispatcher)]
ReconcileDep = Annotated[ReconciliationService, Depends(get_reconciliation_service)]

#: Classes that execute inline. Read-only and short-timeout, so a caller gets
#: the answer rather than a polling loop.
_INLINE_CLASSES = frozenset(
    {
        PermissionClass.CLASS_0_INFORMATION.value,
        PermissionClass.CLASS_1_READ_ONLY.value,
    }
)


@router.post("", response_model=InvocationRead)
async def create_invocation(
    payload: InvocationCreate,
    principal: CurrentPrincipal,
    invocations: InvocationsDep,
    dispatcher: DispatcherDep,
    session: SessionDep,
    response: Response,
    http_request: Request,
) -> InvocationRead:
    """The single execution entry point.

    Authorization is per-tool, not per-endpoint: the policy engine compares the
    caller's roles against the tool's declared ``required_roles``. A blanket
    role guard here would either be too permissive for Class 3 or too strict
    for Class 0.
    """
    request = InvocationRequest(
        tool_name=payload.tool_name,
        tool_version=payload.tool_version,
        arguments=payload.input,
        target_asset_id=payload.target.asset_id,
        target_ref=payload.target.reference,
        idempotency_key=payload.idempotency_key,
        request_id=getattr(http_request.state, "request_id", None),
    )
    invocation = await invocations.create(request, principal)
    _require_justification(invocation, payload)

    if invocation.permission_class in _INLINE_CLASSES and invocation.state == (
        InvocationState.READY.value
    ):
        # Awaiting the shared dispatcher, not bypassing it: same claim, same
        # final gate, same audit, same adapter dispatch.
        await dispatcher.run_inline(invocation.id)

    fresh = await _load(session, invocation.id)
    response.status_code = (
        status.HTTP_202_ACCEPTED
        if fresh.state
        in {
            InvocationState.AWAITING_APPROVAL.value,
            InvocationState.READY.value,
            InvocationState.EXECUTING.value,
            InvocationState.VALIDATING.value,
        }
        else status.HTTP_200_OK
    )
    return InvocationRead.model_validate(fresh)


@router.get("", response_model=list[InvocationRead])
async def list_invocations(
    principal: ViewerPrincipal,
    session: SessionDep,
    state: Annotated[str | None, Query()] = None,
    tool_name: Annotated[str | None, Query()] = None,
    target_asset_id: Annotated[uuid.UUID | None, Query()] = None,
    principal_subject: Annotated[str | None, Query()] = None,
    permission_class: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[InvocationRead]:
    """Recent invocations, newest first, with the obvious filters."""
    query = select(ToolInvocation).order_by(ToolInvocation.requested_at.desc())
    if state:
        query = query.where(ToolInvocation.state == state)
    if tool_name:
        query = query.where(ToolInvocation.tool_name == tool_name)
    if target_asset_id:
        query = query.where(ToolInvocation.target_asset_id == target_asset_id)
    if principal_subject:
        query = query.where(ToolInvocation.principal_subject == principal_subject)
    if permission_class:
        query = query.where(ToolInvocation.permission_class == permission_class)
    rows = (await session.execute(query.limit(limit))).scalars().all()
    return [InvocationRead.model_validate(row) for row in rows]


@router.get("/{invocation_id}", response_model=InvocationRead)
async def get_invocation(
    invocation_id: uuid.UUID, principal: ViewerPrincipal, session: SessionDep
) -> InvocationRead:
    """One invocation, including the security snapshot that applied to it."""
    return InvocationRead.model_validate(await _load(session, invocation_id))


@router.get("/{invocation_id}/envelope", response_model=EnvelopeRead)
async def get_envelope(
    invocation_id: uuid.UUID, principal: ApproverPrincipal, session: SessionDep
) -> EnvelopeRead:
    """The approver's review surface.

    Restricted to approvers and admins not because the envelope is secret - it
    contains nothing a viewer could not see elsewhere - but because it is the
    document an approval is given against, and it should be reached through the
    approval workflow rather than browsed.
    """
    invocation = await _load(session, invocation_id)
    return EnvelopeRead(
        invocation_id=invocation.id,
        envelope=invocation.envelope,
        envelope_digest=invocation.envelope_digest,
        input_digest=invocation.input_digest,
        permission_class=invocation.permission_class,
        state=invocation.state,
    )


@router.get("/{invocation_id}/result", response_model=InvocationResultRead)
async def get_result(
    invocation_id: uuid.UUID, principal: ViewerPrincipal, session: SessionDep
) -> InvocationResultRead:
    """The sanitized outcome and what validation observed."""
    return InvocationResultRead.model_validate(await _load(session, invocation_id))


@router.get("/{invocation_id}/events", response_model=list[InvocationEventRead])
async def get_events(
    invocation_id: uuid.UUID, principal: ViewerPrincipal, session: SessionDep
) -> list[InvocationEventRead]:
    """Every transition, in order."""
    await _load(session, invocation_id)
    rows = (
        (
            await session.execute(
                select(ToolInvocationEvent)
                .where(ToolInvocationEvent.invocation_id == invocation_id)
                .order_by(ToolInvocationEvent.sequence)
            )
        )
        .scalars()
        .all()
    )
    return [InvocationEventRead.model_validate(row) for row in rows]


@router.get("/{invocation_id}/approvals", response_model=list[ApprovalRead])
async def get_approvals(
    invocation_id: uuid.UUID, principal: ApproverPrincipal, session: SessionDep
) -> list[ApprovalRead]:
    """Who decided what, and against which envelope."""
    await _load(session, invocation_id)
    rows = (
        (
            await session.execute(
                select(ToolApproval)
                .where(ToolApproval.invocation_id == invocation_id)
                .order_by(ToolApproval.decided_at)
            )
        )
        .scalars()
        .all()
    )
    return [ApprovalRead.model_validate(row) for row in rows]


@router.post("/{invocation_id}/approve", response_model=ApprovalRead)
async def approve(
    invocation_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    principal: ApproverPrincipal,
    approvals: ApprovalsDep,
) -> ApprovalRead:
    """Approve one invocation, against a stated envelope digest.

    The role guard here is the *coarse* one; the fine-grained check is against
    the invocation's snapshotted ``approver_roles``, and separation of duties
    is derived server-side. There is no field on the request that could assert
    an exemption.
    """
    approval = await approvals.decide(
        invocation_id,
        principal,
        decision=ApprovalDecision.APPROVED,
        justification=payload.justification,
        expected_envelope_digest=payload.envelope_digest,
    )
    return ApprovalRead.model_validate(approval)


@router.post("/{invocation_id}/deny", response_model=ApprovalRead)
async def deny(
    invocation_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    principal: ApproverPrincipal,
    approvals: ApprovalsDep,
) -> ApprovalRead:
    """Deny one invocation. Terminal immediately.

    The first denial wins: there is no "one more approver might say yes".
    Making a denial provisional would let an approver who objected be outvoted
    by attrition.
    """
    approval = await approvals.decide(
        invocation_id,
        principal,
        decision=ApprovalDecision.DENIED,
        justification=payload.justification,
        expected_envelope_digest=payload.envelope_digest,
    )
    return ApprovalRead.model_validate(approval)


@router.post("/{invocation_id}/cancel", response_model=InvocationRead)
async def cancel(
    invocation_id: uuid.UUID,
    payload: CancelRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
    audit: AuditDep,
) -> InvocationRead:
    """Withdraw an invocation before it executes.

    Only from ``AWAITING_APPROVAL`` or ``READY``. Cancelling something already
    ``EXECUTING`` is not offered, because a change already dispatched cannot be
    un-dispatched: if the worker is then lost, the honest outcome is
    ``EXECUTION_INDETERMINATE``, not ``CANCELLED``.

    The state read above is a read, and a worker or an approver can move the
    row between it and the write below. That race is *expected here* and
    nowhere else on this router: cancellation is the one operation a person
    performs against an invocation that something else is simultaneously
    entitled to advance. So the lost compare-and-set becomes 409 rather than
    the 500 a stale transition means anywhere else. Nothing is written either
    way - :func:`~acop.services.tools.state.transition` matched zero rows - so
    the winner's state stands exactly as it was recorded.
    """
    invocation = await _load(session, invocation_id)
    is_admin = principal.has_role(Role.ADMIN)
    if invocation.principal_subject != principal.subject and not is_admin:
        raise AuthorizationError("Only the requester or an admin may cancel.")
    if invocation.state not in {
        InvocationState.AWAITING_APPROVAL.value,
        InvocationState.READY.value,
    }:
        raise ValidationError(
            f"Invocation {invocation_id} is {invocation.state} and cannot be cancelled."
        )
    try:
        await transition(
            session,
            invocation,
            to_state=InvocationState.CANCELLED,
            reason=PolicyReason.ALLOWED.value,
            actor_subject=principal.subject,
            detail={"reason": payload.reason},
        )
    except StaleTransitionError as exc:
        await _cancel_conflicted(audit, invocation, principal, exc)
    await audit.record(
        AuditEventCreate(
            action="tool.cancel",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.NOTICE,
            resource_type="tool_invocation",
            resource_id=str(invocation.id),
            permission_class=invocation.permission_class,
            message=f"{invocation.tool_name}@{invocation.tool_version} cancelled.",
            context={"reason": payload.reason},
        ),
        principal,
        request_id=invocation.request_id,
    )
    return InvocationRead.model_validate(invocation)


@router.post(
    "/{invocation_id}/reconcile",
    response_model=ReconciliationRead,
    status_code=status.HTTP_201_CREATED,
)
async def reconcile(
    invocation_id: uuid.UUID,
    payload: ReconcileRequest,
    principal: ApproverPrincipal,
    reconciliation: ReconcileDep,
) -> ReconciliationRead:
    """Record what a human determined about an indeterminate execution.

    This appends a judgement; it does **not** change the invocation's state.
    ``EXECUTION_INDETERMINATE`` remains a truthful statement of what ACOP knew
    at execution time, and the determination sits beside it, separately
    attributed.
    """
    row = await reconciliation.record(
        invocation_id,
        principal,
        disposition=ReconciliationDisposition(payload.disposition),
        justification=payload.justification,
        evidence_ref=payload.evidence_ref,
    )
    return ReconciliationRead.model_validate(row)


# ---------------------------------------------------------------------------
def _require_justification(invocation: ToolInvocation, payload: InvocationCreate) -> None:
    """Class 2/3 must say why.

    Checked here rather than in the schema because the requirement follows from
    the *tool's* class, and a request field naming its own class is exactly
    what the schema exists to refuse.
    """
    if invocation.permission_class not in {
        cls.value for cls in APPROVAL_REQUIRED_CLASSES
    }:
        return
    if payload.justification and payload.justification.strip():
        return
    raise ValidationError(
        "A justification is required for a change-class tool. An approver "
        "needs to know why, not only what.",
        context={"tool": invocation.tool_name},
    )


async def _load(session: AsyncSession, invocation_id: uuid.UUID) -> ToolInvocation:
    """Fetch an invocation written on another connection.

    ``populate_existing`` because the invocation service writes on its own
    transaction: without it a row already in this session's identity map would
    be returned stale, and a caller would see ``REQUESTED`` for something that
    has already finished.
    """
    row = await session.get(ToolInvocation, invocation_id, populate_existing=True)
    if row is None:
        raise NotFoundError(f"Invocation {invocation_id} does not exist.")
    return row


async def _cancel_conflicted(
    audit: AuditService,
    invocation: ToolInvocation,
    principal: Principal,
    cause: StaleTransitionError,
) -> NoReturn:
    """Refuse a cancellation that arrived after the row had moved on.

    ``record_denial`` rather than ``record``, for the reason it exists: this
    function raises, the request transaction is rolled back by
    :class:`~acop.api.transaction.TransactionalRoute`, and an audit row written
    into that transaction would go with it. The attempt is exactly the thing
    that must survive - somebody tried to withdraw an invocation that is now
    executing, and whoever investigates what that invocation did needs to know
    that.

    ``transition`` has already refreshed the instance from the row it lost to,
    so ``invocation.state`` here is PostgreSQL's answer rather than the one the
    endpoint read. It is recorded and logged; it is not returned. The caller
    gets a fixed phrase and a request id.
    """
    await audit.record_denial(
        AuditEventCreate(
            action="tool.cancel",
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.NOTICE,
            resource_type="tool_invocation",
            resource_id=str(invocation.id),
            permission_class=invocation.permission_class,
            message=(
                f"Cancellation of {invocation.tool_name}@{invocation.tool_version} "
                f"was not applied: the invocation is already {invocation.state}."
            ),
            context={
                "observed_state": invocation.state,
                "attempted_to_state": InvocationState.CANCELLED.value,
            },
        ),
        principal,
        request_id=invocation.request_id,
    )
    raise InvocationStateConflictError(
        f"{invocation.id} is {invocation.state}: the cancellation was not applied.",
        context={
            "invocation_id": str(invocation.id),
            "observed_state": invocation.state,
        },
    ) from cause


__all__ = ["router"]
