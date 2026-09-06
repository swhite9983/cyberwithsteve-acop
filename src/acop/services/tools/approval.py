"""Approvals: separation of duties in three layers, and envelope binding.

**Separation of duties is enforced three times, deliberately.**

1. **The API cannot express it.** ``ApprovalDecisionRequest`` has no
   ``self_approval`` field, and ``FORBIDDEN_APPROVAL_FIELDS`` lists the name so
   a schema test catches anyone adding one. A caller has nowhere to assert it.
2. **The service derives it.** :meth:`ToolApprovalService.decide` computes
   ``self_approval`` server-side from three facts that must *all* hold:
   configuration permits it, the tool's own policy permits it, and the
   approver's subject equals the requester's. Any one missing, and a
   same-subject approval is refused.
3. **The database refuses it.** ``CHECK (approver_subject <> requester_subject
   OR self_approval IS TRUE)``. If both layers above were wrong, the INSERT
   aborts the transaction.

Production never reaches layer 2's permissive branch at all: a validator on
:class:`~acop.config.settings.Settings` refuses to start a staging or
production process with ``tools_allow_self_approval`` enabled. The setting
exists so a single-operator development environment can exercise the approval
path end to end without two identities - not as an operational escape hatch.

**Admin gets no implicit bypass.** ``admin`` holds approval authority because
it is a superset role, not because high-risk work needs an administrator, and
it is subject to exactly the same SoD rule as ``approver``.

**An approval binds to an envelope, not to a tool.** The approver agreed to a
specific request: this tool, at this version, under this class, against this
target, with these arguments. ``approved_envelope_digest`` records that, and
the final execution gate recomputes it. If anything the digest covers has
changed, the approval does not transfer - it is invalidated.

**The first terminal decision wins.** A denial is terminal immediately; there
is no "one more approver might say yes". Making a denial provisional would mean
an approver who objected could be outvoted by attrition.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.config.settings import Settings
from acop.core.logging import get_logger
from acop.db.session import Database
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.tool import ToolApproval, ToolInvocation
from acop.models.tool_vocabulary import (
    ApprovalDecision,
    InvocationState,
    PolicyReason,
    effective_roles,
)
from acop.schemas.audit import AuditEventCreate
from acop.services.audit import AuditService
from acop.services.tools.state import transition
from acop.tools.errors import (
    ApprovalEnvelopeMismatchError,
    DuplicateApprovalError,
    SelfApprovalForbiddenError,
    ToolAuthorizationError,
    ToolNotFoundError,
    ToolPolicyDeniedError,
)

logger = get_logger(__name__)

_ACTION = "tool.approve"

#: The partial unique index that makes a second approval from one subject
#: impossible. Named here because the service recognises *this* violation
#: specifically: any other integrity failure on the same INSERT would be a
#: defect in ACOP, and mislabelling it as a duplicate would hide it.
_DISTINCT_APPROVER_INDEX = "uq_tool_approval_distinct"


class ToolApprovalService:
    """Records approval decisions and advances invocations that satisfy them."""

    def __init__(self, database: Database, settings: Settings) -> None:
        self._database = database
        self._settings = settings

    async def decide(
        self,
        invocation_id: uuid.UUID,
        principal: Principal,
        *,
        decision: ApprovalDecision,
        justification: str,
        expected_envelope_digest: str,
    ) -> ToolApproval:
        """Record one approver's decision.

        Written on its own transaction. A *refused* attempt - wrong state, no
        authority, self-approval - raises, so its record is written out of band
        through :meth:`~acop.services.audit.AuditService.record_denial`, on a
        separate connection that commits immediately. An attempt to approve
        one's own Class 3 change is exactly the event that must survive the
        rollback of the request that made it.

        Raises:
            ToolNotFoundError: No such invocation.
            ToolPolicyDeniedError: The invocation is not awaiting approval.
            ToolAuthorizationError: The principal holds no approval authority
                for this tool.
            SelfApprovalForbiddenError: The requester tried to approve their own.
            DuplicateApprovalError: This subject has already approved this
                invocation. Reported by the partial unique index, not by a
                pre-check, so a concurrent double submission cannot slip past.
            ApprovalEnvelopeMismatchError: The approver's stated digest does
                not match the invocation's. This is a *second* binding on top
                of the final gate's check, and it proves something different:
                that the approver acted on the envelope they were shown, not on
                one that changed between the GET and the POST.
        """
        async with self._database.session() as session:
            audit = AuditService(session, database=self._database)
            invocation = await session.get(ToolInvocation, invocation_id)
            if invocation is None:
                raise ToolNotFoundError(
                    f"Invocation {invocation_id} does not exist.",
                    context={"invocation_id": str(invocation_id)},
                )
            try:
                self._check_state(invocation)
                self._check_envelope(invocation, expected_envelope_digest)
                self._check_authority(invocation, principal)
                self_approval = self._derive_self_approval(invocation, principal)
            except (
                ApprovalEnvelopeMismatchError,
                SelfApprovalForbiddenError,
                ToolAuthorizationError,
                ToolPolicyDeniedError,
            ) as exc:
                await self._audit_refused(audit, invocation, principal, exc)
                raise

            approval = ToolApproval(
                invocation_id=invocation.id,
                decision=decision.value,
                # Bound to what the approver is looking at *now*. The final
                # gate recomputes the invocation's digest and compares.
                approved_envelope_digest=invocation.envelope_digest,
                requester_subject=invocation.principal_subject,
                approver_subject=principal.subject,
                approver_type=principal.principal_type.value,
                approver_issuer=principal.issuer,
                approver_auth_method=principal.auth_method.value,
                self_approval=self_approval,
                justification=justification,
                expires_at=datetime.now(UTC)
                + timedelta(seconds=invocation.approval_ttl_seconds),
            )
            session.add(approval)
            try:
                await session.flush()
            except IntegrityError as exc:
                if _DISTINCT_APPROVER_INDEX not in str(exc.orig):
                    raise
                # Caught rather than pre-checked, deliberately. A SELECT for an
                # existing approval before the INSERT would leave a window in
                # which two concurrent requests from the same subject both see
                # nothing and both proceed, and the index would abort one of
                # them anyway. The index is the authority; this only translates
                # what it refused into the answer the caller deserves, because
                # two approvals from one person are one approval and that is a
                # client mistake, not a server fault.
                #
                # ``invocation_id`` rather than ``invocation.id``: the failed
                # flush leaves the instance's attributes expired, so reading
                # one would issue a SELECT on a session that must roll back
                # first - and the duplicate would resurface as a
                # PendingRollbackError instead of the 409 it is.
                raise DuplicateApprovalError(
                    f"{principal.subject} has already approved invocation "
                    f"{invocation_id}.",
                    context={
                        "invocation_id": str(invocation_id),
                        "constraint": _DISTINCT_APPROVER_INDEX,
                    },
                ) from exc

            if decision is ApprovalDecision.DENIED:
                await transition(
                    session,
                    invocation,
                    to_state=InvocationState.DENIED,
                    reason=PolicyReason.APPROVAL_MISSING.value,
                    actor_subject=principal.subject,
                    detail={"decision": decision.value},
                )
            else:
                await self._count_and_advance(session, invocation, principal)

            await self._audit(audit, invocation, principal, approval)
            return approval

    # ------------------------------------------------------------------
    @staticmethod
    def _check_state(invocation: ToolInvocation) -> None:
        """Only an invocation actually waiting may be decided.

        An already-approved invocation is not re-approvable, and an expired or
        cancelled one is not revivable by approval. Both would otherwise be a
        way to resurrect a request the framework had finished with.
        """
        if invocation.state != InvocationState.AWAITING_APPROVAL.value:
            raise ToolPolicyDeniedError(
                f"Invocation {invocation.id} is {invocation.state}, not awaiting "
                "approval.",
                context={
                    "invocation_id": str(invocation.id),
                    "state": invocation.state,
                },
            )

    @staticmethod
    def _check_envelope(invocation: ToolInvocation, stated: str) -> None:
        """The approver must name the envelope they reviewed.

        Without this, an approver could fetch an envelope, have the request
        change underneath them, and approve the new one by clicking a stale
        button. The digest travels through the client, so agreeing to something
        different is a mismatch rather than a silent substitution.
        """
        if stated != invocation.envelope_digest:
            raise ApprovalEnvelopeMismatchError(
                "The stated envelope digest does not match this invocation.",
                context={"invocation_id": str(invocation.id)},
            )

    @staticmethod
    def _check_authority(invocation: ToolInvocation, principal: Principal) -> None:
        """Whether this principal may approve this invocation.

        Read from the invocation's **snapshot**, not from the tool declaration
        as it stands today. Changing a tool's approver roles must not silently
        change who can approve a request that is already pending - the approver
        set was part of what was authorised.
        """
        allowed = set(
            invocation.effective_approval_policy.get("approver_roles", []) or []
        )
        held = {role.value for role in effective_roles(principal.roles)}
        if not allowed & held:
            raise ToolAuthorizationError(
                f"{principal.subject} holds no approval authority for "
                f"{invocation.tool_name}@{invocation.tool_version}.",
                context={
                    "invocation_id": str(invocation.id),
                    "required_any_of": sorted(allowed),
                },
            )

    def _derive_self_approval(
        self, invocation: ToolInvocation, principal: Principal
    ) -> bool:
        """Compute ``self_approval`` server-side. Never accepted from a caller.

        Returns ``False`` for the normal case - a different subject approving -
        which is what makes the database CHECK satisfiable without any special
        handling. Returns ``True`` only when all three permissions coincide,
        and raises otherwise.
        """
        if principal.subject != invocation.principal_subject:
            return False
        policy_permits = bool(
            invocation.effective_approval_policy.get("self_approval_permitted", False)
        )
        if not (self._settings.tools_allow_self_approval and policy_permits):
            raise SelfApprovalForbiddenError(
                f"{principal.subject} requested this invocation and may not approve it.",
                context={"invocation_id": str(invocation.id)},
            )
        logger.warning(
            "tools.approval.self_approved",
            invocation_id=str(invocation.id),
            subject=principal.subject,
            environment=self._settings.environment.value,
        )
        return True

    async def _count_and_advance(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        principal: Principal,
    ) -> None:
        """Count distinct approvers and move on once the threshold is met.

        ``COUNT(DISTINCT approver_subject)`` rather than a stored counter,
        because a counter can drift and this cannot. The partial unique index
        on ``(invocation_id, approver_subject) WHERE decision = 'APPROVED'``
        already makes a second approval from the same subject impossible, so
        the two mechanisms agree by construction.
        """
        approvals = int(
            await session.scalar(
                select(func.count(func.distinct(ToolApproval.approver_subject))).where(
                    ToolApproval.invocation_id == invocation.id,
                    ToolApproval.decision == ApprovalDecision.APPROVED.value,
                )
            )
            or 0
        )
        invocation.approvals_received = min(approvals, invocation.min_approvals)
        await session.flush()
        if approvals < invocation.min_approvals:
            logger.info(
                "tools.approval.partial",
                invocation_id=str(invocation.id),
                received=approvals,
                required=invocation.min_approvals,
            )
            return
        now = datetime.now(UTC)
        await transition(
            session,
            invocation,
            to_state=InvocationState.APPROVED,
            reason=PolicyReason.ALLOWED.value,
            actor_subject=principal.subject,
            detail={"approvals": approvals},
            approved_at=now,
        )
        # APPROVED -> READY is immediate and unconditional: the approval branch
        # rejoins the single execution path here, and everything that follows
        # is identical for Class 0/1 and Class 2/3.
        await transition(
            session,
            invocation,
            to_state=InvocationState.READY,
            reason=PolicyReason.ALLOWED.value,
            actor_subject=principal.subject,
        )

    @staticmethod
    async def _audit_refused(
        audit: AuditService,
        invocation: ToolInvocation,
        principal: Principal,
        error: Exception,
    ) -> None:
        """Record a refused approval attempt on an independent connection.

        ``record_denial`` rather than ``record``: this session is about to roll
        back when the exception propagates, and the attempt must not roll back
        with it.
        """
        await audit.record_denial(
            AuditEventCreate(
                action=_ACTION,
                outcome=AuditOutcome.DENIED,
                severity=(
                    AuditSeverity.CRITICAL
                    if isinstance(error, SelfApprovalForbiddenError)
                    else AuditSeverity.WARNING
                ),
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"Approval attempt on {invocation.tool_name}@"
                    f"{invocation.tool_version} refused."
                ),
                context={
                    "error": type(error).__name__,
                    "state": invocation.state,
                },
            ),
            principal,
            request_id=invocation.request_id,
        )

    @staticmethod
    async def _audit(
        audit: AuditService,
        invocation: ToolInvocation,
        principal: Principal,
        approval: ToolApproval,
    ) -> None:
        await audit.record(
            AuditEventCreate(
                action=_ACTION,
                outcome=(
                    AuditOutcome.SUCCESS
                    if approval.decision == ApprovalDecision.APPROVED.value
                    else AuditOutcome.DENIED
                ),
                # A self-approval is always notable, even where it is permitted.
                severity=(
                    AuditSeverity.CRITICAL
                    if approval.self_approval
                    else AuditSeverity.NOTICE
                ),
                resource_type="tool_invocation",
                resource_id=str(invocation.id),
                permission_class=invocation.permission_class,
                message=(
                    f"{invocation.tool_name}@{invocation.tool_version} "
                    f"{approval.decision.lower()} by {principal.subject}."
                ),
                context={
                    "decision": approval.decision,
                    "self_approval": approval.self_approval,
                    "approved_envelope_digest": approval.approved_envelope_digest,
                    "state": invocation.state,
                },
            ),
            principal,
            request_id=invocation.request_id,
        )


async def approved_rows(
    session: AsyncSession, invocation: ToolInvocation
) -> list[ToolApproval]:
    """Every APPROVED decision on this invocation, valid or not.

    Deliberately unfiltered. The final gate has to be able to tell "nobody
    approved" from "someone approved and it expired" from "someone approved a
    different request", because the operator response to each is completely
    different: find an approver, re-approve, or re-request.
    """
    return list(
        (
            await session.execute(
                select(ToolApproval).where(
                    ToolApproval.invocation_id == invocation.id,
                    ToolApproval.decision == ApprovalDecision.APPROVED.value,
                )
            )
        )
        .scalars()
        .all()
    )


def approval_failure(
    invocation: ToolInvocation,
    approvals: list[ToolApproval],
    *,
    now: datetime | None = None,
) -> PolicyReason | None:
    """Why these approvals are insufficient, or ``None`` if they are enough.

    Checked in the order that produces the most useful answer: a changed
    envelope is reported as such even if the approval had also expired, because
    re-approving would not help.
    """
    if not invocation.approval_required:
        return None
    moment = now or datetime.now(UTC)
    if not approvals:
        return PolicyReason.APPROVAL_MISSING
    if any(
        row.approved_envelope_digest != invocation.envelope_digest for row in approvals
    ):
        return PolicyReason.APPROVAL_ENVELOPE_MISMATCH
    live = [row for row in approvals if row.expires_at > moment]
    if len(live) < len(approvals):
        return PolicyReason.APPROVAL_EXPIRED
    if len({row.approver_subject for row in live}) < invocation.min_approvals:
        return PolicyReason.APPROVAL_MISSING
    return None


__all__ = [
    "ToolApprovalService",
    "approval_failure",
    "approved_rows",
]
