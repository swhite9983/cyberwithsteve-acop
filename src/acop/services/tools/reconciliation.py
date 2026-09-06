"""Human determinations about indeterminate executions.

``EXECUTION_INDETERMINATE`` is a truthful statement about what ACOP knew when a
worker was lost: the adapter had been called, and the outcome is unknown. That
statement stays as it is, for ever.

This service does not change it. It **appends** a separately attributed
judgement beside it - what a person determined afterwards, when they went and
looked - so the record reads as two facts rather than one revised one: *ACOP
did not know*, and *later, this named person determined this*. Rewriting the
execution event into something ACOP did not know at the time would replace
evidence with a conclusion, and an auditor could no longer tell which was
which.

**It is deliberately not a workflow system.** No assignment, no status, no
queue, no notifications, no reopening. One row: who, when, what they concluded,
why, and a reference to whatever they looked at. Anything more belongs to
incident management, which is a later milestone and a different problem.

**Multiple reconciliations are allowed and are not a mistake.** A first-look
``UNKNOWN`` followed a week later by a ``CONFIRMED_FAILED`` is a more honest
history than a single row edited twice, and the table is append-only precisely
so that sequence survives.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.logging import get_logger
from acop.core.redaction import redact
from acop.db.session import Database
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.tool import ToolInvocation, ToolInvocationReconciliation
from acop.models.tool_vocabulary import InvocationState, ReconciliationDisposition
from acop.schemas.audit import AuditEventCreate
from acop.services.audit import AuditService
from acop.services.tools.state import append_event
from acop.tools.errors import ToolNotFoundError, ToolPolicyDeniedError

logger = get_logger(__name__)

_ACTION = "tool.reconcile"


class ReconciliationService:
    """Records what a human determined about an indeterminate execution."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def record(
        self,
        invocation_id: uuid.UUID,
        principal: Principal,
        *,
        disposition: ReconciliationDisposition,
        justification: str,
        evidence_ref: dict[str, Any] | None = None,
    ) -> ToolInvocationReconciliation:
        """Append one determination.

        Raises:
            ToolNotFoundError: No such invocation.
            ToolPolicyDeniedError: The invocation is not
                ``EXECUTION_INDETERMINATE``. Reconciliation answers a question
                only that state asks; offering it elsewhere would invite people
                to "correct" outcomes ACOP is certain about.
        """
        async with self._database.session() as session:
            audit = AuditService(session, database=self._database)
            invocation = await session.get(ToolInvocation, invocation_id)
            if invocation is None:
                raise ToolNotFoundError(
                    f"Invocation {invocation_id} does not exist.",
                    context={"invocation_id": str(invocation_id)},
                )
            if invocation.state != InvocationState.EXECUTION_INDETERMINATE.value:
                raise ToolPolicyDeniedError(
                    f"Invocation {invocation_id} is {invocation.state}. Only an "
                    "indeterminate execution can be reconciled.",
                    context={"state": invocation.state},
                )

            row = ToolInvocationReconciliation(
                invocation_id=invocation.id,
                disposition=disposition.value,
                justification=justification,
                # Redacted as defence in depth. This is the one field in the
                # milestone a human types freely, so it is the one place a
                # secret could plausibly arrive by accident.
                evidence_ref=redact(evidence_ref or {}),
                reconciled_by_subject=principal.subject,
                reconciled_by_type=principal.principal_type.value,
                reconciled_by_issuer=principal.issuer,
                reconciled_by_auth_method=principal.auth_method.value,
            )
            session.add(row)
            await session.flush()

            # An event, not a transition: from_state and to_state are both
            # EXECUTION_INDETERMINATE, because the state did not change and the
            # history must not suggest it did.
            await append_event(
                session,
                invocation_id=invocation.id,
                from_state=InvocationState.EXECUTION_INDETERMINATE,
                to_state=InvocationState.EXECUTION_INDETERMINATE,
                reason=f"reconciled:{disposition.value.lower()}",
                actor_subject=principal.subject,
                detail={"reconciliation_id": str(row.id)},
            )
            await audit.record(
                AuditEventCreate(
                    action=_ACTION,
                    outcome=AuditOutcome.SUCCESS,
                    severity=AuditSeverity.NOTICE,
                    resource_type="tool_invocation",
                    resource_id=str(invocation.id),
                    permission_class=invocation.permission_class,
                    message=(
                        f"{invocation.tool_name}@{invocation.tool_version} "
                        f"reconciled as {disposition.value}."
                    ),
                    context={"disposition": disposition.value},
                ),
                principal,
                request_id=invocation.request_id,
            )
            logger.info(
                "tools.reconciliation.recorded",
                invocation_id=str(invocation.id),
                disposition=disposition.value,
                subject=principal.subject,
            )
            return row

    async def history(
        self, session: AsyncSession, invocation_id: uuid.UUID
    ) -> list[ToolInvocationReconciliation]:
        """Every determination recorded against an invocation, oldest first."""
        return list(
            (
                await session.execute(
                    select(ToolInvocationReconciliation)
                    .where(ToolInvocationReconciliation.invocation_id == invocation_id)
                    .order_by(ToolInvocationReconciliation.reconciled_at)
                )
            )
            .scalars()
            .all()
        )


__all__ = ["ReconciliationService"]
