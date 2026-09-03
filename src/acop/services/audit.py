"""Audit write path.

This service is the only sanctioned way to create an audit record. It exposes
no update or delete operation - not as a matter of convention but as the first
of three layers enforcing append-only semantics (see
``acop/models/audit.py``).

**Failure policy.** ``record`` raises on failure rather than swallowing the
error. Callers choose:

* An action in a change-bearing permission class (Class 2 or 3) must fail
  closed: if the action cannot be audited, it must not be executed. That rule is
  enforced by the approval engine in Milestone 11, and this service exists in
  Milestone 1 so that engine has a stable contract to build on.
* Informational events may log the failure and continue.

Silently discarding audit failures would defeat the purpose of the log, so it
is never the default.

**Denials.** A refused request ends in an exception, and the request's
transaction is rolled back with it. An audit row written inside that
transaction is rolled back too, so the events most worth keeping - the ones
where ACOP said no - would be the only ones never recorded. ``record_denial``
writes on an independent connection so the record outlives the failure it
describes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.correlation import get_request_id
from acop.core.logging import get_logger
from acop.core.redaction import redact
from acop.models.audit import AuditEvent
from acop.schemas.audit import AuditEventCreate

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from acop.db import Database

logger = get_logger(__name__)


class AuditService:
    """Persists immutable audit records."""

    def __init__(
        self, session: AsyncSession, *, database: Database | None = None
    ) -> None:
        self._session = session
        # Supplied by the API layer so a denial can be written outside the
        # request's transaction. Optional so that service-level tests, which
        # own their session and never roll back mid-test, need no engine.
        self._database = database

    async def record(
        self,
        event: AuditEventCreate,
        principal: Principal,
        *,
        source_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> AuditEvent:
        """Write one audit record and return it.

        The row participates in the caller's transaction, so it commits with
        the change it describes and disappears if that change is rolled back.
        That is the correct coupling for a successful mutation and the wrong
        one for a refusal - see :meth:`record_denial`.

        Identity is taken from ``principal.to_audit_fields()``, which returns
        only the four provider-neutral fields. A new authentication backend
        therefore cannot change what this table stores.
        """
        row = self._build(
            event,
            principal,
            source_address=source_address,
            user_agent=user_agent,
            request_id=request_id,
        )
        self._session.add(row)
        await self._session.flush()
        logger.debug(
            "audit.recorded",
            audit_id=str(row.id),
            action=row.action,
            outcome=row.outcome,
            subject=row.principal_subject,
        )
        return row

    async def record_denial(
        self,
        event: AuditEventCreate,
        principal: Principal,
        *,
        source_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Record a refusal on its own connection, so it survives the rollback.

        The caller is about to re-raise: an identity conflict, a rejected
        secret, a refused transition. Whatever partial work that request did
        must be discarded, but the fact that a principal attempted it and was
        refused must not be. Writing it here, in a separate transaction that
        commits immediately, is what makes those two requirements compatible.

        A failure to write the denial is logged at error level and swallowed.
        This is not the silent discard the module docstring forbids: the
        request is already being refused, so no unaudited change occurs, and
        converting the refusal into a 500 would replace the caller's
        actionable error with an unrelated one while still not producing a
        record. The loud log is the compensating control until Milestone 10
        adds an audit-write alarm.
        """
        if self._database is None:  # pragma: no cover - wired in the API layer
            raise RuntimeError(
                "record_denial requires a Database; construct AuditService with one."
            )
        row = self._build(
            event,
            principal,
            source_address=source_address,
            user_agent=user_agent,
            request_id=request_id,
        )
        try:
            async with self._database.session() as session:
                session.add(row)
        except Exception as exc:
            logger.error(
                "audit.denial_write_failed",
                action=event.action,
                error_type=type(exc).__name__,
                subject=principal.subject,
            )
            return
        logger.info(
            "audit.denial_recorded",
            audit_id=str(row.id),
            action=row.action,
            subject=row.principal_subject,
        )

    def _build(
        self,
        event: AuditEventCreate,
        principal: Principal,
        *,
        source_address: str | None,
        user_agent: str | None,
        request_id: str | None,
    ) -> AuditEvent:
        return AuditEvent(
            occurred_at=event.occurred_at or datetime.now(UTC),
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            permission_class=event.permission_class,
            outcome=(
                event.outcome if isinstance(event.outcome, str) else event.outcome.value
            ),
            severity=(
                event.severity
                if isinstance(event.severity, str)
                else event.severity.value
            ),
            message=event.message,
            request_id=request_id or get_request_id(),
            source_address=source_address,
            user_agent=(user_agent or None) and user_agent[:512],
            # Redaction is applied here as well as in the logging pipeline. The
            # audit log outlives log retention, so a secret leaked into it is a
            # longer-lived problem than one leaked into stdout.
            context=redact(event.context),
            **principal.to_audit_fields(),
        )
