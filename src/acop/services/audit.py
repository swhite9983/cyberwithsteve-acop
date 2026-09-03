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
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.correlation import get_request_id
from acop.core.logging import get_logger
from acop.core.redaction import redact
from acop.models.audit import AuditEvent
from acop.schemas.audit import AuditEventCreate

logger = get_logger(__name__)


class AuditService:
    """Persists immutable audit records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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

        Identity is taken from ``principal.to_audit_fields()``, which returns
        only the four provider-neutral fields. A new authentication backend
        therefore cannot change what this table stores.
        """
        row = AuditEvent(
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
