"""Append-only audit log.

Section 23 of the design brief requires every AI action to be auditable. The
audit log is created in Milestone 1 rather than alongside the tool framework in
Milestone 4 for two reasons:

* It is the one table that every later subsystem writes to. Adding columns to a
  large append-only table later is far more disruptive than defining the shape
  once, up front.
* Authentication events are themselves auditable events, and authentication
  exists from Milestone 1.

**Extensibility strategy.** Rather than pre-creating a dozen nullable columns
for concepts that do not exist yet (tool parameters, approval identity, related
incident, related change), the record carries a typed core plus a JSONB
``context`` column. Later milestones add *indexed generated columns* or
narrowly scoped side tables when a field proves to need querying, instead of
paying schema-churn cost for speculative fields. See
``docs/decisions/ADR-0005-audit-log-shape.md``.

**Immutability.** Enforced in three layers: no ``updated_at`` column, no update
or delete methods on :class:`acop.services.audit.AuditService`, and a database
role that lacks ``UPDATE``/``DELETE`` on this table (documented in
``docs/security/audit-immutability.md``; the role split is applied in the same
milestone that introduces the secrets manager).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, UUIDPrimaryKeyMixin


class AuditOutcome(StrEnum):
    """Result of the audited operation."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class AuditSeverity(StrEnum):
    """Operational significance of the audited event."""

    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    """A single immutable audit record."""

    __tablename__ = "audit_event"

    # -- When -----------------------------------------------------------
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="When the audited event happened, in UTC.",
        comment="When the audited event happened, in UTC.",
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc=(
            "When ACOP persisted the record. Kept separate from occurred_at so "
            "that batch-ingested events (Milestone 6 onward) do not corrupt "
            "incident timelines."
        ),
        comment="When ACOP persisted the record.",
    )

    # -- Who ------------------------------------------------------------
    # These three columns are the provider-neutral identity contract. They are
    # denormalised strings, not a foreign key to an accounts table, precisely so
    # that changing the authentication backend cannot invalidate history.
    principal_subject: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Opaque stable identifier of the acting party.",
    )
    principal_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="human | service | agent | system",
    )
    principal_issuer: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc=(
            "Identifier of the authority that asserted this identity, e.g. "
            "'acop:api-key' in Milestone 1 or an OIDC issuer URL later. Records "
            "which authority vouched for the subject without assuming any "
            "particular provider."
        ),
    )
    auth_method: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="api_key | oidc | mtls | system",
    )
    source_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # -- What -----------------------------------------------------------
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Dotted action identifier, e.g. 'auth.authenticate' or 'tool.execute'.",
    )
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    permission_class: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="Tool permission class from acop.models.provenance.PermissionClass.",
    )

    # -- Result ---------------------------------------------------------
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AuditSeverity.INFO.value
    )
    message: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # -- Correlation ----------------------------------------------------
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # -- Extensible payload ---------------------------------------------
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        doc="Redacted structured detail. Never contains secrets.",
    )

    __table_args__ = (
        # Supports "what happened during this window", the dominant query for
        # incident timelines and change validation.
        Index("ix_audit_event_occurred_at", "occurred_at"),
        # Supports "what did this principal do", required for access review.
        Index("ix_audit_event_principal_occurred", "principal_subject", "occurred_at"),
        # Supports "everything that happened in this request", the join key
        # between an AI request and the tool calls it produced.
        Index("ix_audit_event_request_id", "request_id"),
        Index("ix_audit_event_action_occurred", "action", "occurred_at"),
        {
            "comment": (
                "Append-only audit log. No UPDATE or DELETE path exists in the "
                "application; the acop_app database role should not hold those "
                "privileges on this table."
            )
        },
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AuditEvent {self.action} outcome={self.outcome} "
            f"subject={self.principal_subject}>"
        )


__all__ = ["AuditEvent", "AuditOutcome", "AuditSeverity"]
