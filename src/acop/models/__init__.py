"""SQLAlchemy models.

Every model module must be imported here. Alembic's autogenerate walks
``Base.metadata``, and a model that is never imported is silently absent from
migrations - a failure mode that is easy to introduce and unpleasant to
diagnose.
"""

from acop.models.audit import AuditEvent, AuditOutcome, AuditSeverity
from acop.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from acop.models.provenance import (
    APPROVAL_REQUIRED_CLASSES,
    AUTHORITATIVE_STATUSES,
    PermissionClass,
    SourceType,
    StatementClass,
    VerificationStatus,
)

__all__ = [
    "APPROVAL_REQUIRED_CLASSES",
    "AUTHORITATIVE_STATUSES",
    "AuditEvent",
    "AuditOutcome",
    "AuditSeverity",
    "Base",
    "PermissionClass",
    "SourceType",
    "StatementClass",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "VerificationStatus",
]
