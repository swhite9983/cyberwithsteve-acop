"""SQLAlchemy models.

Every model module must be imported here. Alembic's autogenerate walks
``Base.metadata``, and a model that is never imported is silently absent from
migrations - a failure mode that is easy to introduce and unpleasant to
diagnose.
"""

from acop.models.asset import Asset, AssetIdentifier
from acop.models.audit import AuditEvent, AuditOutcome, AuditSeverity
from acop.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from acop.models.fact import AssetFact, FactAttestation
from acop.models.provenance import (
    APPROVAL_REQUIRED_CLASSES,
    AUTHORITATIVE_STATUSES,
    PermissionClass,
    SourceType,
    StatementClass,
    VerificationStatus,
)
from acop.models.provenance_mixin import ProvenanceMixin, ValidityIntervalMixin
from acop.models.relationship import AssetRelationship
from acop.models.vocabulary import (
    IDENTIFIER_NAMESPACES,
    KNOWN_PREDICATES,
    RELATIONSHIP_SPECS,
    AssetType,
    AttestationAction,
    FactKind,
    LifecycleState,
    RelationshipType,
    ValueType,
)

__all__ = [
    "APPROVAL_REQUIRED_CLASSES",
    "AUTHORITATIVE_STATUSES",
    "IDENTIFIER_NAMESPACES",
    "KNOWN_PREDICATES",
    "RELATIONSHIP_SPECS",
    "Asset",
    "AssetFact",
    "AssetIdentifier",
    "AssetRelationship",
    "AssetType",
    "AttestationAction",
    "AuditEvent",
    "AuditOutcome",
    "AuditSeverity",
    "Base",
    "FactAttestation",
    "FactKind",
    "LifecycleState",
    "PermissionClass",
    "ProvenanceMixin",
    "RelationshipType",
    "SourceType",
    "StatementClass",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "ValidityIntervalMixin",
    "ValueType",
    "VerificationStatus",
]
