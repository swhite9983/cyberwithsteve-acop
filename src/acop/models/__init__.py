"""SQLAlchemy models.

Every model module must be imported here. Alembic's autogenerate walks
``Base.metadata``, and a model that is never imported is silently absent from
migrations - a failure mode that is easy to introduce and unpleasant to
diagnose.
"""

from acop.models.asset import Asset, AssetIdentifier
from acop.models.audit import AuditEvent, AuditOutcome, AuditSeverity
from acop.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from acop.models.embedding import (
    EMBEDDING_MODEL_BY_DIMENSIONS,
    EmbeddingSpace,
    KnowledgeEmbeddingD768,
    embedding_model_for,
)
from acop.models.fact import AssetFact, FactAttestation
from acop.models.knowledge import (
    KnowledgeAssetMention,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeDocumentVersion,
    KnowledgeFinding,
    KnowledgeFindingDisposition,
    KnowledgeIngestAttempt,
    KnowledgeSource,
)
from acop.models.knowledge_vocabulary import (
    DEFAULT_ROLE_SENSITIVITY,
    KNOWLEDGE_FACT_SOURCE_PREFIX,
    SUPPORTED_MEDIA_TYPES,
    ChunkFlag,
    Disposition,
    DistanceMetric,
    FindingSeverity,
    FindingType,
    IngestOutcome,
    KnowledgeLifecycle,
    MentionResolution,
    MentionSource,
    RetrievalMethod,
    RetrievalStrategy,
    ScreeningOutcome,
    Sensitivity,
    SourceKind,
    SpaceLifecycle,
    StatementKind,
    TruncationPolicy,
    TrustClass,
)
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
    "DEFAULT_ROLE_SENSITIVITY",
    "EMBEDDING_MODEL_BY_DIMENSIONS",
    "IDENTIFIER_NAMESPACES",
    "KNOWLEDGE_FACT_SOURCE_PREFIX",
    "KNOWN_PREDICATES",
    "RELATIONSHIP_SPECS",
    "SUPPORTED_MEDIA_TYPES",
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
    "ChunkFlag",
    "Disposition",
    "DistanceMetric",
    "EmbeddingSpace",
    "FactAttestation",
    "FactKind",
    "FindingSeverity",
    "FindingType",
    "IngestOutcome",
    "KnowledgeAssetMention",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "KnowledgeDocumentVersion",
    "KnowledgeEmbeddingD768",
    "KnowledgeFinding",
    "KnowledgeFindingDisposition",
    "KnowledgeIngestAttempt",
    "KnowledgeLifecycle",
    "KnowledgeSource",
    "LifecycleState",
    "MentionResolution",
    "MentionSource",
    "PermissionClass",
    "ProvenanceMixin",
    "RelationshipType",
    "RetrievalMethod",
    "RetrievalStrategy",
    "ScreeningOutcome",
    "Sensitivity",
    "SourceKind",
    "SourceType",
    "SpaceLifecycle",
    "StatementClass",
    "StatementKind",
    "TimestampMixin",
    "TruncationPolicy",
    "TrustClass",
    "UUIDPrimaryKeyMixin",
    "ValidityIntervalMixin",
    "ValueType",
    "VerificationStatus",
    "embedding_model_for",
]
