"""Pydantic schemas for the API boundary.

Kept separate from :mod:`acop.models` on purpose: the database representation
and the wire representation change for different reasons and at different
times.
"""

from acop.schemas.asset import (
    AssetCreate,
    AssetDetail,
    AssetPage,
    AssetRead,
    AssetUpdate,
    IdentifierInput,
    IdentifierRead,
    ResolutionCandidate,
    ResolutionResult,
    ResolveRequest,
)
from acop.schemas.audit import AuditEventCreate, AuditEventRead
from acop.schemas.fact import (
    AttestationRead,
    ConflictingClaim,
    DesiredFactCreate,
    EffectiveValue,
    FactAssert,
    FactAssertResult,
    FactHistory,
    FactRead,
    PredicateConflict,
    TrustTransition,
)
from acop.schemas.health import (
    ComponentCheck,
    ComponentStatus,
    HealthReport,
    LivenessResponse,
    ReadinessResponse,
)
from acop.schemas.relationship import (
    Neighbour,
    NeighbourList,
    RelationshipAssert,
    RelationshipAssertResult,
    RelationshipRead,
)

__all__ = [
    "AssetCreate",
    "AssetDetail",
    "AssetPage",
    "AssetRead",
    "AssetUpdate",
    "AttestationRead",
    "AuditEventCreate",
    "AuditEventRead",
    "ComponentCheck",
    "ComponentStatus",
    "ConflictingClaim",
    "DesiredFactCreate",
    "EffectiveValue",
    "FactAssert",
    "FactAssertResult",
    "FactHistory",
    "FactRead",
    "HealthReport",
    "IdentifierInput",
    "IdentifierRead",
    "LivenessResponse",
    "Neighbour",
    "NeighbourList",
    "PredicateConflict",
    "ReadinessResponse",
    "RelationshipAssert",
    "RelationshipAssertResult",
    "RelationshipRead",
    "ResolutionCandidate",
    "ResolutionResult",
    "ResolveRequest",
    "TrustTransition",
]
