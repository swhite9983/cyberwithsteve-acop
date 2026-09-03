"""Relationship wire schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from acop.models.provenance import SourceType
from acop.models.vocabulary import RelationshipType

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class RelationshipAssert(BaseModel):
    """Assert an edge between two assets.

    For a symmetric type the service canonicalises the endpoints into UUID
    order before insert, so asserting A-to-B and B-to-A produce the identical
    row and the second is rejected as a duplicate rather than stored as a
    second cable.
    """

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    relationship_type: RelationshipType
    source_asset_id: UUID
    target_asset_id: UUID
    qualifier: str | None = Field(default=None, max_length=128, examples=["Gi1/0/24"])
    source_type: SourceType
    source_id: str = Field(min_length=1, max_length=255)
    confidence: Confidence = 1.0


class RelationshipRead(BaseModel):
    """An edge as stored, in canonical direction."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    relationship_type: str
    source_asset_id: UUID
    target_asset_id: UUID
    is_symmetric: bool
    qualifier: str | None
    statement_class: str
    source_type: str
    source_id: str
    confidence: float
    verification_status: str
    verified_by_subject: str | None
    verified_at: datetime | None
    approved_by_subject: str | None
    approved_at: datetime | None
    supersedes_rel_id: UUID | None
    valid_from: datetime
    valid_to: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime


class RelationshipAssertResult(BaseModel):
    """What asserting an edge did."""

    outcome: str = Field(description="CREATED | TOUCHED")
    relationship: RelationshipRead
    canonicalised: bool = Field(
        default=False,
        description="True when a symmetric edge's endpoints were swapped into UUID order.",
    )


class Neighbour(BaseModel):
    """One directly related asset.

    ``label`` is the inverse when this asset is the target, so both directions
    read naturally: a VM shows ``RUNS_ON`` its host, and the host shows
    ``HOSTS`` the VM, from the same stored row.
    """

    relationship_id: UUID
    label: str
    direction: str = Field(description="out | in")
    qualifier: str | None
    asset_id: UUID
    asset_type: str
    display_name: str
    lifecycle_state: str
    verification_status: str
    source_id: str


class NeighbourList(BaseModel):
    """Depth-1 traversal result.

    Depth 1 only. Recursive traversal is Milestone 8; the schema makes it a
    query rather than a migration, which is why deferring it is safe.
    """

    asset_id: UUID
    neighbours: list[Neighbour]


__all__ = [
    "Neighbour",
    "NeighbourList",
    "RelationshipAssert",
    "RelationshipAssertResult",
    "RelationshipRead",
]
