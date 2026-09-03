"""Asset and identifier wire schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from acop.models.provenance import SourceType
from acop.models.vocabulary import (
    IDENTIFIER_NAMESPACES,
    NAMESPACE_PATTERN,
    AssetType,
    LifecycleState,
)

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class IdentifierInput(BaseModel):
    """One identifier presented for attachment or resolution."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    namespace: str = Field(max_length=48, examples=["serial"])
    value: str = Field(min_length=1, max_length=255)
    source_type: SourceType = SourceType.MANUAL_ENTRY
    source_id: str = Field(default="acop:api", max_length=255)
    confidence: Confidence = 1.0

    @field_validator("namespace")
    @classmethod
    def _namespace_format(cls, value: str) -> str:
        lowered = value.strip().lower()
        if not NAMESPACE_PATTERN.match(lowered):
            raise ValueError(
                "namespace must be lowercase segments separated by ':', "
                "e.g. 'serial' or 'proxmox:vmid'"
            )
        return lowered

    @property
    def is_registered(self) -> bool:
        return self.namespace in IDENTIFIER_NAMESPACES


class IdentifierRead(BaseModel):
    """An identifier as stored."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    namespace: str
    value_raw: str
    value_normalized: str
    unique_in_namespace: bool
    source_type: str
    source_id: str
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    retired_at: datetime | None


class AssetCreate(BaseModel):
    """Create an asset, optionally resolving identity first."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    asset_type: AssetType
    display_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE
    identifiers: list[IdentifierInput] = Field(
        default_factory=list,
        description=(
            "When supplied, the asset is resolved against these first, making a "
            "collector's create idempotent by construction."
        ),
    )

    @field_validator("lifecycle_state")
    @classmethod
    def _not_terminal_on_create(cls, value: LifecycleState) -> LifecycleState:
        if value in (LifecycleState.RETIRED, LifecycleState.MERGED):
            raise ValueError("an asset cannot be created already retired or merged")
        return value


class AssetUpdate(BaseModel):
    """Patch an asset's label, description or lifecycle.

    ``asset_type`` is absent on purpose: it is part of identity, not metadata.
    """

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    lifecycle_state: LifecycleState | None = None

    @field_validator("lifecycle_state")
    @classmethod
    def _no_terminal_via_patch(
        cls, value: LifecycleState | None
    ) -> LifecycleState | None:
        if value in (LifecycleState.RETIRED, LifecycleState.MERGED):
            raise ValueError(
                "use POST /cmdb/assets/{id}/retire; retirement closes facts and "
                "relationships and is not a plain field update"
            )
        return value


class AssetRead(BaseModel):
    """An asset as returned in a list."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_type: str
    lifecycle_state: str
    display_name: str
    description: str | None
    merged_into_id: UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    retired_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    """An asset with its live identifiers and neighbour count."""

    identifiers: list[IdentifierRead] = Field(default_factory=list)
    live_fact_count: int = 0
    relationship_count: int = 0


class AssetPage(BaseModel):
    """A page of assets, keyset-paginated."""

    items: list[AssetRead]
    next_cursor: str | None = Field(
        default=None, description="Opaque cursor for the next page, or null at the end."
    )


class ResolveRequest(BaseModel):
    """Resolve identity without asserting any facts."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    asset_type: AssetType
    display_name: str = Field(min_length=1, max_length=255)
    identifiers: list[IdentifierInput] = Field(min_length=1)
    create_if_missing: bool = True


class ResolutionCandidate(BaseModel):
    """One asset a multi-match resolved to."""

    asset_id: UUID
    display_name: str
    matched_on: list[str]


class ResolutionResult(BaseModel):
    """Outcome of identity resolution."""

    outcome: str = Field(description="MATCHED | CREATED")
    asset: AssetRead
    matched_on: list[str] = Field(default_factory=list)


__all__ = [
    "AssetCreate",
    "AssetDetail",
    "AssetPage",
    "AssetRead",
    "AssetUpdate",
    "IdentifierInput",
    "IdentifierRead",
    "ResolutionCandidate",
    "ResolutionResult",
    "ResolveRequest",
]
