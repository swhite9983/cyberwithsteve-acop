"""Fact wire schemas.

Note what a caller cannot send: ``verification_status`` and
``statement_class`` are absent from every input model. Both are derived from
``source_type`` at the service boundary, so no client can assert its own
trustworthiness or relabel an inference as an observation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from acop.models.provenance import SourceType
from acop.models.vocabulary import (
    KNOWN_PREDICATES,
    PREDICATE_PATTERN,
    RESERVED_RELATIONSHIP_PREDICATES,
    FactKind,
    ValueType,
)

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class _TypedValue(BaseModel):
    """Shared typed-value fields and the exactly-one-set rule.

    Mirrors ``ck_asset_fact_value_exclusive`` and
    ``ck_asset_fact_value_type_matches`` so a malformed request fails at the
    boundary with a readable message rather than as an IntegrityError.
    """

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    value_type: ValueType
    value_text: str | None = None
    value_number: float | None = None
    value_bool: bool | None = None
    value_timestamp: datetime | None = None
    value_json: dict[str, Any] | None = None
    value_asset_id: UUID | None = None
    unit: str | None = Field(default=None, max_length=24)

    @model_validator(mode="after")
    def _exactly_one_value(self) -> _TypedValue:
        populated = {
            "TEXT": self.value_text is not None,
            "NUMBER": self.value_number is not None,
            "BOOL": self.value_bool is not None,
            "TIMESTAMP": self.value_timestamp is not None,
            "JSON": self.value_json is not None,
            "ASSET_REF": self.value_asset_id is not None,
        }
        set_names = [name for name, present in populated.items() if present]
        if len(set_names) != 1:
            raise ValueError(
                f"exactly one value column must be set, got {len(set_names)}: "
                f"{sorted(set_names)}"
            )
        declared = str(self.value_type)
        if set_names[0] != declared:
            raise ValueError(
                f"value_type is {declared} but the populated column is {set_names[0]}"
            )
        return self


class FactAssert(_TypedValue):
    """Assert a claim about an asset."""

    predicate: str = Field(max_length=128, examples=["memory.total_bytes"])
    fact_kind: FactKind = FactKind.OBSERVED_STATE
    source_type: SourceType
    source_id: str = Field(min_length=1, max_length=255, examples=["proxmox:pve-01"])
    confidence: Confidence = 1.0

    @field_validator("predicate")
    @classmethod
    def _predicate_rules(cls, value: str) -> str:
        lowered = value.strip().lower()
        if not PREDICATE_PATTERN.match(lowered):
            raise ValueError(
                "predicate must be lowercase dotted segments, e.g. 'memory.total_bytes'"
            )
        if lowered in RESERVED_RELATIONSHIP_PREDICATES:
            raise ValueError(
                f"{lowered!r} names a relationship type; assert it via "
                "POST /cmdb/relationships instead. Storing an edge as both a "
                "fact and a relationship is silent dual representation."
            )
        return lowered

    @model_validator(mode="after")
    def _known_predicate_shape(self) -> FactAssert:
        spec = KNOWN_PREDICATES.get(self.predicate)
        if spec is not None and str(self.value_type) != str(spec.value_type):
            raise ValueError(
                f"predicate {self.predicate!r} is registered as "
                f"{spec.value_type}, not {self.value_type}"
            )
        return self

    @model_validator(mode="after")
    def _desired_state_needs_a_human(self) -> FactAssert:
        if str(self.fact_kind) == FactKind.DESIRED_STATE.value:
            raise ValueError(
                "a desired state is created by approving a fact "
                "(POST /cmdb/facts/{id}/approve) or by POST "
                "/cmdb/assets/{id}/desired-facts, never by a plain assert"
            )
        return self


class DesiredFactCreate(_TypedValue):
    """Declare an approved desired configuration directly."""

    predicate: str = Field(max_length=128)
    reason: str | None = Field(default=None, max_length=1024)

    @field_validator("predicate")
    @classmethod
    def _predicate_rules(cls, value: str) -> str:
        # One rule, one place: reuse the FactAssert validator verbatim.
        return FactAssert._predicate_rules(value)


class FactRead(BaseModel):
    """A fact as stored."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    predicate: str
    fact_kind: str
    statement_class: str
    value_type: str
    value_text: str | None
    value_number: float | None
    value_bool: bool | None
    value_timestamp: datetime | None
    value_json: dict[str, Any] | None
    value_asset_id: UUID | None
    unit: str | None
    source_type: str
    source_id: str
    confidence: float
    verification_status: str
    verified_by_subject: str | None
    verified_at: datetime | None
    approved_by_subject: str | None
    approved_at: datetime | None
    supersedes_fact_id: UUID | None
    derived_from_fact_id: UUID | None
    valid_from: datetime
    valid_to: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime


class FactAssertResult(BaseModel):
    """What an assert actually did.

    ``TOUCHED`` means the value was unchanged and only ``last_seen_at`` moved -
    the property that makes a five-minute discovery sweep survivable.
    """

    outcome: str = Field(description="CREATED | SUPERSEDED | TOUCHED")
    fact: FactRead
    superseded_fact_id: UUID | None = None
    json_keys_redacted: list[str] = Field(default_factory=list)


class ConflictingClaim(BaseModel):
    """One live claim participating in a disagreement."""

    fact_id: UUID
    source_type: str
    source_id: str
    statement_class: str
    verification_status: str
    confidence: float
    value_summary: str


class PredicateConflict(BaseModel):
    """A predicate whose live sources disagree."""

    predicate: str
    fact_kind: str
    distinct_values: int
    claims: list[ConflictingClaim]


class EffectiveValue(BaseModel):
    """The current value, and on what basis it was determined.

    Milestone 2 does not resolve conflicts. It reports the raw claims plus one
    unambiguous signal:

    * ``AUTHORITATIVE_SINGLE`` - exactly one live authoritative claim, which
      after ``uq_asset_fact_live_authority`` is a database guarantee.
    * ``UNANIMOUS`` - no authoritative claim, but every live non-INFERENCE
      claim agrees. AI rows are excluded from the vote: the likeliest reason an
      inference agrees with an observation is that it read the observation.
    * ``UNRESOLVED`` - anything else, including inference-only. No value.

    The Milestone 8 resolver replaces the third case only.
    """

    model_config = ConfigDict(from_attributes=True)

    predicate: str
    fact_kind: str
    basis: str
    fact: FactRead | None = None
    conflict_present: bool = False
    resolution_required: bool = False
    inference_only: bool = False
    dissenting_claims: list[ConflictingClaim] = Field(default_factory=list)


class TrustTransition(BaseModel):
    """Body for verify, approve and revoke."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=1024)


class AttestationRead(BaseModel):
    """One immutable trust transition."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    fact_id: UUID
    action: str
    from_status: str
    to_status: str
    principal_subject: str
    principal_type: str
    principal_issuer: str
    auth_method: str
    reason: str | None
    request_id: str | None
    occurred_at: datetime


class FactHistory(BaseModel):
    """Every interval ever recorded for one predicate, plus its attestations."""

    asset_id: UUID
    predicate: str
    intervals: list[FactRead]
    attestations: list[AttestationRead] = Field(default_factory=list)


__all__ = [
    "AttestationRead",
    "ConflictingClaim",
    "DesiredFactCreate",
    "EffectiveValue",
    "FactAssert",
    "FactAssertResult",
    "FactHistory",
    "FactRead",
    "PredicateConflict",
    "TrustTransition",
]
