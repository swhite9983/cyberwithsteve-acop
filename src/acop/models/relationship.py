"""Typed directed edges between assets.

A relationship is a subject-predicate-object statement and could have lived in
``asset_fact`` as a value of type ``ASSET_REF``. It has its own table because
edges need four things facts do not: a meaningful inverse label, symmetry,
reverse-direction indexes (the query that matters in an outage reads the
*target* side), and endpoint qualifiers.

What it keeps from the unified design is the important half: the same
provenance mixin and the same trust rules, so the two cannot drift apart.
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.dialects.postgresql import ExcludeConstraint
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, UUIDPrimaryKeyMixin
from acop.models.provenance_mixin import ProvenanceMixin, ValidityIntervalMixin


class AssetRelationship(
    ProvenanceMixin, ValidityIntervalMixin, UUIDPrimaryKeyMixin, Base
):
    """One claimed edge, from one source, over one interval."""

    __tablename__ = "asset_relationship"

    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_asset_relationship_source_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_asset_relationship_target_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    is_symmetric: Mapped[bool] = mapped_column(
        nullable=False,
        doc=(
            "Denormalised from RELATIONSHIP_SPECS, the same pattern as "
            "unique_in_namespace. Changing a type's symmetry later would need a "
            "one-off recanonicalisation migration - recorded in ADR-0008."
        ),
    )
    qualifier: Mapped[str | None] = mapped_column(
        String(128), nullable=True, doc="Which port or interface, e.g. 'Gi1/0/24'."
    )

    supersedes_rel_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset_relationship.id",
            name="fk_asset_relationship_supersedes_rel_id_asset_relationship",
        ),
        nullable=True,
        doc="Backward pointer, for the same reason as AssetFact.supersedes_fact_id.",
    )

    __table_args__ = (
        CheckConstraint(
            "source_asset_id <> target_asset_id",
            name="no_self",
        ),
        # A symmetric edge is stored ONCE, in canonical UUID order, so one
        # physical link cannot appear twice with the endpoints swapped.
        CheckConstraint(
            "NOT is_symmetric OR source_asset_id < target_asset_id",
            name="symmetric_order",
        ),
        CheckConstraint(
            "NOT ((statement_class = 'INFERENCE' OR source_type = 'AI_INFERENCE')"
            " AND verification_status IN ('VERIFIED', 'APPROVED'))",
            name="inference_not_authoritative",
        ),
        CheckConstraint(
            "verification_status <> 'VERIFIED'"
            " OR (verified_by_subject IS NOT NULL AND verified_at IS NOT NULL)",
            name="verified_attribution",
        ),
        CheckConstraint(
            "verification_status <> 'APPROVED'"
            " OR (approved_by_subject IS NOT NULL AND approved_at IS NOT NULL)",
            name="approved_attribution",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_to >= valid_from",
            name="interval",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="confidence",
        ),
        ExcludeConstraint(
            ("source_asset_id", "="),
            ("relationship_type", "="),
            ("target_asset_id", "="),
            (text("coalesce(qualifier, '')"), "="),
            ("source_id", "="),
            (text("tstzrange(valid_from, valid_to)"), "&&"),
            name="ex_asset_relationship_no_overlap",
            using="gist",
        ),
        # coalesce() is required: NULL is not equal to NULL in a unique index,
        # so without it two rows with a null qualifier would both be permitted.
        Index(
            "uq_asset_relationship_live",
            "source_asset_id",
            "relationship_type",
            "target_asset_id",
            text("coalesce(qualifier, '')"),
            "source_id",
            unique=True,
            postgresql_where=text("valid_to IS NULL"),
        ),
        # Deliberately NO authority index. A fact's *value* can differ between
        # claims, so two authoritative claims can contradict. An edge's
        # endpoints are in the key, so two verified claims necessarily agree.
        Index(
            "ix_asset_relationship_out",
            "source_asset_id",
            "relationship_type",
            postgresql_where=text("valid_to IS NULL"),
        ),
        Index(
            "ix_asset_relationship_in",
            "target_asset_id",
            "relationship_type",
            postgresql_where=text("valid_to IS NULL"),
        ),
        Index(
            "ix_asset_relationship_type",
            "relationship_type",
            postgresql_where=text("valid_to IS NULL"),
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AssetRelationship {self.relationship_type} q={self.qualifier!r}>"


__all__ = ["AssetRelationship"]
