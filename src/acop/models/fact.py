"""Typed facts, their history, and the record of who trusted them.

Two tables:

* ``asset_fact`` - every claim ever made about an asset, append-only, with a
  validity interval. Superseding closes the old interval and inserts a new row.
* ``fact_attestation`` - an append-only record of every verify, approve and
  revoke. See the class docstring for why this is not left to the audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, ExcludeConstraint
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, UUIDPrimaryKeyMixin
from acop.models.provenance_mixin import ProvenanceMixin, ValidityIntervalMixin


class AssetFact(ProvenanceMixin, ValidityIntervalMixin, UUIDPrimaryKeyMixin, Base):
    """One claim about one asset, from one source, over one interval."""

    __tablename__ = "asset_fact"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey("asset.id", name="fk_asset_fact_asset_id_asset", ondelete="RESTRICT"),
        nullable=False,
    )
    predicate: Mapped[str] = mapped_column(String(128), nullable=False)
    fact_kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="OBSERVED_STATE | DESIRED_STATE - the axis independent of trust.",
    )

    # -- Typed value ----------------------------------------------------
    # Six nullable columns and a discriminator rather than one text column.
    # Casting text on read loses ordered comparison, and retrofitting types
    # onto accumulated values is a migration over live data.
    value_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Decimal, not float: NUMERIC is exact for integers and decimals alike, and
    # a byte count or a VLAN id must never come back rounded.
    value_number: Mapped[Decimal | None] = mapped_column(Numeric, nullable=True)
    value_bool: Mapped[bool | None] = mapped_column(nullable=True)
    value_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # none_as_null=True is essential, not cosmetic: JSONB otherwise stores
    # Python None as the JSON value `null`, which is NOT NULL to SQL - so
    # ck_asset_fact_value_exclusive would count it as a populated column and
    # reject every non-JSON fact.
    value_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    value_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_asset_fact_value_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    unit: Mapped[str | None] = mapped_column(String(24), nullable=True)

    # -- Lineage --------------------------------------------------------
    supersedes_fact_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey("asset_fact.id", name="fk_asset_fact_supersedes_fact_id_asset_fact"),
        nullable=True,
        doc=(
            "The row this one replaced. Deliberately a BACKWARD pointer: the "
            "close must precede the insert to satisfy uq_asset_fact_live_claim, "
            "so a forward pointer would reference a row that does not exist yet "
            "and fail its foreign key."
        ),
    )
    derived_from_fact_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey("asset_fact.id", name="fk_asset_fact_derived_from_fact_id_asset_fact"),
        nullable=True,
        doc="For a DESIRED_STATE promoted from an observation, the observation.",
    )

    __table_args__ = (
        CheckConstraint(
            r"predicate ~ '^[a-z0-9][a-z0-9_]*(\.[a-z0-9_]+)*$'",
            name="predicate_format",
        ),
        CheckConstraint(
            "(CASE WHEN value_text IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_number IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_bool IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_timestamp IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_json IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_asset_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="value_exclusive",
        ),
        CheckConstraint(
            "(value_type = 'TEXT' AND value_text IS NOT NULL)"
            " OR (value_type = 'NUMBER' AND value_number IS NOT NULL)"
            " OR (value_type = 'BOOL' AND value_bool IS NOT NULL)"
            " OR (value_type = 'TIMESTAMP' AND value_timestamp IS NOT NULL)"
            " OR (value_type = 'JSON' AND value_json IS NOT NULL)"
            " OR (value_type = 'ASSET_REF' AND value_asset_id IS NOT NULL)",
            name="value_type_matches",
        ),
        # The core safety property, enforced by the database so that a future
        # collector bug or a careless psql session cannot violate it.
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
            "fact_kind <> 'DESIRED_STATE' OR verification_status = 'APPROVED'",
            name="desired_is_approved",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_to >= valid_from",
            name="interval",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="confidence",
        ),
        # No overlapping intervals for one claim lineage. Without this,
        # "what was true at 10:30" can have two answers, which is corrupt
        # history rather than merely untidy. An open-ended range overlaps
        # everything after valid_from, so this also subsumes the live-claim
        # uniqueness below - both are kept because the partial unique index
        # gives a faster, more legible failure on the common mistake.
        ExcludeConstraint(
            ("asset_id", "="),
            ("predicate", "="),
            ("fact_kind", "="),
            ("source_id", "="),
            (text("tstzrange(valid_from, valid_to)"), "&&"),
            name="ex_asset_fact_no_overlap",
            using="gist",
        ),
        # One live claim per source. Two sources MAY disagree at once - that is
        # how conflict is stored rather than lost.
        Index(
            "uq_asset_fact_live_claim",
            "asset_id",
            "predicate",
            "fact_kind",
            "source_id",
            unique=True,
            postgresql_where=text("valid_to IS NULL"),
        ),
        # At most one AUTHORITATIVE live claim, so a resolved value is a
        # database guarantee. Also yields exactly one live desired state.
        Index(
            "uq_asset_fact_live_authority",
            "asset_id",
            "predicate",
            "fact_kind",
            unique=True,
            postgresql_where=text(
                "valid_to IS NULL AND verification_status IN ('VERIFIED', 'APPROVED')"
            ),
        ),
        Index(
            "ix_asset_fact_live",
            "asset_id",
            "predicate",
            postgresql_where=text("valid_to IS NULL"),
        ),
        Index("ix_asset_fact_history", "asset_id", "predicate", text("valid_from DESC")),
        Index(
            "ix_asset_fact_predicate",
            "predicate",
            postgresql_where=text("valid_to IS NULL"),
        ),
        Index(
            "ix_asset_fact_asset_ref",
            "value_asset_id",
            postgresql_where=text("value_asset_id IS NOT NULL"),
        ),
        Index(
            "ix_asset_fact_verification",
            "verification_status",
            postgresql_where=text("valid_to IS NULL"),
        ),
        Index(
            "ix_asset_fact_supersedes",
            "supersedes_fact_id",
            postgresql_where=text("supersedes_fact_id IS NOT NULL"),
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "live" if self.valid_to is None else "closed"
        return f"<AssetFact {self.predicate} {self.verification_status} {state}>"


class FactAttestation(UUIDPrimaryKeyMixin, Base):
    """Append-only record of every trust transition on a fact.

    **Why this exists rather than relying on the audit log.** ``audit_event``
    does record every verify and revoke with full principal attribution, and
    for a while that looked sufficient. It is not, for one reason: audit
    retention is an open question (docs/security/audit-immutability.md defers
    it to Milestone 10). If the only record of who verified a fact lives in a
    log that may later be tiered or pruned, accountability is not durable.

    **Why not extra columns on asset_fact.** ``revoked_by_subject`` /
    ``revoked_at`` alongside ``verified_by_subject`` would retain only the most
    recent verify/revoke pair. A verify → revoke → verify → revoke sequence
    would overwrite the first pair, which is exactly the erasure of historical
    attribution the requirement forbids.

    So the fact row carries *current* attribution - which the CHECK constraints
    reference and which makes the common query a single-row read - and this
    table carries the full immutable lineage. Clearing the fact's attribution
    columns on revoke is safe precisely because this record exists.
    """

    __tablename__ = "fact_attestation"

    fact_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset_fact.id",
            name="fk_fact_attestation_fact_id_asset_fact",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(16), nullable=False, doc="VERIFY | APPROVE | REVOKE"
    )
    from_status: Mapped[str] = mapped_column(String(16), nullable=False)
    to_status: Mapped[str] = mapped_column(String(16), nullable=False)

    # The provider-neutral identity contract, same four fields the audit log
    # uses, taken from Principal.to_audit_fields().
    principal_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)

    reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "action IN ('VERIFY', 'APPROVE', 'REVOKE')",
            name="action",
        ),
        Index("ix_fact_attestation_fact", "fact_id", text("occurred_at DESC")),
        Index("ix_fact_attestation_subject", "principal_subject", "occurred_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FactAttestation {self.action} by {self.principal_subject}>"
