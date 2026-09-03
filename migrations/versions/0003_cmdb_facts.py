"""Milestone 2b: typed facts, history, and trust attestations.

The heart of the CMDB. Every claim carries provenance and a validity interval;
nothing is ever overwritten. Two guarantees are worth reading the constraints
for:

* ``ck_asset_fact_inference_not_authoritative`` - an AI inference can never
  hold VERIFIED or APPROVED. Enforced by the database, so a future collector
  bug or a careless psql session cannot violate it.
* ``uq_asset_fact_live_authority`` - at most one live authoritative claim per
  (asset, predicate, fact_kind), so "the resolved value" is a database
  guarantee rather than a convention.

Requires ``btree_gist``, installed by 0002.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_fact",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("predicate", sa.String(length=128), nullable=False),
        sa.Column("fact_kind", sa.String(length=16), nullable=False),
        sa.Column("statement_class", sa.String(length=16), nullable=False),
        # Typed value: six nullable columns plus a discriminator, with CHECKs
        # enforcing exactly one set and matching. One text column would lose
        # ordered comparison, and retrofitting types onto accumulated values is
        # a migration over live data.
        sa.Column("value_type", sa.String(length=16), nullable=False),
        sa.Column("value_text", sa.Text(), nullable=True),
        sa.Column("value_number", sa.Numeric(), nullable=True),
        sa.Column("value_bool", sa.Boolean(), nullable=True),
        sa.Column("value_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("value_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("value_asset_id", sa.UUID(), nullable=True),
        sa.Column("unit", sa.String(length=24), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column(
            "confidence",
            sa.Numeric(precision=4, scale=3, asdecimal=False),
            server_default="1.000",
            nullable=False,
        ),
        sa.Column("verification_status", sa.String(length=16), nullable=False),
        sa.Column("verified_by_subject", sa.String(length=255), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by_subject", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        # Backward pointer. A forward "superseded_by" cannot work: the close
        # must precede the insert to satisfy uq_asset_fact_live_claim, so it
        # would reference a row that does not exist yet.
        sa.Column("supersedes_fact_id", sa.UUID(), nullable=True),
        sa.Column("derived_from_fact_id", sa.UUID(), nullable=True),
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            r"predicate ~ '^[a-z0-9][a-z0-9_]*(\.[a-z0-9_]+)*$'",
            name="predicate_format",
        ),
        sa.CheckConstraint(
            "(CASE WHEN value_text IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_number IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_bool IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_timestamp IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_json IS NOT NULL THEN 1 ELSE 0 END"
            " + CASE WHEN value_asset_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="value_exclusive",
        ),
        sa.CheckConstraint(
            "(value_type = 'TEXT' AND value_text IS NOT NULL)"
            " OR (value_type = 'NUMBER' AND value_number IS NOT NULL)"
            " OR (value_type = 'BOOL' AND value_bool IS NOT NULL)"
            " OR (value_type = 'TIMESTAMP' AND value_timestamp IS NOT NULL)"
            " OR (value_type = 'JSON' AND value_json IS NOT NULL)"
            " OR (value_type = 'ASSET_REF' AND value_asset_id IS NOT NULL)",
            name="value_type_matches",
        ),
        sa.CheckConstraint(
            "NOT ((statement_class = 'INFERENCE' OR source_type = 'AI_INFERENCE')"
            " AND verification_status IN ('VERIFIED', 'APPROVED'))",
            name="inference_not_authoritative",
        ),
        sa.CheckConstraint(
            "verification_status <> 'VERIFIED'"
            " OR (verified_by_subject IS NOT NULL AND verified_at IS NOT NULL)",
            name="verified_attribution",
        ),
        sa.CheckConstraint(
            "verification_status <> 'APPROVED'"
            " OR (approved_by_subject IS NOT NULL AND approved_at IS NOT NULL)",
            name="approved_attribution",
        ),
        sa.CheckConstraint(
            "fact_kind <> 'DESIRED_STATE' OR verification_status = 'APPROVED'",
            name="desired_is_approved",
        ),
        sa.CheckConstraint("valid_to IS NULL OR valid_to >= valid_from", name="interval"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence"),
        # Non-overlapping history. Without it, "what was true at 10:30" can
        # have two answers - corrupt history, not merely untidy.
        postgresql.ExcludeConstraint(
            (sa.column("asset_id"), "="),
            (sa.column("predicate"), "="),
            (sa.column("fact_kind"), "="),
            (sa.column("source_id"), "="),
            (sa.text("tstzrange(valid_from, valid_to)"), "&&"),
            using="gist",
            name="ex_asset_fact_no_overlap",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name="fk_asset_fact_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["value_asset_id"],
            ["asset.id"],
            name="fk_asset_fact_value_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_fact_id"],
            ["asset_fact.id"],
            name="fk_asset_fact_supersedes_fact_id_asset_fact",
        ),
        sa.ForeignKeyConstraint(
            ["derived_from_fact_id"],
            ["asset_fact.id"],
            name="fk_asset_fact_derived_from_fact_id_asset_fact",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_asset_fact"),
    )
    # One live claim per source. Multiple sources MAY disagree at once: that is
    # the storage representation of conflict.
    op.create_index(
        "uq_asset_fact_live_claim",
        "asset_fact",
        ["asset_id", "predicate", "fact_kind", "source_id"],
        unique=True,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    # At most one AUTHORITATIVE live claim. Also yields exactly one live
    # desired state, since DESIRED_STATE must be APPROVED.
    op.create_index(
        "uq_asset_fact_live_authority",
        "asset_fact",
        ["asset_id", "predicate", "fact_kind"],
        unique=True,
        postgresql_where=sa.text(
            "valid_to IS NULL AND verification_status IN ('VERIFIED', 'APPROVED')"
        ),
    )
    op.create_index(
        "ix_asset_fact_live",
        "asset_fact",
        ["asset_id", "predicate"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_index(
        "ix_asset_fact_history",
        "asset_fact",
        ["asset_id", "predicate", sa.literal_column("valid_from DESC")],
        unique=False,
    )
    op.create_index(
        "ix_asset_fact_predicate",
        "asset_fact",
        ["predicate"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_index(
        "ix_asset_fact_asset_ref",
        "asset_fact",
        ["value_asset_id"],
        unique=False,
        postgresql_where=sa.text("value_asset_id IS NOT NULL"),
    )
    op.create_index(
        "ix_asset_fact_verification",
        "asset_fact",
        ["verification_status"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_index(
        "ix_asset_fact_supersedes",
        "asset_fact",
        ["supersedes_fact_id"],
        unique=False,
        postgresql_where=sa.text("supersedes_fact_id IS NOT NULL"),
    )

    # Append-only lineage of every verify, approve and revoke. Kept in the
    # domain rather than left to audit_event because audit retention is an open
    # question - accountability must not depend on a log that may be pruned.
    op.create_table(
        "fact_attestation",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("fact_id", sa.UUID(), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=False),
        sa.Column("to_status", sa.String(length=16), nullable=False),
        sa.Column("principal_subject", sa.String(length=255), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("principal_issuer", sa.String(length=255), nullable=False),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=1024), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('VERIFY', 'APPROVE', 'REVOKE')",
            name="action",
        ),
        sa.ForeignKeyConstraint(
            ["fact_id"],
            ["asset_fact.id"],
            name="fk_fact_attestation_fact_id_asset_fact",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_fact_attestation"),
    )
    op.create_index(
        "ix_fact_attestation_fact",
        "fact_attestation",
        ["fact_id", sa.literal_column("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_fact_attestation_subject",
        "fact_attestation",
        ["principal_subject", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_fact_attestation_subject", table_name="fact_attestation")
    op.drop_index("ix_fact_attestation_fact", table_name="fact_attestation")
    op.drop_table("fact_attestation")

    op.drop_index("ix_asset_fact_supersedes", table_name="asset_fact")
    op.drop_index("ix_asset_fact_verification", table_name="asset_fact")
    op.drop_index("ix_asset_fact_asset_ref", table_name="asset_fact")
    op.drop_index("ix_asset_fact_predicate", table_name="asset_fact")
    op.drop_index("ix_asset_fact_history", table_name="asset_fact")
    op.drop_index("ix_asset_fact_live", table_name="asset_fact")
    op.drop_index("uq_asset_fact_live_authority", table_name="asset_fact")
    op.drop_index("uq_asset_fact_live_claim", table_name="asset_fact")
    op.drop_table("asset_fact")
