"""Milestone 2c: typed directed edges between assets.

One edge table with a ``relationship_type`` column, both endpoints indexed.
That shape is what lets Milestone 8 answer "everything that transitively
depends on this switch" with a recursive CTE instead of a graph database.

``ck_asset_relationship_symmetric_order`` is the constraint worth noting: a
symmetric edge is stored once, in canonical UUID order, so one physical link
cannot appear twice with the endpoints swapped. Without it, topology
double-counts and retiring one row leaves a phantom half-link.

Requires ``btree_gist``, installed by 0002.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_relationship",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("relationship_type", sa.String(length=32), nullable=False),
        sa.Column("source_asset_id", sa.UUID(), nullable=False),
        sa.Column("target_asset_id", sa.UUID(), nullable=False),
        sa.Column("is_symmetric", sa.Boolean(), nullable=False),
        sa.Column("qualifier", sa.String(length=128), nullable=True),
        sa.Column("statement_class", sa.String(length=16), nullable=False),
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
        sa.Column("supersedes_rel_id", sa.UUID(), nullable=True),
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
        sa.CheckConstraint("source_asset_id <> target_asset_id", name="no_self"),
        sa.CheckConstraint(
            "NOT is_symmetric OR source_asset_id < target_asset_id",
            name="symmetric_order",
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
            "valid_to IS NULL OR valid_to >= valid_from",
            name="interval",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="confidence",
        ),
        postgresql.ExcludeConstraint(
            (sa.column("source_asset_id"), "="),
            (sa.column("relationship_type"), "="),
            (sa.column("target_asset_id"), "="),
            (sa.text("coalesce(qualifier, '')"), "="),
            (sa.column("source_id"), "="),
            (sa.text("tstzrange(valid_from, valid_to)"), "&&"),
            using="gist",
            name="ex_asset_relationship_no_overlap",
        ),
        sa.ForeignKeyConstraint(
            ["source_asset_id"],
            ["asset.id"],
            name="fk_asset_relationship_source_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_asset_id"],
            ["asset.id"],
            name="fk_asset_relationship_target_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_rel_id"],
            ["asset_relationship.id"],
            name="fk_asset_relationship_supersedes_rel_id_asset_relationship",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_asset_relationship"),
    )
    # coalesce() is required: NULL is not equal to NULL in a unique index, so
    # without it two rows with a null qualifier would both be permitted.
    op.create_index(
        "uq_asset_relationship_live",
        "asset_relationship",
        [
            "source_asset_id",
            "relationship_type",
            "target_asset_id",
            sa.literal_column("coalesce(qualifier, '')"),
            "source_id",
        ],
        unique=True,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    # Both directions indexed. The reverse index is the one an outage query
    # uses: "what depends on this host".
    op.create_index(
        "ix_asset_relationship_out",
        "asset_relationship",
        ["source_asset_id", "relationship_type"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_index(
        "ix_asset_relationship_in",
        "asset_relationship",
        ["target_asset_id", "relationship_type"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_index(
        "ix_asset_relationship_type",
        "asset_relationship",
        ["relationship_type"],
        unique=False,
        postgresql_where=sa.text("valid_to IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_asset_relationship_type", table_name="asset_relationship")
    op.drop_index("ix_asset_relationship_in", table_name="asset_relationship")
    op.drop_index("ix_asset_relationship_out", table_name="asset_relationship")
    op.drop_index("uq_asset_relationship_live", table_name="asset_relationship")
    op.drop_table("asset_relationship")
