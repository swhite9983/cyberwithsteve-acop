"""Milestone 2a: assets and external identifiers.

Creates the identity layer. An asset's durable identity is its UUID and
nothing else; every natural key lives in ``asset_identifier`` as a correlator,
because serials are absent on VMs, MACs are reused, hostnames change and
Proxmox VMIDs are reissued after deletion.

Also installs ``btree_gist``, which the exclusion constraints in 0003 and 0004
require. It is created here, in the first CMDB migration, so that it is
unambiguously present before any statement that depends on it. The downgrade
deliberately does **not** drop it: dropping an extension other objects may use
is riskier than leaving an unused one installed.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Required by ex_asset_fact_no_overlap (0003) and
    # ex_asset_relationship_no_overlap (0004). Standard contrib module, already
    # present in the pgvector/pgvector:pg16 image. This is NOT pgvector, which
    # remains Milestone 3.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")

    op.create_table(
        "asset",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column(
            "lifecycle_state",
            sa.String(length=16),
            server_default="ACTIVE",
            nullable=False,
        ),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("merged_into_id", sa.UUID(), nullable=True),
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
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'MERGED') = (merged_into_id IS NOT NULL)",
            name="merged_state",
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        sa.CheckConstraint("merged_into_id IS DISTINCT FROM id", name="no_self_merge"),
        sa.ForeignKeyConstraint(
            ["merged_into_id"], ["asset.id"], name="fk_asset_merged_into_id_asset"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_asset"),
    )
    op.create_index("ix_asset_created_at", "asset", ["created_at"], unique=False)
    op.create_index(
        "ix_asset_display_name_lower",
        "asset",
        [sa.literal_column("lower(display_name)")],
        unique=False,
    )
    op.create_index(
        "ix_asset_last_seen",
        "asset",
        [sa.literal_column("last_seen_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_asset_type_state", "asset", ["asset_type", "lifecycle_state"], unique=False
    )

    op.create_table(
        "asset_identifier",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("namespace", sa.String(length=48), nullable=False),
        sa.Column("value_raw", sa.String(length=255), nullable=False),
        sa.Column("value_normalized", sa.String(length=255), nullable=False),
        sa.Column("unique_in_namespace", sa.Boolean(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column(
            "confidence",
            sa.Numeric(precision=4, scale=3, asdecimal=False),
            server_default="1.000",
            nullable=False,
        ),
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
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "namespace ~ '^[a-z0-9]+(:[a-z0-9_-]+)*$'",
            name="namespace_format",
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name="fk_asset_identifier_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_asset_identifier"),
    )
    op.create_index(
        "ix_asset_identifier_asset",
        "asset_identifier",
        ["asset_id"],
        unique=False,
        postgresql_where=sa.text("retired_at IS NULL"),
    )
    op.create_index(
        "ix_asset_identifier_created_at",
        "asset_identifier",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_asset_identifier_lookup",
        "asset_identifier",
        ["namespace", "value_normalized"],
        unique=False,
    )
    # The deduplication guarantee. Only namespaces the code registry declares
    # globally unique participate, and only while the identifier is live - so
    # retiring one frees the value for legitimate reuse.
    op.create_index(
        "uq_asset_identifier_live_unique",
        "asset_identifier",
        ["namespace", "value_normalized"],
        unique=True,
        postgresql_where=sa.text("retired_at IS NULL AND unique_in_namespace"),
    )
    op.create_index(
        "uq_asset_identifier_asset_ns_value",
        "asset_identifier",
        ["asset_id", "namespace", "value_normalized"],
        unique=True,
        postgresql_where=sa.text("retired_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_asset_identifier_asset_ns_value", table_name="asset_identifier")
    op.drop_index("uq_asset_identifier_live_unique", table_name="asset_identifier")
    op.drop_index("ix_asset_identifier_lookup", table_name="asset_identifier")
    op.drop_index("ix_asset_identifier_created_at", table_name="asset_identifier")
    op.drop_index("ix_asset_identifier_asset", table_name="asset_identifier")
    op.drop_table("asset_identifier")

    op.drop_index("ix_asset_type_state", table_name="asset")
    op.drop_index("ix_asset_last_seen", table_name="asset")
    op.drop_index("ix_asset_display_name_lower", table_name="asset")
    op.drop_index("ix_asset_created_at", table_name="asset")
    op.drop_table("asset")
    # btree_gist is intentionally left installed.
