"""Milestone 3c: pgvector, the embedding-space registry, partitioned vectors.

``CREATE EXTENSION vector`` lives here, before anything that depends on it, and
the downgrade deliberately does **not** drop it - mirroring how ``btree_gist``
was handled in 0002. Another object may depend on a shared extension, and
dropping one during a rollback is a worse failure than leaving it installed.
Installing it by migration rather than by hand is also what makes a database
restored from backup a *working* database.

The vector table is LIST-partitioned by ``embedding_space_id``. That is not a
stylistic choice - it was measured. A single table with one partial HNSW index
per space uses the index under a custom plan and silently falls back to
``Seq Scan`` under a **generic** plan, because PostgreSQL cannot prove
``space_id = $1`` implies the index predicate. SQLAlchemy with asyncpg uses
prepared statements, so that is the production path. Partitioning survives the
generic plan (``Append -> Subplans Removed: 1 -> Index Scan``), which is why
the partition *is* the space.

No embedding space row is inserted here. Registration is a deliberate operator
action that must record the provider's verified prompt-prefix behaviour, and a
migration cannot verify that.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None

#: Kept in step with acop.models.embedding.D768.
DIMENSIONS = 768
PARENT = f"knowledge_embedding_d{DIMENSIONS}"


def upgrade() -> None:
    # Must precede every dependent statement.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "embedding_space",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("space_key", sa.String(48), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("model_digest", sa.String(128), nullable=True),
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column(
            "distance_metric", sa.String(16), nullable=False, server_default="cosine"
        ),
        sa.Column("normalize_vectors", sa.Boolean(), nullable=False),
        sa.Column("document_prefix", sa.String(255), nullable=False, server_default=""),
        sa.Column("query_prefix", sa.String(255), nullable=False, server_default=""),
        sa.Column("prefix_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("prefix_verified_by_subject", sa.String(255), nullable=True),
        sa.Column("max_input_tokens", sa.Integer(), nullable=False),
        sa.Column(
            "truncation_policy",
            sa.String(24),
            nullable=False,
            server_default="REJECT_OVERSIZE",
        ),
        sa.Column("storage_relation", sa.String(63), nullable=False),
        sa.Column("partition_relation", sa.String(63), nullable=False),
        sa.Column(
            "lifecycle_state", sa.String(16), nullable=False, server_default="ACTIVE"
        ),
        sa.Column(
            "is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("space_key", name="uq_embedding_space_key"),
        # The machine-readable definition of "same embedding space". Change any
        # element and you necessarily get a different row.
        sa.UniqueConstraint(
            "provider",
            "model",
            "model_digest",
            "dimensions",
            "distance_metric",
            "normalize_vectors",
            "document_prefix",
            "query_prefix",
            "truncation_policy",
            name="uq_embedding_space_identity",
        ),
        # Measured: vector(2001) is a legal column but cannot carry an HNSW
        # index, which would silently make every search a sequential scan.
        sa.CheckConstraint("dimensions BETWEEN 1 AND 2000", name="dimensions_indexable"),
        sa.CheckConstraint(
            "space_key ~ '^[a-z][a-z0-9_]{2,47}$'", name="space_key_format"
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('ACTIVE','DEPRECATED','RETIRED')",
            name="lifecycle_state",
        ),
    )
    op.create_index(
        "uq_embedding_space_default",
        "embedding_space",
        ["is_default"],
        unique=True,
        postgresql_where=sa.text("is_default"),
    )

    # The partitioned parent. The d<N> suffix names a pgvector storage
    # constraint; a partition of it names a semantic space.
    op.execute(
        f"""
        CREATE TABLE {PARENT} (
            id                    uuid    NOT NULL,
            embedding_space_id    uuid    NOT NULL,
            chunk_id              uuid    NOT NULL,
            source_id             uuid    NOT NULL,
            document_id           uuid    NOT NULL,
            embedding             vector({DIMENSIONS}) NOT NULL,
            is_current_embedding  boolean NOT NULL DEFAULT true,
            is_retrievable        boolean NOT NULL DEFAULT true,
            sensitivity           varchar(16) NOT NULL,
            input_token_estimate  integer NOT NULL,
            was_truncated         boolean NOT NULL DEFAULT false,
            created_at            timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT pk_{PARENT} PRIMARY KEY (id, embedding_space_id),
            CONSTRAINT fk_{PARENT}_embedding_space_id_embedding_space
                FOREIGN KEY (embedding_space_id) REFERENCES embedding_space(id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_{PARENT}_chunk_id_knowledge_chunk
                FOREIGN KEY (chunk_id) REFERENCES knowledge_chunk(id)
                ON DELETE RESTRICT
        ) PARTITION BY LIST (embedding_space_id)
        """
    )
    # One current vector per (chunk, space). The partition key is part of the
    # key, which PostgreSQL requires for a unique index on a partitioned table.
    op.execute(
        f"""
        CREATE UNIQUE INDEX uq_ke_d{DIMENSIONS}_current
            ON {PARENT} (chunk_id, embedding_space_id)
            WHERE is_current_embedding
        """
    )


def downgrade() -> None:
    op.execute(f"DROP TABLE IF EXISTS {PARENT} CASCADE")
    op.drop_index("uq_embedding_space_default", table_name="embedding_space")
    op.drop_table("embedding_space")
    # The vector extension is deliberately NOT dropped. See the module
    # docstring; 0002 handles btree_gist the same way.
