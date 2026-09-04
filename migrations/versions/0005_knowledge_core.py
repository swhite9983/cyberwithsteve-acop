"""Milestone 3a: knowledge sources, documents, immutable versions and chunks.

Also creates the ingest-attempt boundary. The ordering in this file matters:
``knowledge_ingest_attempt`` exists so that a rejected or quarantined
submission has somewhere to be recorded **without** creating an incomplete
canonical version. The CHECK named ``only_successful_attempts_have_versions``
is that rule as a database invariant rather than a convention the service layer
has to remember.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # -- sources -------------------------------------------------------
    op.create_table(
        "knowledge_source",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("uri", sa.String(2048), nullable=True),
        sa.Column("origin", sa.String(255), nullable=False),
        sa.Column("owner_subject", sa.String(255), nullable=True),
        sa.Column("trust_class", sa.String(32), nullable=False),
        sa.Column("sensitivity", sa.String(16), nullable=False),
        sa.Column(
            "lifecycle_state",
            sa.String(16),
            nullable=False,
            server_default="ACTIVE",
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by_subject", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        sa.CheckConstraint(
            "sensitivity IN ('PUBLIC','INTERNAL','CONFIDENTIAL')", name="sensitivity"
        ),
    )
    op.create_index(
        "ix_knowledge_source_kind_state",
        "knowledge_source",
        ["source_kind", "lifecycle_state"],
    )
    op.create_index("ix_knowledge_source_created_at", "knowledge_source", ["created_at"])

    # -- documents -----------------------------------------------------
    op.create_table(
        "knowledge_document",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_ref", sa.String(1024), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("current_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "lifecycle_state", sa.String(16), nullable=False, server_default="ACTIVE"
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by_subject", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["knowledge_source.id"],
            name="fk_knowledge_document_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
    )
    # Partial unique: what makes a re-ingest resolve to the same document
    # instead of duplicating it.
    op.create_index(
        "uq_knowledge_document_source_ref",
        "knowledge_document",
        ["source_id", "external_ref"],
        unique=True,
        postgresql_where=sa.text("lifecycle_state = 'ACTIVE'"),
    )
    op.create_index(
        "ix_knowledge_document_source",
        "knowledge_document",
        ["source_id"],
        postgresql_where=sa.text("lifecycle_state = 'ACTIVE'"),
    )
    op.create_index(
        "ix_knowledge_document_created_at", "knowledge_document", ["created_at"]
    )

    # -- immutable versions --------------------------------------------
    op.create_table(
        "knowledge_document_version",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column("raw_content_hash", sa.String(64), nullable=False),
        sa.Column("text_content_hash", sa.String(64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("char_count", sa.Integer(), nullable=False),
        sa.Column("parser_name", sa.String(64), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("chunker_name", sa.String(64), nullable=False),
        sa.Column("chunker_version", sa.String(32), nullable=False),
        sa.Column(
            "chunker_params",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("ingested_by_subject", sa.String(255), nullable=False),
        sa.Column("supersedes_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("screening_outcome", sa.String(16), nullable=False),
        sa.Column("created_by_attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["knowledge_document.id"],
            name="fk_knowledge_document_version_document_id_knowledge_document",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_version_id"],
            ["knowledge_document_version.id"],
            name="fk_kdv_supersedes_version_id_kdv",
        ),
        sa.UniqueConstraint("document_id", "version_no", name="uq_document_version_no"),
        # The idempotence guarantee.
        sa.UniqueConstraint(
            "document_id", "raw_content_hash", name="uq_document_raw_hash"
        ),
        sa.CheckConstraint("version_no > 0", name="version_no_positive"),
        sa.CheckConstraint(
            "(supersedes_version_id IS NULL) = (version_no = 1)",
            name="supersession_matches_version_no",
        ),
        # QUARANTINED is not a legal value here: a quarantined submission never
        # produces a version.
        sa.CheckConstraint(
            "screening_outcome IN ('CLEAN','FLAGGED')", name="screening_outcome"
        ),
    )
    op.create_index(
        "ix_knowledge_document_version_created_at",
        "knowledge_document_version",
        ["created_at"],
    )
    op.create_index(
        "ix_knowledge_document_version_history",
        "knowledge_document_version",
        ["document_id", sa.text("version_no DESC")],
    )
    op.create_index(
        "ix_knowledge_document_version_live",
        "knowledge_document_version",
        ["document_id"],
        postgresql_where=sa.text("superseded_at IS NULL"),
    )

    # -- immutable chunks ----------------------------------------------
    op.create_table(
        "knowledge_chunk",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("char_start", sa.Integer(), nullable=False),
        sa.Column("char_end", sa.Integer(), nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False),
        sa.Column("heading_path", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("section_label", sa.String(255), nullable=True),
        sa.Column("page_number", sa.Integer(), nullable=True),
        # GENERATED, not a trigger: PostgreSQL keeps it consistent by
        # construction and no code path can forget it.
        sa.Column(
            "lexeme",
            postgresql.TSVECTOR(),
            sa.Computed("to_tsvector('english', content)", persisted=True),
            nullable=False,
        ),
        sa.Column(
            "flags",
            postgresql.ARRAY(sa.String(32)),
            nullable=False,
            server_default=sa.text("'{}'::varchar[]"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["knowledge_document_version.id"],
            name="fk_knowledge_chunk_version_id_knowledge_document_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["knowledge_document.id"],
            name="fk_knowledge_chunk_document_id_knowledge_document",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["knowledge_source.id"],
            name="fk_knowledge_chunk_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("version_id", "ordinal", name="uq_chunk_version_ordinal"),
        sa.CheckConstraint("char_end > char_start", name="char_range"),
        sa.CheckConstraint("ordinal >= 0", name="ordinal_non_negative"),
        sa.CheckConstraint("length(content) > 0", name="content_not_empty"),
    )
    op.create_index(
        "ix_knowledge_chunk_lexeme",
        "knowledge_chunk",
        ["lexeme"],
        postgresql_using="gin",
    )
    op.create_index("ix_knowledge_chunk_document", "knowledge_chunk", ["document_id"])
    op.create_index("ix_knowledge_chunk_source", "knowledge_chunk", ["source_id"])
    op.create_index("ix_knowledge_chunk_version", "knowledge_chunk", ["version_id"])

    # -- ingest attempts (process record, never canonical) --------------
    op.create_table(
        "knowledge_ingest_attempt",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_ref", sa.String(1024), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("raw_content_hash", sa.String(64), nullable=False),
        sa.Column("text_content_hash", sa.String(64), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("requested_by_subject", sa.String(255), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("principal_issuer", sa.String(255), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("chunk_count", sa.Integer(), nullable=True),
        sa.Column("embedded_count", sa.Integer(), nullable=True),
        sa.Column(
            "blocking_finding_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["knowledge_source.id"],
            name="fk_knowledge_ingest_attempt_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["knowledge_document.id"],
            name="fk_knowledge_ingest_attempt_document_id_knowledge_document",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["knowledge_document_version.id"],
            name="fk_kia_version_id_kdv",
        ),
        sa.CheckConstraint(
            "(outcome <> 'PENDING') = (finished_at IS NOT NULL)",
            name="finished_matches_outcome",
        ),
        # R3 §2, in SQL: a failed attempt can never reference canonical state.
        sa.CheckConstraint(
            "(outcome IN ('CREATED','VERSIONED')) = (version_id IS NOT NULL)",
            name="successful_has_version",
        ),
    )
    op.create_index(
        "ix_knowledge_ingest_attempt_target",
        "knowledge_ingest_attempt",
        ["source_id", "external_ref", sa.text("started_at DESC")],
    )
    op.create_index(
        "ix_knowledge_ingest_attempt_hash",
        "knowledge_ingest_attempt",
        ["raw_content_hash"],
    )
    op.create_index(
        "ix_knowledge_ingest_attempt_blocked",
        "knowledge_ingest_attempt",
        [sa.text("started_at DESC")],
        postgresql_where=sa.text("outcome = 'REJECTED_SECRET'"),
    )

    # -- findings: positions and fingerprints, never values -------------
    op.create_table(
        "knowledge_finding",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("chunk_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("finding_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("detector", sa.String(64), nullable=False),
        sa.Column("detector_version", sa.String(32), nullable=False),
        sa.Column("locator", sa.String(255), nullable=False),
        sa.Column("match_fingerprint", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["attempt_id"],
            ["knowledge_ingest_attempt.id"],
            name="fk_knowledge_finding_attempt_id_knowledge_ingest_attempt",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["knowledge_document_version.id"],
            name="fk_knowledge_finding_version_id_knowledge_document_version",
        ),
        sa.ForeignKeyConstraint(
            ["chunk_id"],
            ["knowledge_chunk.id"],
            name="fk_knowledge_finding_chunk_id_knowledge_chunk",
        ),
        sa.CheckConstraint("severity IN ('BLOCKING','ADVISORY')", name="severity"),
    )
    op.create_index("ix_knowledge_finding_attempt", "knowledge_finding", ["attempt_id"])
    op.create_index(
        "ix_knowledge_finding_fingerprint", "knowledge_finding", ["match_fingerprint"]
    )
    op.create_index("ix_knowledge_finding_version", "knowledge_finding", ["version_id"])

    # -- dispositions: scoped approver judgements -----------------------
    op.create_table(
        "knowledge_finding_disposition",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_ref", sa.String(1024), nullable=False),
        sa.Column("raw_content_hash", sa.String(64), nullable=False),
        sa.Column("match_fingerprint", sa.String(64), nullable=False),
        sa.Column("detector", sa.String(64), nullable=False),
        sa.Column("disposition", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("decided_by_subject", sa.String(255), nullable=False),
        sa.Column("origin_attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["knowledge_source.id"],
            name="fk_knowledge_finding_disposition_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["origin_attempt_id"],
            ["knowledge_ingest_attempt.id"],
            name="fk_kfd_origin_attempt_id_kia",
        ),
        sa.CheckConstraint(
            "disposition IN ('FALSE_POSITIVE','REMEDIATED_AT_SOURCE')",
            name="disposition",
        ),
    )
    op.create_index(
        "ix_knowledge_finding_disposition_scope",
        "knowledge_finding_disposition",
        [
            "source_id",
            "external_ref",
            "raw_content_hash",
            "match_fingerprint",
            sa.text("decided_at DESC"),
        ],
    )

    # -- asset mentions: knowledge -> CMDB, one way ---------------------
    op.create_table(
        "knowledge_asset_mention",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("chunk_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("mention_text", sa.String(255), nullable=False),
        sa.Column("mention_source", sa.String(24), nullable=False),
        sa.Column("resolution", sa.String(16), nullable=False),
        sa.Column(
            "candidate_asset_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("'{}'::uuid[]"),
        ),
        sa.Column("matched_namespace", sa.String(48), nullable=True),
        sa.Column("created_by_subject", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["chunk_id"],
            ["knowledge_chunk.id"],
            name="fk_knowledge_asset_mention_chunk_id_knowledge_chunk",
            ondelete="RESTRICT",
        ),
        # The boundary: knowledge references the CMDB and nothing in the
        # Milestone 2 schema points back.
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name="fk_knowledge_asset_mention_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(resolution = 'RESOLVED') = (asset_id IS NOT NULL)",
            name="resolution_matches_asset",
        ),
        sa.CheckConstraint(
            "resolution <> 'AMBIGUOUS' OR array_length(candidate_asset_ids, 1) > 1",
            name="ambiguous_has_candidates",
        ),
        sa.CheckConstraint(
            "mention_source IN ('IDENTIFIER_MATCH','EXPLICIT')", name="mention_source"
        ),
    )
    op.create_index(
        "ix_knowledge_asset_mention_asset",
        "knowledge_asset_mention",
        ["asset_id"],
        postgresql_where=sa.text("asset_id IS NOT NULL"),
    )
    op.create_index(
        "ix_knowledge_asset_mention_chunk", "knowledge_asset_mention", ["chunk_id"]
    )


def downgrade() -> None:
    op.drop_table("knowledge_asset_mention")
    op.drop_table("knowledge_finding_disposition")
    op.drop_table("knowledge_finding")
    op.drop_table("knowledge_ingest_attempt")
    op.drop_table("knowledge_chunk")
    op.drop_table("knowledge_document_version")
    op.drop_table("knowledge_document")
    op.drop_table("knowledge_source")
