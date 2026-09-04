"""Knowledge sources, documents, versions and chunks — the evidence store.

Nothing in this module is authoritative infrastructure state. A chunk saying
"switch01 uses VLAN 100" records *what a document claims*, from a source of
known trust, at a known time. Promoting such a claim into the CMDB is a human
act through Milestone 2's assert/verify workflow, and Milestone 3 contains no
code path that performs it.

**Two immutability rules govern this file, and they are not the same rule.**

1. ``KnowledgeDocumentVersion`` and ``KnowledgeChunk`` are *canonical* and
   immutable: once written, their content never changes. A changed document
   produces a new version. Citations anchor to a chunk id and therefore resolve
   for ever.
2. ``KnowledgeIngestAttempt`` is a *process* record and is append-only but not
   canonical. It exists precisely so that a failed or quarantined submission
   has somewhere to be recorded **without** creating an incomplete canonical
   version. Letting those two kinds of record share a table was the defect
   corrected in R3 §2: with a unique index on ``(document_id,
   raw_content_hash)``, a post-override success would have had to either mutate
   an immutable row or duplicate it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from acop.models.knowledge_vocabulary import (
    IngestOutcome,
    KnowledgeLifecycle,
    ScreeningOutcome,
)


class KnowledgeSource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Where knowledge comes from, and how far it is trusted.

    Trust and sensitivity live here rather than on each document so that
    downgrading a source is one row, not a sweep. Both are inherited by every
    document, version and chunk beneath.
    """

    __tablename__ = "knowledge_source"

    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    uri: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        doc="Path or URL the material came from; NULL for text pasted in.",
    )
    origin: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="Who or what provided this material."
    )
    owner_subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="Provider-neutral Principal subject of the owner, if known.",
    )
    trust_class: Mapped[str] = mapped_column(String(32), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(16), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=KnowledgeLifecycle.ACTIVE.value,
        server_default=KnowledgeLifecycle.ACTIVE.value,
    )
    source_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB(none_as_null=True),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        doc=(
            "Descriptive labelling for humans and filters - vendor, product "
            "family, document number. Explicitly NOT a fact store: no "
            "retrieval decision may depend on an unregistered key."
        ),
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    retired_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        CheckConstraint(
            "sensitivity IN ('PUBLIC','INTERNAL','CONFIDENTIAL')", name="sensitivity"
        ),
        Index("ix_knowledge_source_kind_state", "source_kind", "lifecycle_state"),
        Index("ix_knowledge_source_created_at", "created_at"),
    )


class KnowledgeDocument(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One document within a source, stable across all its revisions.

    ``current_version_id`` is the only mutable link in the version chain. It is
    denormalised because "give me the current text" is the dominant query and
    walking ``ORDER BY version_no DESC LIMIT 1`` on every retrieval is waste.
    """

    __tablename__ = "knowledge_document"

    source_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_source.id",
            name="fk_knowledge_document_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    external_ref: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        doc="Filename or logical path. Stable across versions; the natural key.",
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True), nullable=True
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=KnowledgeLifecycle.ACTIVE.value,
        server_default=KnowledgeLifecycle.ACTIVE.value,
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    retired_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        # Partial unique: this is what makes re-ingest resolve to the same
        # document rather than duplicating it - the direct analogue of
        # Milestone 2's identity resolution.
        Index(
            "uq_knowledge_document_source_ref",
            "source_id",
            "external_ref",
            unique=True,
            postgresql_where=text("lifecycle_state = 'ACTIVE'"),
        ),
        Index(
            "ix_knowledge_document_source",
            "source_id",
            postgresql_where=text("lifecycle_state = 'ACTIVE'"),
        ),
    )


class KnowledgeDocumentVersion(UUIDPrimaryKeyMixin, Base):
    """What a document said on one occasion. Immutable.

    Two content hashes, deliberately. ``raw_content_hash`` answers "is this the
    identical file?" and drives idempotence. ``text_content_hash`` answers "did
    the meaning change?", so a cosmetic re-encode (CRLF to LF, a BOM added) is
    recognised as a no-op even though the bytes differ. Storing only one forces
    a choice between false-positive versions and missed changes.
    """

    __tablename__ = "knowledge_document_version"

    document_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document.id",
            name="fk_knowledge_document_version_document_id_knowledge_document",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    text_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False)

    parser_name: Mapped[str] = mapped_column(String(64), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    chunker_name: Mapped[str] = mapped_column(String(64), nullable=False)
    chunker_version: Mapped[str] = mapped_column(String(32), nullable=False)
    chunker_params: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        doc=(
            "Chunk boundaries are only reproducible if the settings that "
            "produced them are known. Without this, 're-chunk this version "
            "identically' is unanswerable a year later."
        ),
    )

    source_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ingested_by_subject: Mapped[str] = mapped_column(String(255), nullable=False)

    supersedes_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document_version.id",
            name="fk_kdv_supersedes_version_id_kdv",
        ),
        nullable=True,
        doc=(
            "Points BACKWARDS, for ADR-0007's reason: at the moment a version "
            "is superseded its replacement does not exist yet, so a forward "
            "pointer would require updating a historical row."
        ),
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc=(
            "The single exception to immutability: a closure marker written on "
            "the previous row when the next version arrives. Content is never "
            "rewritten."
        ),
    )
    screening_outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by_attempt_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        nullable=False,
        doc="The attempt that earned this version. Ties the audit trail across "
        "the persistence security gate.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    __table_args__ = (
        UniqueConstraint("document_id", "version_no", name="uq_document_version_no"),
        UniqueConstraint("document_id", "raw_content_hash", name="uq_document_raw_hash"),
        CheckConstraint("version_no > 0", name="version_no_positive"),
        CheckConstraint(
            "(supersedes_version_id IS NULL) = (version_no = 1)",
            name="supersession_matches_version_no",
        ),
        # QUARANTINED is deliberately absent: a quarantined submission never
        # produces a version, so the state is unrepresentable here (R3 §2).
        CheckConstraint(
            "screening_outcome IN ('CLEAN','FLAGGED')", name="screening_outcome"
        ),
        Index(
            "ix_knowledge_document_version_history",
            "document_id",
            text("version_no DESC"),
        ),
        Index(
            "ix_knowledge_document_version_live",
            "document_id",
            postgresql_where=text("superseded_at IS NULL"),
        ),
    )


class KnowledgeChunk(UUIDPrimaryKeyMixin, Base):
    """One retrievable passage. Immutable, and the anchor for every citation.

    ``document_id`` and ``source_id`` are denormalised deliberately. They are
    retrieval filter predicates, and a filter that requires a join can be
    neither an index predicate nor a cheap count - which measurement showed is
    the difference between correct results and none at all.
    """

    __tablename__ = "knowledge_chunk"

    version_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document_version.id",
            name="fk_knowledge_chunk_version_id_knowledge_document_version",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document.id",
            name="fk_knowledge_chunk_document_id_knowledge_document",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_source.id",
            name="fk_knowledge_chunk_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    char_start: Mapped[int] = mapped_column(Integer, nullable=False)
    char_end: Mapped[int] = mapped_column(Integer, nullable=False)
    token_estimate: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        doc=(
            "Explicitly an estimate (chars/4). Named so a future exact "
            "tokenizer supersedes a known-approximate value rather than "
            "contradicting one that claimed to be exact."
        ),
    )
    heading_path: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text), nullable=True, doc="['3. VLANs', '3.2 Trunking']"
    )
    section_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    page_number: Mapped[int | None] = mapped_column(
        Integer, nullable=True, doc="Reserved for PDF; unused in Milestone 3."
    )
    lexeme: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('english', content)", persisted=True),
        nullable=False,
        doc=(
            "A GENERATED column rather than a trigger: PostgreSQL keeps it "
            "correct by construction and no code path can forget it."
        ),
    )
    flags: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)),
        nullable=False,
        default=list,
        server_default=text("'{}'::varchar[]"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("version_id", "ordinal", name="uq_chunk_version_ordinal"),
        CheckConstraint("char_end > char_start", name="char_range"),
        CheckConstraint("ordinal >= 0", name="ordinal_non_negative"),
        CheckConstraint("length(content) > 0", name="content_not_empty"),
        Index("ix_knowledge_chunk_lexeme", "lexeme", postgresql_using="gin"),
        Index("ix_knowledge_chunk_document", "document_id"),
        Index("ix_knowledge_chunk_source", "source_id"),
        Index("ix_knowledge_chunk_version", "version_id"),
    )


class KnowledgeIngestAttempt(UUIDPrimaryKeyMixin, Base):
    """One submission, successful or not. Append-only, never canonical.

    This table is the R3 §2 correction. A rejected or quarantined submission
    records itself here and creates **no** document, version, chunk or
    embedding. Only after content clears the persistence security gate does the
    same attempt create canonical rows and set ``version_id``.

    The CHECK below is that rule as a database invariant rather than a
    convention the service layer must remember.
    """

    __tablename__ = "knowledge_ingest_attempt"

    source_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_source.id",
            name="fk_knowledge_ingest_attempt_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    external_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    document_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document.id",
            name="fk_knowledge_ingest_attempt_document_id_knowledge_document",
        ),
        nullable=True,
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document_version.id",
            name="fk_kia_version_id_kdv",
        ),
        nullable=True,
    )

    raw_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    text_content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)

    outcome: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=IngestOutcome.PENDING.value,
        server_default=IngestOutcome.PENDING.value,
    )
    requested_by_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    chunk_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    embedded_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    blocking_finding_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "(outcome <> 'PENDING') = (finished_at IS NOT NULL)",
            name="finished_matches_outcome",
        ),
        # The correction, in SQL: only a successful attempt may reference a
        # canonical version, in either direction.
        CheckConstraint(
            "(outcome IN ('CREATED','VERSIONED')) = (version_id IS NOT NULL)",
            name="successful_has_version",
        ),
        Index(
            "ix_knowledge_ingest_attempt_target",
            "source_id",
            "external_ref",
            text("started_at DESC"),
        ),
        Index("ix_knowledge_ingest_attempt_hash", "raw_content_hash"),
        Index(
            "ix_knowledge_ingest_attempt_blocked",
            text("started_at DESC"),
            postgresql_where=text("outcome = 'REJECTED_SECRET'"),
        ),
    )


class KnowledgeFinding(UUIDPrimaryKeyMixin, Base):
    """What a screening detector found. Never what it found.

    ``locator`` stores a position; ``match_fingerprint`` a salted hash. Copying
    a suspected secret into a findings table to explain that a secret was found
    would defeat the control - the same reasoning that keeps fact values out of
    Milestone 2's audit context.
    """

    __tablename__ = "knowledge_finding"

    attempt_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_ingest_attempt.id",
            name="fk_knowledge_finding_attempt_id_knowledge_ingest_attempt",
            ondelete="RESTRICT",
        ),
        nullable=False,
        doc="Findings belong to the attempt that produced them - the only "
        "thing guaranteed to exist when a submission is rejected.",
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_document_version.id",
            name="fk_knowledge_finding_version_id_knowledge_document_version",
        ),
        nullable=True,
        doc="Set only when the attempt succeeded and produced a version.",
    )
    chunk_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_chunk.id", name="fk_knowledge_finding_chunk_id_knowledge_chunk"
        ),
        nullable=True,
    )

    finding_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(32), nullable=False)
    locator: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="'line 412, cols 18-64'. A position, never the matched value.",
    )
    match_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc=(
            "Salted hash of the match, so repeated submissions are "
            "recognisable without this table becoming an offline-crackable "
            "dictionary of the estate's secrets."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("severity IN ('BLOCKING','ADVISORY')", name="severity"),
        Index("ix_knowledge_finding_attempt", "attempt_id"),
        Index("ix_knowledge_finding_fingerprint", "match_fingerprint"),
        Index("ix_knowledge_finding_version", "version_id"),
    )


class KnowledgeFindingDisposition(UUIDPrimaryKeyMixin, Base):
    """An approver's judgement about a detector, scoped to exact content.

    The scope is the whole point. A disposition is keyed to one finding
    fingerprint, on one content hash, for one document target. It is not a
    detector-wide suppression, it does not carry to another document, and it
    cannot carry to edited content - edited content has a different hash.

    Append-only: a mistaken disposition is corrected by a later row, and the
    gate reads the most recent. Note what is absent - no content, no matched
    value, no document body. Only fingerprints and a human's reasoning.
    """

    __tablename__ = "knowledge_finding_disposition"

    source_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_source.id",
            name="fk_knowledge_finding_disposition_source_id_knowledge_source",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    external_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    raw_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    match_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    disposition: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    decided_by_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    origin_attempt_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_ingest_attempt.id",
            name="fk_kfd_origin_attempt_id_kia",
        ),
        nullable=False,
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "disposition IN ('FALSE_POSITIVE','REMEDIATED_AT_SOURCE')",
            name="disposition",
        ),
        Index(
            "ix_knowledge_finding_disposition_scope",
            "source_id",
            "external_ref",
            "raw_content_hash",
            "match_fingerprint",
            text("decided_at DESC"),
        ),
    )


class KnowledgeAssetMention(UUIDPrimaryKeyMixin, Base):
    """A chunk names a CMDB asset. Evidence, never state.

    The foreign key points knowledge to the CMDB and nothing in the Milestone 2
    schema points back. That asymmetry is the boundary: retiring knowledge can
    never orphan or invalidate an authoritative row.

    ``AMBIGUOUS`` is the descendant of Milestone 2's ``IdentityConflictError``.
    A document naming a value that matches two assets records both candidates
    and stays unresolved. Refusing is recoverable; guessing is not.
    """

    __tablename__ = "knowledge_asset_mention"

    chunk_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_chunk.id",
            name="fk_knowledge_asset_mention_chunk_id_knowledge_chunk",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_knowledge_asset_mention_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    mention_text: Mapped[str] = mapped_column(String(255), nullable=False)
    mention_source: Mapped[str] = mapped_column(String(24), nullable=False)
    resolution: Mapped[str] = mapped_column(String(16), nullable=False)
    candidate_asset_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(PostgresUuid(as_uuid=True)),
        nullable=False,
        default=list,
        server_default=text("'{}'::uuid[]"),
    )
    matched_namespace: Mapped[str | None] = mapped_column(String(48), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "(resolution = 'RESOLVED') = (asset_id IS NOT NULL)",
            name="resolution_matches_asset",
        ),
        CheckConstraint(
            "resolution <> 'AMBIGUOUS' OR array_length(candidate_asset_ids, 1) > 1",
            name="ambiguous_has_candidates",
        ),
        CheckConstraint(
            "mention_source IN ('IDENTIFIER_MATCH','EXPLICIT')",
            name="mention_source",
        ),
        Index(
            "ix_knowledge_asset_mention_asset",
            "asset_id",
            postgresql_where=text("asset_id IS NOT NULL"),
        ),
        Index("ix_knowledge_asset_mention_chunk", "chunk_id"),
    )


__all__ = [
    "KnowledgeAssetMention",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "KnowledgeDocumentVersion",
    "KnowledgeFinding",
    "KnowledgeFindingDisposition",
    "KnowledgeIngestAttempt",
    "KnowledgeSource",
    "ScreeningOutcome",
]
