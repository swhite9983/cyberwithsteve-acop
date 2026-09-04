"""Embedding spaces and vector storage.

**An embedding space is the complete set of conditions under which two stored
vectors are meaningfully comparable.** Dimension is a *storage* property and
nowhere near sufficient: two 768-dimensional models produce numerically
compatible, semantically unrelated vectors. Putting them in one ANN candidate
population is a correctness failure, not a performance one.

The identity tuple is the composite unique constraint on
:class:`EmbeddingSpace`. Change any element - a different model digest, a
different task prefix, a different normalisation choice - and you have a
different space, by construction.

**Physical layout, and why.** pgvector requires a fixed dimension for an
indexable column, so storage is necessarily dimension-typed. Semantic
separation is then achieved by LIST partitioning on ``embedding_space_id``,
with one HNSW index per partition. Three measurements drove this:

* a dimensionless ``vector`` column accepts mixed dimensions but **cannot be
  indexed at all** (``ERROR: column does not have dimensions``);
* a single table with one *partial* HNSW index per space works under a custom
  plan and silently degrades to ``Seq Scan`` under a **generic** plan, because
  PostgreSQL cannot prove ``space_id = $1`` implies the index predicate - and
  SQLAlchemy with asyncpg uses prepared statements, so that is production, not
  theory;
* partitioning survives the generic plan: ``Append -> Subplans Removed: 1 ->
  Index Scan``.

So the partition *is* the space. Cross-space contamination is not a filter that
can fail; it is unrepresentable.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, UUIDPrimaryKeyMixin
from acop.models.knowledge_vocabulary import (
    MAX_INDEXABLE_DIMENSIONS,
    DistanceMetric,
    SpaceLifecycle,
    TruncationPolicy,
)

#: The one dimension family Milestone 3 ships. Adding a family is a migration
#: plus one entry in :data:`EMBEDDING_MODEL_BY_DIMENSIONS`; it changes no
#: public retrieval interface.
D768 = 768


class EmbeddingSpace(UUIDPrimaryKeyMixin, Base):
    """Immutable registry of one comparable vector population.

    Nothing may ``UPDATE`` an identity column of a row here. Changing a model
    means registering a new space, never editing an old one - otherwise every
    vector already stored under that row becomes retroactively mislabelled.
    """

    __tablename__ = "embedding_space"

    space_key: Mapped[str] = mapped_column(
        String(48),
        nullable=False,
        doc="Safe identifier fragment used to name this space's partition.",
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(
        String(128), nullable=False, doc="Exact tag, e.g. 'embeddinggemma:latest'."
    )
    model_digest: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        doc=(
            "Ollama tags are mutable: re-pulling ':latest' can change weights, "
            "producing silently incomparable vectors under an unchanged tag. "
            "This is the identity element most likely to be forgotten and most "
            "damaging when it is."
        ),
    )
    dimensions: Mapped[int] = mapped_column(Integer, nullable=False)
    distance_metric: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=DistanceMetric.COSINE.value,
        server_default=DistanceMetric.COSINE.value,
    )
    normalize_vectors: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        doc="Whether ACOP L2-normalises before storing. Changes what the "
        "metric means, so it is part of identity.",
    )
    document_prefix: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        server_default="",
        doc=(
            "Task prefix applied when embedding a document. Prefix-trained "
            "models place prefixed and unprefixed text in different regions, "
            "so changing this invalidates the corpus with no error - which is "
            "exactly why it is part of space identity."
        ),
    )
    query_prefix: Mapped[str] = mapped_column(
        String(255), nullable=False, server_default=""
    )
    prefix_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc=(
            "When an operator empirically confirmed the provider's prefix "
            "behaviour. NULL means unverified, and the ingestion gate refuses "
            "to persist canonical embeddings into an unverified space."
        ),
    )
    prefix_verified_by_subject: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    max_input_tokens: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        doc="Provider's input ceiling. embeddinggemma reports 2048.",
    )
    truncation_policy: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=TruncationPolicy.REJECT_OVERSIZE.value,
        server_default=TruncationPolicy.REJECT_OVERSIZE.value,
    )
    storage_relation: Mapped[str] = mapped_column(
        String(63), nullable=False, doc="Physical parent, e.g. knowledge_embedding_d768."
    )
    partition_relation: Mapped[str] = mapped_column(
        String(63), nullable=False, doc="This space's physical partition."
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=SpaceLifecycle.ACTIVE.value,
        server_default=SpaceLifecycle.ACTIVE.value,
    )
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("space_key", name="uq_embedding_space_key"),
        # The machine-readable definition of "same space". Change any element
        # and you get a different row, by construction.
        UniqueConstraint(
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
        CheckConstraint(
            f"dimensions BETWEEN 1 AND {MAX_INDEXABLE_DIMENSIONS}",
            name="dimensions_indexable",
        ),
        CheckConstraint("space_key ~ '^[a-z][a-z0-9_]{2,47}$'", name="space_key_format"),
        CheckConstraint(
            "lifecycle_state IN ('ACTIVE','DEPRECATED','RETIRED')",
            name="lifecycle_state",
        ),
        # Exactly one default space.
        Index(
            "uq_embedding_space_default",
            "is_default",
            unique=True,
            postgresql_where=text("is_default"),
        ),
    )


class KnowledgeEmbeddingD768(Base):
    """Vectors for the 768-dimension family, partitioned by embedding space.

    The primary key includes ``embedding_space_id`` because PostgreSQL requires
    the partition key to be part of any unique constraint on a partitioned
    table.

    Two independent booleans, because they answer different questions:

    * ``is_current_embedding`` - is this the live vector for this chunk in this
      space? Re-embedding inserts new rows and flips old ones false, which is
      what makes re-embedding non-destructive.
    * ``is_retrievable`` - does this chunk take part in *default* retrieval?
      False once its version is superseded or its document or source retired.

    Both appear in the per-partition HNSW index predicate, so lifecycle
    filtering is structural rather than a post-filter. ``sensitivity``,
    ``source_id`` and ``document_id`` are denormalised for the same reason a
    join cannot be an index predicate - but they stay *out* of the ANN index so
    that authorization policy is never welded into storage.
    """

    __tablename__ = "knowledge_embedding_d768"

    id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    embedding_space_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "embedding_space.id",
            name="fk_knowledge_embedding_d768_embedding_space_id_embedding_space",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    chunk_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "knowledge_chunk.id",
            name="fk_knowledge_embedding_d768_chunk_id_knowledge_chunk",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True), nullable=False
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True), nullable=False
    )
    embedding: Mapped[list[float]] = mapped_column(Vector(D768), nullable=False)
    is_current_embedding: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    is_retrievable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    sensitivity: Mapped[str] = mapped_column(String(16), nullable=False)
    input_token_estimate: Mapped[int] = mapped_column(Integer, nullable=False)
    was_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index(
            "uq_ke_d768_current",
            "chunk_id",
            "embedding_space_id",
            unique=True,
            postgresql_where=text("is_current_embedding"),
        ),
        {"postgresql_partition_by": "LIST (embedding_space_id)"},
    )


#: Dimension family to ORM class. A **static, code-level** map: the physical
#: relation for a space is chosen from this, never from a string read out of
#: the database, so no database value can ever reach SQL as an identifier.
EMBEDDING_MODEL_BY_DIMENSIONS: dict[int, type[KnowledgeEmbeddingD768]] = {
    D768: KnowledgeEmbeddingD768,
}


def embedding_model_for(dimensions: int) -> type[KnowledgeEmbeddingD768]:
    """The ORM class storing vectors of ``dimensions``.

    Raises:
        KeyError: No storage family exists for that dimension. Adding one is a
            migration plus an entry above - and changes no public interface.
    """
    try:
        return EMBEDDING_MODEL_BY_DIMENSIONS[dimensions]
    except KeyError as exc:  # pragma: no cover - guarded at registration
        raise KeyError(
            f"No embedding storage family for {dimensions} dimensions. "
            "Add a knowledge_embedding_d<N> table by migration and register it "
            "in EMBEDDING_MODEL_BY_DIMENSIONS."
        ) from exc


__all__ = [
    "D768",
    "EMBEDDING_MODEL_BY_DIMENSIONS",
    "EmbeddingSpace",
    "KnowledgeEmbeddingD768",
    "embedding_model_for",
]
