"""Embedding-space registration and the partitions that store their vectors.

Registration is an **admin** action, not a migration, for one reason: a space
cannot honestly be registered until someone has verified what the provider does
with task prefixes, and a migration cannot verify anything. So the migration
creates the partitioned parent and this service creates a partition per space.

That is also why ``migrations/env.py`` filters partitions out of autogenerate -
they are runtime objects, and without the filter every ``alembic check`` after
the first registration would report them as tables to drop.

**Identifier safety.** Partition and index names are built from ``space_key``,
which is validated three times over: a CHECK constraint on the column, a regex
in :func:`acop.models.knowledge_vocabulary.partition_relation`, and again here
before any DDL is emitted. No value read from the database reaches SQL as an
identifier without passing all three.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.exceptions import ConflictError, NotFoundError, ValidationError
from acop.core.logging import get_logger
from acop.models.embedding import EmbeddingSpace, embedding_model_for
from acop.models.knowledge_vocabulary import (
    DISTANCE_OPS_CLASS,
    MAX_INDEXABLE_DIMENSIONS,
    SPACE_KEY_PATTERN,
    DistanceMetric,
    SpaceLifecycle,
    TruncationPolicy,
    parent_relation,
    partition_relation,
)

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SpaceRegistration:
    """Everything that makes a space a distinct semantic population."""

    space_key: str
    provider: str
    model: str
    dimensions: int
    model_digest: str | None = None
    distance_metric: DistanceMetric = DistanceMetric.COSINE
    normalize_vectors: bool = True
    document_prefix: str = ""
    query_prefix: str = ""
    max_input_tokens: int = 2048
    truncation_policy: TruncationPolicy = TruncationPolicy.REJECT_OVERSIZE
    make_default: bool = False


class EmbeddingSpaceService:
    """Registers spaces and creates their physical partitions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def default_space(self) -> EmbeddingSpace:
        space = (
            (
                await self._session.execute(
                    select(EmbeddingSpace).where(EmbeddingSpace.is_default)
                )
            )
            .scalars()
            .first()
        )
        if space is None:
            raise NotFoundError(
                "No default embedding space is registered. Register one with "
                "scripts/register_embedding_space.py after verifying the "
                "provider's prompt-prefix behaviour."
            )
        return space

    async def get(self, space_id: uuid.UUID) -> EmbeddingSpace:
        space = await self._session.get(EmbeddingSpace, space_id)
        if space is None:
            raise NotFoundError(f"Embedding space {space_id} does not exist.")
        return space

    async def by_key(self, space_key: str) -> EmbeddingSpace | None:
        return (
            (
                await self._session.execute(
                    select(EmbeddingSpace).where(EmbeddingSpace.space_key == space_key)
                )
            )
            .scalars()
            .first()
        )

    async def list_spaces(self) -> list[EmbeddingSpace]:
        return list(
            (
                await self._session.execute(
                    select(EmbeddingSpace).order_by(EmbeddingSpace.created_at)
                )
            ).scalars()
        )

    async def register(self, registration: SpaceRegistration) -> EmbeddingSpace:
        """Create a space and its partition.

        Raises:
            ValidationError: The key or dimension is unusable.
            ConflictError: A space with this key already exists.
        """
        if not SPACE_KEY_PATTERN.match(registration.space_key):
            raise ValidationError(
                "Embedding space key must match ^[a-z][a-z0-9_]{2,47}$.",
                context={"space_key": registration.space_key},
            )
        if not 1 <= registration.dimensions <= MAX_INDEXABLE_DIMENSIONS:
            # Measured: above 2000, the column is legal but cannot carry an
            # HNSW index, so every search would silently become a scan.
            raise ValidationError(
                f"Dimensions must be between 1 and {MAX_INDEXABLE_DIMENSIONS} "
                "to be indexable by HNSW.",
                context={"dimensions": registration.dimensions},
            )
        # Raises if no storage family exists - a deliberate, loud failure
        # rather than creating a table nothing can query.
        embedding_model_for(registration.dimensions)

        if await self.by_key(registration.space_key) is not None:
            raise ConflictError(
                f"Embedding space {registration.space_key!r} already exists.",
                context={"space_key": registration.space_key},
            )

        parent = parent_relation(registration.dimensions)
        partition = partition_relation(registration.dimensions, registration.space_key)

        space = EmbeddingSpace(
            id=uuid.uuid4(),
            space_key=registration.space_key,
            provider=registration.provider,
            model=registration.model,
            model_digest=registration.model_digest,
            dimensions=registration.dimensions,
            distance_metric=registration.distance_metric.value,
            normalize_vectors=registration.normalize_vectors,
            document_prefix=registration.document_prefix,
            query_prefix=registration.query_prefix,
            max_input_tokens=registration.max_input_tokens,
            truncation_policy=registration.truncation_policy.value,
            storage_relation=parent,
            partition_relation=partition,
            lifecycle_state=SpaceLifecycle.ACTIVE.value,
            is_default=False,
        )
        self._session.add(space)
        await self._session.flush()

        await self._create_partition(space)

        if registration.make_default:
            await self.set_default(space.id)
        logger.info(
            "knowledge.embedding_space.registered",
            space_key=space.space_key,
            provider=space.provider,
            model=space.model,
            dimensions=space.dimensions,
            partition=partition,
        )
        return space

    async def _create_partition(self, space: EmbeddingSpace) -> None:
        """Create the partition and its two indexes.

        The ANN index predicate carries only *lifecycle* columns. Sensitivity
        is deliberately absent: baking authorization policy into an index would
        weld storage to today's role map, and the policy has to stay
        replaceable. Sensitivity is filtered in the query instead, with the
        eligible-set index below making that affordable.
        """
        partition = partition_relation(space.dimensions, space.space_key)
        parent = parent_relation(space.dimensions)
        ops = DISTANCE_OPS_CLASS[DistanceMetric(space.distance_metric)]
        ann_index = f"ix_{partition[:52]}_ann"
        eligible_index = f"ix_{partition[:47]}_eligible"

        # DDL cannot take bind parameters, so the space id is interpolated.
        # That is safe here and only here: ``space.id`` is a ``uuid.UUID``
        # object, and re-formatting it through ``uuid.UUID(...)`` guarantees it
        # is 36 hex-and-dash characters with no SQL metacharacter possible.
        space_literal = str(uuid.UUID(str(space.id)))
        await self._session.execute(
            text(
                f'CREATE TABLE IF NOT EXISTS "{partition}" '
                f"PARTITION OF \"{parent}\" FOR VALUES IN ('{space_literal}')"
            )
        )
        await self._session.execute(
            text(
                f'CREATE INDEX IF NOT EXISTS "{ann_index}" ON "{partition}" '
                f"USING hnsw (embedding {ops}) "
                "WHERE is_current_embedding AND is_retrievable"
            )
        )
        # Supports both the stage-2 eligible count and the stage-3 exact
        # fallback's filter, without touching the ANN index.
        await self._session.execute(
            text(
                f'CREATE INDEX IF NOT EXISTS "{eligible_index}" ON "{partition}" '
                "(sensitivity, source_id, document_id) INCLUDE (chunk_id) "
                "WHERE is_current_embedding AND is_retrievable"
            )
        )

    async def set_default(self, space_id: uuid.UUID) -> EmbeddingSpace:
        """Make one space the default, atomically."""
        space = await self.get(space_id)
        await self._session.execute(
            text("UPDATE embedding_space SET is_default = false WHERE is_default")
        )
        space.is_default = True
        await self._session.flush()
        return space

    async def resync_source_sensitivity(self, source_id: uuid.UUID) -> int:
        """Push a source's sensitivity down onto its stored vectors.

        The vector rows carry a denormalised ``sensitivity`` so the
        per-partition eligible index can serve the exact-fallback filter; the
        authoritative value lives on ``knowledge_source``. Retrieval requires
        **both** to permit a row, which fails closed if they diverge - but a
        divergence still hides content that a principal is entitled to read, so
        it must be repaired rather than tolerated.

        This is the repair, and it is the only sanctioned writer of that column
        after ingest. Reclassifying a source must call it in the same
        transaction as the source update, so the two can never be observed
        apart.

        Returns:
            The number of vector rows updated, across every registered space.
        """
        from acop.models.knowledge import KnowledgeChunk, KnowledgeSource

        source = await self._session.get(KnowledgeSource, source_id)
        if source is None:
            raise NotFoundError(f"Knowledge source {source_id} does not exist.")

        updated = 0
        for dimensions in {space.dimensions for space in await self.list_spaces()}:
            model = embedding_model_for(dimensions)
            chunk_ids = select(KnowledgeChunk.id).where(
                KnowledgeChunk.source_id == source_id
            )
            rows = (
                await self._session.execute(
                    select(model).where(
                        model.chunk_id.in_(chunk_ids),
                        model.sensitivity != source.sensitivity,
                    )
                )
            ).scalars()
            for row in rows:
                row.sensitivity = source.sensitivity
                updated += 1
        await self._session.flush()
        if updated:
            logger.info(
                "knowledge.embedding.sensitivity_resynced",
                source_id=str(source_id),
                sensitivity=source.sensitivity,
                rows=updated,
            )
        return updated

    async def mark_prefixes_verified(
        self, space_id: uuid.UUID, subject: str
    ) -> EmbeddingSpace:
        """Record that a human confirmed the provider's prefix behaviour.

        This is the gate the ingestion service checks. It is a deliberate,
        attributed act rather than a default, because an unverified prefix
        silently produces a corpus that cannot be searched correctly and
        nothing anywhere would report it.
        """
        space = await self.get(space_id)
        from datetime import UTC, datetime

        space.prefix_verified_at = datetime.now(UTC)
        space.prefix_verified_by_subject = subject
        await self._session.flush()
        logger.info(
            "knowledge.embedding_space.prefix_verified",
            space_key=space.space_key,
            subject=subject,
        )
        return space


__all__ = ["EmbeddingSpaceService", "SpaceRegistration"]
