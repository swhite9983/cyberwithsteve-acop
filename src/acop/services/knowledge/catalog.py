"""Sources, documents, attempts and dispositions: the read and lifecycle side.

Ingestion lives in :mod:`acop.services.knowledge.ingest` because it is the one
write path into canonical content and deserves to be readable on its own. This
module is everything else the API needs - registering a source, listing what has
been ingested, retiring material, and recording an approver's judgement about a
finding.

**Retirement, not deletion.** Nothing here deletes. A retired source or document
stops being retrieved by default and its vectors are taken out of the ANN
population, but the versions, chunks and citations that referenced it remain
addressable. An answer given last month cited something; deleting it would make
that answer unverifiable, which is the opposite of what an audit trail is for.

**Reclassification propagates.** Sensitivity lives authoritatively on the source
and is denormalised onto every stored vector so the per-partition eligible index
can serve the exact fallback. Retrieval requires both to agree, so a
reclassification that updated only one would silently hide material a principal
is entitled to read. The resync happens in the same transaction, here, rather
than being left to a maintenance job nobody runs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal, Role
from acop.core.exceptions import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from acop.core.logging import get_logger
from acop.models.embedding import embedding_model_for
from acop.models.knowledge import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeDocumentVersion,
    KnowledgeFinding,
    KnowledgeFindingDisposition,
    KnowledgeIngestAttempt,
    KnowledgeSource,
)
from acop.models.knowledge_vocabulary import (
    APPROVER_ONLY_TRUST,
    Disposition,
    KnowledgeLifecycle,
    Sensitivity,
    SourceKind,
    TrustClass,
)
from acop.services.knowledge.spaces import EmbeddingSpaceService

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SourceRegistration:
    source_kind: SourceKind
    title: str
    origin: str
    trust_class: TrustClass
    sensitivity: Sensitivity
    uri: str | None = None
    owner_subject: str | None = None
    metadata: dict[str, Any] | None = None


class KnowledgeCatalogService:
    """Everything about knowledge that is not the ingest write path."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # -- sources --------------------------------------------------------

    async def create_source(
        self, registration: SourceRegistration, principal: Principal
    ) -> KnowledgeSource:
        """Register a source.

        Raises:
            AuthorizationError: The caller tried to assign a trust class only an
                approver may grant. Declaring material "this is our policy" is
                an approval act, not an editorial one, and letting an operator
                do it would make the trust vocabulary self-service.
        """
        self._guard_trust(registration.trust_class, principal)
        source = KnowledgeSource(
            id=uuid.uuid4(),
            source_kind=registration.source_kind.value,
            title=registration.title,
            uri=registration.uri,
            origin=registration.origin,
            owner_subject=registration.owner_subject,
            trust_class=registration.trust_class.value,
            sensitivity=registration.sensitivity.value,
            lifecycle_state=KnowledgeLifecycle.ACTIVE.value,
            source_metadata=registration.metadata or {},
        )
        self._session.add(source)
        await self._session.flush()
        logger.info(
            "knowledge.source.created",
            source_id=str(source.id),
            trust_class=source.trust_class,
            sensitivity=source.sensitivity,
            subject=principal.subject,
        )
        return source

    async def get_source(self, source_id: uuid.UUID) -> KnowledgeSource:
        source = await self._session.get(KnowledgeSource, source_id)
        if source is None:
            raise NotFoundError(f"Knowledge source {source_id} does not exist.")
        return source

    async def list_sources(
        self,
        *,
        source_kind: str | None = None,
        include_retired: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeSource]:
        statement: Select[Any] = select(KnowledgeSource)
        if source_kind:
            statement = statement.where(KnowledgeSource.source_kind == source_kind)
        if not include_retired:
            statement = statement.where(
                KnowledgeSource.lifecycle_state == KnowledgeLifecycle.ACTIVE.value
            )
        statement = (
            statement.order_by(KnowledgeSource.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(statement)).scalars())

    async def reclassify_source(
        self,
        source_id: uuid.UUID,
        principal: Principal,
        *,
        trust_class: TrustClass | None = None,
        sensitivity: Sensitivity | None = None,
    ) -> tuple[KnowledgeSource, int]:
        """Change a source's trust or classification, and propagate the change.

        Returns:
            The source and the number of vector rows whose denormalised
            sensitivity was repaired - reported rather than swallowed so a
            caller can see that the propagation actually happened.
        """
        if trust_class is None and sensitivity is None:
            raise ValidationError("Reclassification must change something.")
        source = await self.get_source(source_id)
        if trust_class is not None:
            self._guard_trust(trust_class, principal)
            source.trust_class = trust_class.value
        resynced = 0
        if sensitivity is not None and source.sensitivity != sensitivity.value:
            source.sensitivity = sensitivity.value
            await self._session.flush()
            resynced = await EmbeddingSpaceService(
                self._session
            ).resync_source_sensitivity(source_id)
        await self._session.flush()
        logger.info(
            "knowledge.source.reclassified",
            source_id=str(source_id),
            trust_class=source.trust_class,
            sensitivity=source.sensitivity,
            vectors_resynced=resynced,
            subject=principal.subject,
        )
        return source, resynced

    async def retire_source(
        self, source_id: uuid.UUID, principal: Principal
    ) -> KnowledgeSource:
        """Retire a source and take its vectors out of default retrieval."""
        source = await self.get_source(source_id)
        if source.lifecycle_state == KnowledgeLifecycle.RETIRED.value:
            raise ConflictError(f"Knowledge source {source_id} is already retired.")
        now = datetime.now(UTC)
        source.lifecycle_state = KnowledgeLifecycle.RETIRED.value
        source.retired_at = now
        source.retired_by_subject = principal.subject
        await self._session.flush()
        retired = await self._retire_vectors(KnowledgeChunk.source_id == source_id)
        logger.info(
            "knowledge.source.retired",
            source_id=str(source_id),
            vectors_retired=retired,
            subject=principal.subject,
        )
        return source

    # -- documents ------------------------------------------------------

    async def get_document(self, document_id: uuid.UUID) -> KnowledgeDocument:
        document = await self._session.get(KnowledgeDocument, document_id)
        if document is None:
            raise NotFoundError(f"Knowledge document {document_id} does not exist.")
        return document

    async def list_documents(
        self,
        *,
        source_id: uuid.UUID | None = None,
        include_retired: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeDocument]:
        statement: Select[Any] = select(KnowledgeDocument)
        if source_id:
            statement = statement.where(KnowledgeDocument.source_id == source_id)
        if not include_retired:
            statement = statement.where(
                KnowledgeDocument.lifecycle_state == KnowledgeLifecycle.ACTIVE.value
            )
        statement = (
            statement.order_by(KnowledgeDocument.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(statement)).scalars())

    async def list_versions(
        self, document_id: uuid.UUID
    ) -> list[KnowledgeDocumentVersion]:
        """Every version, newest first. History is never pruned."""
        await self.get_document(document_id)
        return list(
            (
                await self._session.execute(
                    select(KnowledgeDocumentVersion)
                    .where(KnowledgeDocumentVersion.document_id == document_id)
                    .order_by(KnowledgeDocumentVersion.version_no.desc())
                )
            ).scalars()
        )

    async def list_chunks(self, version_id: uuid.UUID) -> list[KnowledgeChunk]:
        chunks = list(
            (
                await self._session.execute(
                    select(KnowledgeChunk)
                    .where(KnowledgeChunk.version_id == version_id)
                    .order_by(KnowledgeChunk.ordinal)
                )
            ).scalars()
        )
        if not chunks:
            raise NotFoundError(f"Document version {version_id} has no chunks.")
        return chunks

    async def retire_document(
        self, document_id: uuid.UUID, principal: Principal
    ) -> KnowledgeDocument:
        document = await self.get_document(document_id)
        if document.lifecycle_state == KnowledgeLifecycle.RETIRED.value:
            raise ConflictError(f"Knowledge document {document_id} is already retired.")
        document.lifecycle_state = KnowledgeLifecycle.RETIRED.value
        document.retired_at = datetime.now(UTC)
        document.retired_by_subject = principal.subject
        await self._session.flush()
        retired = await self._retire_vectors(KnowledgeChunk.document_id == document_id)
        logger.info(
            "knowledge.document.retired",
            document_id=str(document_id),
            vectors_retired=retired,
            subject=principal.subject,
        )
        return document

    # -- attempts, findings, dispositions -------------------------------

    async def list_attempts(
        self,
        *,
        source_id: uuid.UUID | None = None,
        external_ref: str | None = None,
        outcome: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeIngestAttempt]:
        statement: Select[Any] = select(KnowledgeIngestAttempt)
        if source_id:
            statement = statement.where(KnowledgeIngestAttempt.source_id == source_id)
        if external_ref:
            statement = statement.where(
                KnowledgeIngestAttempt.external_ref == external_ref
            )
        if outcome:
            statement = statement.where(KnowledgeIngestAttempt.outcome == outcome)
        statement = (
            statement.order_by(KnowledgeIngestAttempt.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(statement)).scalars())

    async def get_attempt(
        self, attempt_id: uuid.UUID
    ) -> tuple[KnowledgeIngestAttempt, list[KnowledgeFinding]]:
        attempt = await self._session.get(KnowledgeIngestAttempt, attempt_id)
        if attempt is None:
            raise NotFoundError(f"Ingest attempt {attempt_id} does not exist.")
        findings = list(
            (
                await self._session.execute(
                    select(KnowledgeFinding)
                    .where(KnowledgeFinding.attempt_id == attempt_id)
                    .order_by(KnowledgeFinding.created_at)
                )
            ).scalars()
        )
        return attempt, findings

    async def record_disposition(
        self,
        finding_id: uuid.UUID,
        principal: Principal,
        *,
        disposition: Disposition,
        reason: str,
    ) -> KnowledgeFindingDisposition:
        """Record an approver's judgement, scoped to exactly what was reviewed.

        The scope is copied from the finding's own attempt: this source, this
        external ref, this raw content hash, this fingerprint. That is what
        makes a ``FALSE_POSITIVE`` mean "these bytes, reviewed by a named
        person" rather than "suppress this detector from now on".

        The originating attempt is **not** mutated. It is an immutable record of
        what happened at the time, and a later judgement is a later row - which
        is also what lets a mistaken disposition be corrected by another one
        without rewriting history.
        """
        finding = await self._session.get(KnowledgeFinding, finding_id)
        if finding is None:
            raise NotFoundError(f"Knowledge finding {finding_id} does not exist.")
        attempt = await self._session.get(KnowledgeIngestAttempt, finding.attempt_id)
        if attempt is None:  # pragma: no cover - foreign key guarantees this
            raise NotFoundError(f"Ingest attempt {finding.attempt_id} does not exist.")

        row = KnowledgeFindingDisposition(
            id=uuid.uuid4(),
            source_id=attempt.source_id,
            external_ref=attempt.external_ref,
            raw_content_hash=attempt.raw_content_hash,
            match_fingerprint=finding.match_fingerprint,
            detector=finding.detector,
            disposition=disposition.value,
            reason=reason,
            decided_by_subject=principal.subject,
            origin_attempt_id=attempt.id,
        )
        self._session.add(row)
        await self._session.flush()
        logger.info(
            "knowledge.finding.disposed",
            finding_id=str(finding_id),
            attempt_id=str(attempt.id),
            disposition=disposition.value,
            subject=principal.subject,
        )
        return row

    # -- internals ------------------------------------------------------

    def _guard_trust(self, trust_class: TrustClass, principal: Principal) -> None:
        if trust_class in APPROVER_ONLY_TRUST and not principal.has_any_role(
            Role.APPROVER, Role.ADMIN
        ):
            raise AuthorizationError(
                f"Trust class {trust_class.value} may only be assigned by an approver.",
                context={"trust_class": trust_class.value},
            )

    async def _retire_vectors(self, chunk_predicate: Any) -> int:
        """Take vectors out of default retrieval without destroying them.

        ``is_retrievable`` is in each partition's HNSW index predicate, so
        flipping it removes the rows from the ANN population structurally
        rather than as a post-filter - and keeps them for history, which
        deletion would not.
        """
        spaces = await EmbeddingSpaceService(self._session).list_spaces()
        retired = 0
        for dimensions in {space.dimensions for space in spaces}:
            model = embedding_model_for(dimensions)
            chunk_ids = select(KnowledgeChunk.id).where(chunk_predicate)
            rows = (
                await self._session.execute(
                    select(model).where(
                        model.chunk_id.in_(chunk_ids),
                        model.is_retrievable.is_(True),
                    )
                )
            ).scalars()
            for row in rows:
                row.is_retrievable = False
                retired += 1
        await self._session.flush()
        return retired


__all__ = ["KnowledgeCatalogService", "SourceRegistration"]
