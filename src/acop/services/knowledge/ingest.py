"""Document ingestion: attempt first, canonical state only after the gate.

The ordering in :meth:`KnowledgeIngestService.ingest` is the milestone's most
important invariant, so it is worth stating before the code:

1. An **attempt** row is written first, always, and on its own transaction, so
   that a submission which is about to be refused still leaves a record.
2. Validation, then hashing, then **screening**. Screening completes before a
   single byte of content is written anywhere.
3. Only after the gate passes do parse, chunk, embed and persist run - all in
   the caller's request transaction, so they commit together or not at all.

That separation is the R3 §2 correction. Before it, a quarantined submission
created a ``knowledge_document_version`` with no content; a later
false-positive override would then have had to either mutate that immutable row
or duplicate it past ``uq_document_raw_hash``. Neither was acceptable. Now a
rejected submission creates no canonical row at all, and the *successful*
attempt is the one that earns the version.

Idempotence is a property of canonical state, not of the attempt log. Repeated
identical successful submissions write nothing new and make no embedding call;
repeated rejected submissions append an attempt each time, which is correct -
an attempt is an event, not a resource.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.exceptions import (
    ConflictError,
    NotFoundError,
    SecretRejectedError,
    ValidationError,
)
from acop.core.logging import get_logger
from acop.db import Database
from acop.models.embedding import EmbeddingSpace, embedding_model_for
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
    SUPPORTED_MEDIA_TYPES,
    UNBLOCKING_DISPOSITIONS,
    ChunkFlag,
    Disposition,
    FindingSeverity,
    FindingType,
    IngestOutcome,
    KnowledgeLifecycle,
    ScreeningOutcome,
    TruncationPolicy,
)
from acop.services.knowledge.chunking import (
    CHUNKER_NAME,
    CHUNKER_VERSION,
    PARSER_NAME,
    PARSER_VERSION,
    Chunk,
    ChunkerParams,
    chunk_document,
    normalise,
)
from acop.services.knowledge.embedding_provider import (
    EmbeddingProvider,
    EmbeddingUnavailableError,
)
from acop.services.knowledge.screening import (
    DETECTOR_VERSION,
    MAX_DOCUMENT_BYTES,
    DocumentScreen,
    Finding,
    injection_ranges,
)

logger = get_logger(__name__)


class KnowledgeSecretRejectedError(SecretRejectedError):
    """A submission was refused because it appears to carry secret material.

    Exists to solve a real tension with Milestone 1's error contract. That
    contract deliberately returns only a stable ``code`` and a *class-level*
    generic message, keeping detail in the logs so the API cannot disclose
    internals to a caller. Applied unchanged here it produces a refusal a
    submitter cannot act on: they are told "no" and nothing else, and the
    detector findings are approver-scoped, so they cannot look them up either.

    The resolution is to build the public message **per instance** from
    material that is not sensitive: the detector's name, a line-and-column
    locator into the submitter's *own* document, and the attempt id. None of
    that is secret - the locator points at bytes the submitter already has -
    and the matched value is never included, stored, logged or returned.

    Milestone 1's handler needs no change: it reads ``exc.public_message``, and
    an instance attribute shadows the class one.
    """

    #: Enough for a human to act on; a document with forty identical findings
    #: should not produce a forty-item error body.
    MAX_LISTED: Final[int] = 5

    def __init__(
        self,
        *,
        attempt_id: uuid.UUID,
        findings: tuple[Finding, ...],
        context: dict[str, object] | None = None,
    ) -> None:
        listed = findings[: self.MAX_LISTED]
        located = "; ".join(f"{f.detector} at {f.locator}" for f in listed)
        remainder = len(findings) - len(listed)
        if remainder > 0:
            located += f"; and {remainder} more"
        self.public_message = (
            "Submission refused: the content appears to contain secret "
            f"material. Detected: {located}. The matched values were not "
            f"stored, logged or returned. Attempt {attempt_id} records the "
            "findings for approver review."
        )
        super().__init__(self.public_message, context=context)


class EmbeddingSpaceUnverifiedError(ConflictError):
    """The space's prompt-prefix behaviour has not been observed by a human.

    Per-instance message for the same reason as above: a bare "conflict" tells
    an operator nothing, and what they need to know - which space, and which
    script to run - is not sensitive.
    """

    def __init__(self, space_key: str) -> None:
        self.public_message = (
            f"Embedding space {space_key!r} is unusable: nobody has verified "
            "what the provider does with task prompt prefixes. Run "
            "scripts/probe_embedding_prefixes.py against the provider, then "
            "POST /knowledge/embedding-spaces/{space_id}/verify-prefixes. "
            "Embedding into an unverified space produces a corpus that cannot "
            "be searched correctly, and reports nothing while doing it."
        )
        super().__init__(self.public_message, context={"space_key": space_key})


@dataclass(frozen=True, slots=True)
class IngestRequest:
    source_id: uuid.UUID
    external_ref: str
    title: str
    content: str
    media_type: str = "text/markdown"
    source_modified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IngestResult:
    attempt_id: uuid.UUID
    outcome: IngestOutcome
    document_id: uuid.UUID | None
    version_id: uuid.UUID | None
    version_no: int | None
    chunk_count: int
    embedded_count: int
    advisory_finding_count: int


def _sha256(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


class KnowledgeIngestService:
    """The one write path into canonical knowledge."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        screen: DocumentScreen,
        embedder: EmbeddingProvider,
        database: Database | None = None,
        chunker_params: ChunkerParams | None = None,
    ) -> None:
        self._session = session
        self._screen = screen
        self._embedder = embedder
        self._database = database
        self._chunker_params = chunker_params or ChunkerParams()

    # ------------------------------------------------------------------
    # Attempt bookkeeping
    # ------------------------------------------------------------------
    async def _open_attempt(
        self,
        request: IngestRequest,
        principal: Principal,
        raw_hash: str,
        request_id: str | None,
    ) -> KnowledgeIngestAttempt:
        """Write the attempt on an independent transaction.

        Same mechanism as ``AuditService.record_denial`` and for the same
        reason: everything after this point may be rolled back, and the record
        that a submission happened must survive that.
        """
        fields = principal.to_audit_fields()
        attempt = KnowledgeIngestAttempt(
            id=uuid.uuid4(),
            source_id=request.source_id,
            external_ref=request.external_ref,
            raw_content_hash=raw_hash,
            byte_size=len(request.content.encode("utf-8")),
            media_type=request.media_type,
            outcome=IngestOutcome.PENDING.value,
            requested_by_subject=fields["principal_subject"],
            principal_type=fields["principal_type"],
            principal_issuer=fields["principal_issuer"],
            auth_method=fields["auth_method"],
            request_id=request_id,
            started_at=datetime.now(UTC),
        )
        if self._database is not None:
            async with self._database.session() as session:
                session.add(attempt)
        else:  # pragma: no cover - service-level tests own their session
            self._session.add(attempt)
            await self._session.flush()
        return attempt

    async def _close_attempt(
        self,
        attempt: KnowledgeIngestAttempt,
        outcome: IngestOutcome,
        *,
        document_id: uuid.UUID | None = None,
        version_id: uuid.UUID | None = None,
        text_hash: str | None = None,
        chunk_count: int | None = None,
        embedded_count: int | None = None,
        blocking_findings: int = 0,
        error_code: str | None = None,
        started: float | None = None,
        findings: tuple[Finding, ...] = (),
        in_request_transaction: bool = False,
    ) -> None:
        """Finalise the attempt and its findings.

        Which transaction this uses is not a detail - it is forced by two
        facts pulling in opposite directions:

        * A **failure** rolls the request back, so the attempt's final state
          must be written where that rollback cannot reach it: an independent
          transaction, the same mechanism as ``AuditService.record_denial``.
        * A **success** sets ``version_id``, and that column has a foreign key
          to a version created in the request transaction, which has not
          committed yet. Writing it out-of-band would fail the constraint. It
          must therefore be part of the same transaction as the rows it
          references - which is also what makes the attempt and the canonical
          version atomic with each other.
        """
        values = {
            "outcome": outcome.value,
            "document_id": document_id,
            "version_id": version_id,
            "text_content_hash": text_hash,
            "chunk_count": chunk_count,
            "embedded_count": embedded_count,
            "blocking_finding_count": blocking_findings,
            "error_code": error_code,
            "finished_at": datetime.now(UTC),
            "duration_ms": int((time.monotonic() - started) * 1000) if started else None,
        }
        if self._database is not None and not in_request_transaction:
            async with self._database.session() as session:
                row = await session.get(KnowledgeIngestAttempt, attempt.id)
                if row is not None:
                    for key, value in values.items():
                        setattr(row, key, value)
                for finding in findings:
                    session.add(self._finding_row(attempt.id, finding))
            return

        row = await self._session.get(KnowledgeIngestAttempt, attempt.id)
        target = row if row is not None else attempt
        for key, value in values.items():
            setattr(target, key, value)
        for finding in findings:
            self._session.add(
                self._finding_row(attempt.id, finding, version_id=version_id)
            )
        await self._session.flush()

    @staticmethod
    def _finding_row(
        attempt_id: uuid.UUID, finding: Finding, version_id: uuid.UUID | None = None
    ) -> KnowledgeFinding:
        return KnowledgeFinding(
            id=uuid.uuid4(),
            attempt_id=attempt_id,
            version_id=version_id,
            finding_type=finding.finding_type.value,
            severity=finding.severity.value,
            detector=finding.detector,
            detector_version=finding.detector_version,
            locator=finding.locator,
            match_fingerprint=finding.match_fingerprint,
        )

    # ------------------------------------------------------------------
    # The gate
    # ------------------------------------------------------------------
    async def _cleared_fingerprints(
        self, source_id: uuid.UUID, external_ref: str, raw_hash: str
    ) -> set[str]:
        """Fingerprints an approver has judged false positives, for this content.

        The scope is deliberately narrow: one fingerprint, one content hash,
        one document target. A false-positive judgement about one document does
        not silently apply to another, and it cannot apply to edited content
        because edited content has a different hash.

        Only ``FALSE_POSITIVE`` clears. ``REMEDIATED_AT_SOURCE`` records that a
        real secret was dealt with and can never unblock the original bytes.
        """
        rows = (
            await self._session.execute(
                select(KnowledgeFindingDisposition)
                .where(
                    KnowledgeFindingDisposition.source_id == source_id,
                    KnowledgeFindingDisposition.external_ref == external_ref,
                    KnowledgeFindingDisposition.raw_content_hash == raw_hash,
                )
                .order_by(KnowledgeFindingDisposition.decided_at)
            )
        ).scalars()
        # Later rows win, so a mistaken disposition is corrected by a new one.
        latest: dict[str, str] = {}
        for row in rows:
            latest[row.match_fingerprint] = row.disposition
        return {
            fingerprint
            for fingerprint, disposition in latest.items()
            if Disposition(disposition) in UNBLOCKING_DISPOSITIONS
        }

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------
    async def ingest(
        self,
        request: IngestRequest,
        principal: Principal,
        *,
        space: EmbeddingSpace,
        request_id: str | None = None,
    ) -> IngestResult:
        started = time.monotonic()
        raw_hash = _sha256(request.content)
        attempt = await self._open_attempt(request, principal, raw_hash, request_id)

        source = await self._session.get(KnowledgeSource, request.source_id)
        if source is None:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                error_code="source_not_found",
                started=started,
            )
            raise NotFoundError(f"Knowledge source {request.source_id} does not exist.")
        if source.lifecycle_state != KnowledgeLifecycle.ACTIVE.value:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                error_code="source_retired",
                started=started,
            )
            raise ConflictError("Cannot ingest into a retired source.")

        # -- validate --------------------------------------------------
        if request.media_type not in SUPPORTED_MEDIA_TYPES:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                error_code="unsupported_media_type",
                started=started,
            )
            raise ValidationError(
                f"Milestone 3 ingests {sorted(SUPPORTED_MEDIA_TYPES)} only.",
                context={"media_type": request.media_type},
            )
        if len(request.content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                error_code="document_too_large",
                started=started,
            )
            raise ValidationError(
                f"Document exceeds {MAX_DOCUMENT_BYTES} bytes.",
                context={"byte_size": len(request.content.encode("utf-8"))},
            )

        document = await self._find_document(request)
        current = (
            await self._session.get(KnowledgeDocumentVersion, document.current_version_id)
            if document is not None and document.current_version_id
            else None
        )

        # -- idempotence, before any expensive work --------------------
        if current is not None and current.raw_content_hash == raw_hash:
            await self._close_attempt(
                attempt,
                IngestOutcome.UNCHANGED,
                document_id=document.id if document else None,
                text_hash=current.text_content_hash,
                started=started,
            )
            return IngestResult(
                attempt_id=attempt.id,
                outcome=IngestOutcome.UNCHANGED,
                document_id=document.id if document else None,
                version_id=current.id,
                version_no=current.version_no,
                chunk_count=0,
                embedded_count=0,
                advisory_finding_count=0,
            )

        normalised = normalise(request.content)
        text_hash = _sha256(normalised)
        if current is not None and current.text_content_hash == text_hash:
            # Bytes differ, meaning does not: a CRLF/BOM re-encode.
            await self._close_attempt(
                attempt,
                IngestOutcome.UNCHANGED_TEXT,
                document_id=document.id if document else None,
                text_hash=text_hash,
                started=started,
            )
            return IngestResult(
                attempt_id=attempt.id,
                outcome=IngestOutcome.UNCHANGED_TEXT,
                document_id=document.id if document else None,
                version_id=current.id,
                version_no=current.version_no,
                chunk_count=0,
                embedded_count=0,
                advisory_finding_count=0,
            )

        # ==== PERSISTENCE SECURITY GATE ===============================
        report = self._screen.screen(normalised)
        cleared = await self._cleared_fingerprints(
            request.source_id, request.external_ref, raw_hash
        )
        unresolved = tuple(
            f for f in report.blocking if f.match_fingerprint not in cleared
        )
        if unresolved:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_SECRET,
                text_hash=text_hash,
                blocking_findings=len(unresolved),
                error_code="secret_rejected",
                started=started,
                findings=report.findings,
            )
            # Locators and detectors only. The matched value is never echoed
            # into the error, the audit context, or the logs.
            raise KnowledgeSecretRejectedError(
                attempt_id=attempt.id,
                findings=unresolved,
                context={
                    "attempt_id": str(attempt.id),
                    "blocking_findings": [
                        {
                            "detector": f.detector,
                            "locator": f.locator,
                            "fingerprint": f.match_fingerprint,
                        }
                        for f in unresolved
                    ],
                },
            )
        # ==============================================================

        if not space.prefix_verified_at:
            # Ruling: do not guess prefix behaviour. An unverified space would
            # produce a corpus that cannot be searched correctly, silently.
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                text_hash=text_hash,
                error_code="embedding_prefixes_unverified",
                started=started,
                findings=report.findings,
            )
            raise EmbeddingSpaceUnverifiedError(space.space_key)

        chunks = chunk_document(normalised, self._chunker_params)
        oversize = [
            c
            for c in chunks
            if c.token_estimate + _prefix_tokens(space) > space.max_input_tokens
        ]
        if oversize and space.truncation_policy == TruncationPolicy.REJECT_OVERSIZE.value:
            await self._close_attempt(
                attempt,
                IngestOutcome.REJECTED_INVALID,
                text_hash=text_hash,
                chunk_count=len(chunks),
                error_code="chunk_exceeds_model_input",
                started=started,
                findings=(
                    *report.findings,
                    Finding(
                        finding_type=FindingType.OVERSIZE_INPUT,
                        severity=FindingSeverity.ADVISORY,
                        detector="chunk_size",
                        detector_version=DETECTOR_VERSION,
                        locator=f"chunk ordinal {oversize[0].ordinal}",
                        match_fingerprint=self._screen.fingerprint(
                            f"oversize:{oversize[0].ordinal}"
                        ),
                    ),
                ),
            )
            raise ValidationError(
                "A chunk exceeds the embedding model's input limit and the "
                "space's policy is REJECT_OVERSIZE.",
                context={
                    "max_input_tokens": space.max_input_tokens,
                    "largest_chunk_tokens": max(c.token_estimate for c in oversize),
                },
            )

        try:
            vectors = await self._embedder.embed_documents(
                [c.content for c in chunks], prefix=space.document_prefix
            )
        except EmbeddingUnavailableError:
            await self._close_attempt(
                attempt,
                IngestOutcome.FAILED_EMBEDDING,
                text_hash=text_hash,
                chunk_count=len(chunks),
                error_code="embedding_unavailable",
                started=started,
                findings=report.findings,
            )
            raise

        version, stored_chunks = await self._persist(
            request=request,
            attempt=attempt,
            source=source,
            document=document,
            current=current,
            normalised=normalised,
            raw_hash=raw_hash,
            text_hash=text_hash,
            chunks=chunks,
            vectors=vectors,
            space=space,
            principal=principal,
            advisory=report.advisory,
        )

        outcome = (
            IngestOutcome.CREATED if version.version_no == 1 else IngestOutcome.VERSIONED
        )
        await self._close_attempt(
            attempt,
            outcome,
            document_id=version.document_id,
            version_id=version.id,
            text_hash=text_hash,
            chunk_count=len(stored_chunks),
            embedded_count=len(vectors),
            started=started,
            in_request_transaction=True,
        )
        return IngestResult(
            attempt_id=attempt.id,
            outcome=outcome,
            document_id=version.document_id,
            version_id=version.id,
            version_no=version.version_no,
            chunk_count=len(stored_chunks),
            embedded_count=len(vectors),
            advisory_finding_count=len(report.advisory),
        )

    async def _find_document(self, request: IngestRequest) -> KnowledgeDocument | None:
        return (
            (
                await self._session.execute(
                    select(KnowledgeDocument).where(
                        KnowledgeDocument.source_id == request.source_id,
                        KnowledgeDocument.external_ref == request.external_ref,
                        KnowledgeDocument.lifecycle_state
                        == KnowledgeLifecycle.ACTIVE.value,
                    )
                )
            )
            .scalars()
            .first()
        )

    async def _persist(
        self,
        *,
        request: IngestRequest,
        attempt: KnowledgeIngestAttempt,
        source: KnowledgeSource,
        document: KnowledgeDocument | None,
        current: KnowledgeDocumentVersion | None,
        normalised: str,
        raw_hash: str,
        text_hash: str,
        chunks: list[Chunk],
        vectors: list[list[float]],
        space: EmbeddingSpace,
        principal: Principal,
        advisory: tuple[Finding, ...],
    ) -> tuple[KnowledgeDocumentVersion, list[KnowledgeChunk]]:
        """Write every canonical row, in the caller's transaction."""
        now = datetime.now(UTC)
        if document is None:
            document = KnowledgeDocument(
                id=uuid.uuid4(),
                source_id=request.source_id,
                external_ref=request.external_ref,
                title=request.title,
                media_type=request.media_type,
                lifecycle_state=KnowledgeLifecycle.ACTIVE.value,
            )
            self._session.add(document)
            await self._session.flush()

        version_no = (current.version_no + 1) if current else 1
        version = KnowledgeDocumentVersion(
            id=uuid.uuid4(),
            document_id=document.id,
            version_no=version_no,
            raw_content_hash=raw_hash,
            text_content_hash=text_hash,
            byte_size=len(request.content.encode("utf-8")),
            char_count=len(normalised),
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            chunker_name=CHUNKER_NAME,
            chunker_version=CHUNKER_VERSION,
            chunker_params=self._chunker_params.as_dict(),
            source_modified_at=request.source_modified_at,
            ingested_at=now,
            ingested_by_subject=principal.subject,
            supersedes_version_id=current.id if current else None,
            screening_outcome=(
                ScreeningOutcome.FLAGGED.value
                if advisory
                else ScreeningOutcome.CLEAN.value
            ),
            created_by_attempt_id=attempt.id,
        )
        self._session.add(version)
        await self._session.flush()

        if current is not None:
            # The one permitted write to a historical row: a closure marker.
            # Content is never rewritten.
            current.superseded_at = now
            await self._retire_embeddings_for_version(current.id, space)
        document.current_version_id = version.id
        document.title = request.title

        injections = injection_ranges(normalised)
        embedding_model = embedding_model_for(space.dimensions)
        stored: list[KnowledgeChunk] = []
        # Chunks are inserted and flushed before any embedding, because the
        # embedding table has no ORM relationship to chunk - SQLAlchemy's unit
        # of work therefore cannot infer the dependency and would otherwise
        # order the vector INSERTs first, violating the foreign key.
        for chunk in chunks:
            flags: list[str] = []
            if injections.overlaps(chunk.char_start, chunk.char_end):
                flags.append(ChunkFlag.INJECTION_SUSPECTED.value)
            row = KnowledgeChunk(
                id=uuid.uuid4(),
                version_id=version.id,
                document_id=document.id,
                source_id=source.id,
                ordinal=chunk.ordinal,
                content=chunk.content,
                content_hash=chunk.content_hash,
                char_start=chunk.char_start,
                char_end=chunk.char_end,
                token_estimate=chunk.token_estimate,
                heading_path=list(chunk.heading_path) or None,
                section_label=chunk.section_label,
                flags=flags,
            )
            self._session.add(row)
            stored.append(row)
        await self._session.flush()

        for row, chunk, vector in zip(stored, chunks, vectors, strict=True):
            self._session.add(
                embedding_model(
                    id=uuid.uuid4(),
                    embedding_space_id=space.id,
                    chunk_id=row.id,
                    source_id=source.id,
                    document_id=document.id,
                    embedding=vector,
                    is_current_embedding=True,
                    is_retrievable=True,
                    sensitivity=source.sensitivity,
                    input_token_estimate=chunk.token_estimate,
                    was_truncated=False,
                )
            )
        await self._session.flush()

        for finding in advisory:
            self._session.add(
                self._finding_row(attempt.id, finding, version_id=version.id)
            )
        await self._session.flush()
        return version, stored

    async def _retire_embeddings_for_version(
        self, version_id: uuid.UUID, space: EmbeddingSpace
    ) -> None:
        """Take a superseded version's vectors out of default retrieval.

        Flipping ``is_retrievable`` rather than deleting keeps the vectors for
        history and comparison, and because the flag is in the ANN index
        predicate the exclusion is structural rather than a post-filter.
        """
        model = embedding_model_for(space.dimensions)
        chunk_ids = select(KnowledgeChunk.id).where(
            KnowledgeChunk.version_id == version_id
        )
        rows = (
            await self._session.execute(
                select(model).where(model.chunk_id.in_(chunk_ids))
            )
        ).scalars()
        for row in rows:
            row.is_retrievable = False
        await self._session.flush()


def _prefix_tokens(space: EmbeddingSpace) -> int:
    from acop.services.knowledge.chunking import estimate_tokens

    return estimate_tokens(space.document_prefix) if space.document_prefix else 0


__all__ = [
    "EmbeddingSpaceUnverifiedError",
    "IngestRequest",
    "IngestResult",
    "KnowledgeIngestService",
    "KnowledgeSecretRejectedError",
]
