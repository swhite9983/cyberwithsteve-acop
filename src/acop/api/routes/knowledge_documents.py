"""Document ingestion, version history, attempts, findings and dispositions.

The ingest endpoint is the only write path into canonical knowledge content, and
its behaviour on refusal is the part worth reading: a rejected submission leaves
an attempt row and no document, version, chunk or embedding at all. The error it
returns names detectors and line positions and never the matched value.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from acop.api.deps import (
    ApproverPrincipal,
    OperatorPrincipal,
    ViewerPrincipal,
    get_audit_service,
    get_embedding_space_service,
    get_knowledge_catalog_service,
    get_knowledge_ingest_service,
)
from acop.api.transaction import TransactionalRoute
from acop.models.audit import AuditOutcome
from acop.models.knowledge_vocabulary import IngestOutcome
from acop.schemas.audit import AuditEventCreate
from acop.schemas.knowledge import (
    AttemptDetail,
    AttemptRead,
    ChunkRead,
    DispositionCreate,
    DispositionRead,
    DocumentIngest,
    DocumentRead,
    FindingRead,
    IngestResultRead,
    VersionRead,
)
from acop.services import AuditService
from acop.services.knowledge import (
    EmbeddingSpaceService,
    IngestRequest,
    KnowledgeCatalogService,
    KnowledgeIngestService,
)

router = APIRouter(
    prefix="/knowledge", tags=["knowledge-documents"], route_class=TransactionalRoute
)

CatalogDep = Annotated[KnowledgeCatalogService, Depends(get_knowledge_catalog_service)]
IngestDep = Annotated[KnowledgeIngestService, Depends(get_knowledge_ingest_service)]
SpacesDep = Annotated[EmbeddingSpaceService, Depends(get_embedding_space_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


@router.post(
    "/documents",
    response_model=IngestResultRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a document",
)
async def ingest_document(
    request: Request,
    payload: DocumentIngest,
    principal: OperatorPrincipal,
    ingest: IngestDep,
    spaces: SpacesDep,
    audit: AuditDep,
) -> IngestResultRead:
    """Submit content for screening, chunking, embedding and storage.

    Resubmitting identical content is a no-op that makes no embedding call and
    writes no new version - idempotence is a property of canonical state, not of
    the attempt log, so the attempt is still recorded.
    """
    space = (
        await spaces.get(payload.embedding_space_id)
        if payload.embedding_space_id
        else await spaces.default_space()
    )
    result = await ingest.ingest(
        IngestRequest(
            source_id=payload.source_id,
            external_ref=payload.external_ref,
            title=payload.title,
            content=payload.content,
            media_type=payload.media_type,
            source_modified_at=payload.source_modified_at,
        ),
        principal,
        space=space,
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.document.ingest",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.document",
            resource_id=str(result.document_id) if result.document_id else None,
            context={
                # Deliberately no content, no title text beyond the reference,
                # and no finding values.
                "attempt_id": str(result.attempt_id),
                "outcome": result.outcome.value,
                "version_no": result.version_no,
                "chunk_count": result.chunk_count,
                "embedded_count": result.embedded_count,
                "advisory_findings": result.advisory_finding_count,
                "embedding_space_id": str(space.id),
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return IngestResultRead(
        attempt_id=result.attempt_id,
        outcome=result.outcome,
        document_id=result.document_id,
        version_id=result.version_id,
        version_no=result.version_no,
        chunk_count=result.chunk_count,
        embedded_count=result.embedded_count,
        advisory_finding_count=result.advisory_finding_count,
    )


@router.get("/documents", response_model=list[DocumentRead], summary="List documents")
async def list_documents(
    principal: ViewerPrincipal,
    catalog: CatalogDep,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    include_retired: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[DocumentRead]:
    del principal
    rows = await catalog.list_documents(
        source_id=source_id,
        include_retired=include_retired,
        limit=limit,
        offset=offset,
    )
    return [DocumentRead.model_validate(row) for row in rows]


@router.get(
    "/documents/{document_id}", response_model=DocumentRead, summary="Read a document"
)
async def read_document(
    document_id: uuid.UUID, principal: ViewerPrincipal, catalog: CatalogDep
) -> DocumentRead:
    del principal
    return DocumentRead.model_validate(await catalog.get_document(document_id))


@router.get(
    "/documents/{document_id}/versions",
    response_model=list[VersionRead],
    summary="List a document's versions",
)
async def list_versions(
    document_id: uuid.UUID, principal: ViewerPrincipal, catalog: CatalogDep
) -> list[VersionRead]:
    """Every version ever ingested, newest first.

    History is never pruned, so a citation written against version 1 still
    resolves after version 7 exists.
    """
    del principal
    rows = await catalog.list_versions(document_id)
    return [VersionRead.model_validate(row) for row in rows]


@router.get(
    "/versions/{version_id}/chunks",
    response_model=list[ChunkRead],
    summary="List a version's chunks",
)
async def list_chunks(
    version_id: uuid.UUID, principal: ViewerPrincipal, catalog: CatalogDep
) -> list[ChunkRead]:
    del principal
    rows = await catalog.list_chunks(version_id)
    return [ChunkRead.model_validate(row) for row in rows]


@router.post(
    "/documents/{document_id}/retire",
    response_model=DocumentRead,
    summary="Retire a document",
)
async def retire_document(
    request: Request,
    document_id: uuid.UUID,
    principal: ApproverPrincipal,
    catalog: CatalogDep,
    audit: AuditDep,
) -> DocumentRead:
    document = await catalog.retire_document(document_id, principal)
    await audit.record(
        AuditEventCreate(
            action="knowledge.document.retire",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.document",
            resource_id=str(document_id),
            context={"lifecycle_state": document.lifecycle_state},
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return DocumentRead.model_validate(document)


@router.get("/attempts", response_model=list[AttemptRead], summary="List ingest attempts")
async def list_attempts(
    principal: ApproverPrincipal,
    catalog: CatalogDep,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    external_ref: Annotated[str | None, Query(max_length=1024)] = None,
    outcome: Annotated[IngestOutcome | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AttemptRead]:
    """The submission log, including everything that was refused.

    Approver-scoped: the list of what was blocked, by which detector and where,
    is a security review surface rather than general reading.
    """
    del principal
    rows = await catalog.list_attempts(
        source_id=source_id,
        external_ref=external_ref,
        outcome=str(outcome) if outcome else None,
        limit=limit,
        offset=offset,
    )
    return [AttemptRead.model_validate(row) for row in rows]


@router.get(
    "/attempts/{attempt_id}",
    response_model=AttemptDetail,
    summary="Read one attempt and its findings",
)
async def read_attempt(
    attempt_id: uuid.UUID, principal: ApproverPrincipal, catalog: CatalogDep
) -> AttemptDetail:
    del principal
    attempt, findings = await catalog.get_attempt(attempt_id)
    return AttemptDetail(
        attempt=AttemptRead.model_validate(attempt),
        findings=[FindingRead.model_validate(f) for f in findings],
    )


@router.post(
    "/findings/{finding_id}/dispositions",
    response_model=DispositionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record an approver's judgement about a finding",
)
async def record_disposition(
    request: Request,
    finding_id: uuid.UUID,
    payload: DispositionCreate,
    principal: ApproverPrincipal,
    catalog: CatalogDep,
    audit: AuditDep,
) -> DispositionRead:
    """Dispose of a finding, scoped to exactly the bytes that were reviewed.

    ``FALSE_POSITIVE`` clears that fingerprint for that source, that reference
    and that content hash - nothing wider. ``REMEDIATED_AT_SOURCE`` records that
    a real secret was dealt with and deliberately does **not** unblock the
    original content: the submitter has to edit their document, and edited
    content has a different hash.
    """
    row = await catalog.record_disposition(
        finding_id,
        principal,
        disposition=payload.disposition,
        reason=payload.reason,
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.finding.dispose",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.finding",
            resource_id=str(finding_id),
            context={
                "disposition": row.disposition,
                "detector": row.detector,
                "origin_attempt_id": str(row.origin_attempt_id),
                # The fingerprint, never the value.
                "match_fingerprint": row.match_fingerprint,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return DispositionRead.model_validate(row)
