"""Retrieval, evidence, embedding spaces and asset mentions.

The audit record for a search is the interesting design decision. It stores the
principal, the request id, a hash and length of the query, the retrieval mode
and strategy, the embedding space, the filters, the result ids and counts,
timings and outcome - and **not the query text**. A search query is often the
most sensitive thing about a search, because it describes what an operator was
worried about, and an immutable audit trail is a poor place to keep something
that cannot be redacted afterwards. The hash still makes repeated queries
correlatable, which is what an investigation actually needs.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from acop.api.deps import (
    OperatorPrincipal,
    ViewerPrincipal,
    get_asset_mention_service,
    get_audit_service,
    get_embedding_space_service,
    get_knowledge_retrieval_service,
)
from acop.api.transaction import TransactionalRoute
from acop.auth.principal import Principal, Role
from acop.core.exceptions import AuthorizationError
from acop.models.audit import AuditOutcome
from acop.schemas.audit import AuditEventCreate
from acop.schemas.knowledge import (
    AssetMentionRead,
    CitationRead,
    EmbeddingSpaceCreate,
    EmbeddingSpaceRead,
    EvidenceRequest,
    EvidenceResponse,
    ExplicitMentionCreate,
    MentionScanResult,
    PrefixVerification,
    RetrievalDiagnosticsRead,
    RetrievedChunkRead,
    SearchRequest,
    SearchResponse,
)
from acop.services import AuditService
from acop.services.knowledge import (
    AssetMentionService,
    EmbeddingSpaceService,
    KnowledgeRetrievalService,
    RetrievalFilters,
    SpaceRegistration,
)
from acop.services.knowledge.evidence import EvidenceBundle
from acop.services.knowledge.retrieval import RetrievalDiagnostics, RetrievedChunk

router = APIRouter(
    prefix="/knowledge", tags=["knowledge-search"], route_class=TransactionalRoute
)

RetrievalDep = Annotated[
    KnowledgeRetrievalService, Depends(get_knowledge_retrieval_service)
]
SpacesDep = Annotated[EmbeddingSpaceService, Depends(get_embedding_space_service)]
MentionsDep = Annotated[AssetMentionService, Depends(get_asset_mention_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


def _diagnostics(source: RetrievalDiagnostics) -> RetrievalDiagnosticsRead:
    return RetrievalDiagnosticsRead(
        mode=source.mode,
        strategy=source.strategy,
        embedding_space_id=source.embedding_space_id,
        requested_k=source.requested_k,
        returned_count=source.returned_count,
        ann_candidates_returned=source.ann_candidates_returned,
        ann_eligible_count=source.ann_eligible_count,
        eligible_population=source.eligible_population,
        eligible_population_capped=source.eligible_population_capped,
        exact_rows_ranked=source.exact_rows_ranked,
        lexical_candidates=source.lexical_candidates,
        fused_candidates=source.fused_candidates,
        rrf_k=source.rrf_k,
        degraded=source.degraded,
        degradation_reason=source.degradation_reason,
        total_latency_ms=round(source.total_latency_ms, 2),
    )


def _chunk(row: RetrievedChunk) -> RetrievedChunkRead:
    return RetrievedChunkRead(
        chunk_id=row.chunk_id,
        document_id=row.document_id,
        source_id=row.source_id,
        version_id=row.version_id,
        ordinal=row.ordinal,
        content=row.content,
        heading_path=list(row.heading_path),
        section_label=row.section_label,
        flags=list(row.flags),
        rank=row.rank,
        score=row.score,
        distance=row.distance,
        retrieval_method=row.method,
        vector_rank=row.vector_rank,
        lexical_rank=row.lexical_rank,
        fused_score=row.fused_score,
        sensitivity=row.sensitivity,
        trust_class=row.trust_class,
        source_kind=row.source_kind,
        source_title=row.source_title,
        document_title=row.document_title,
        external_ref=row.external_ref,
    )


def _filters(payload: SearchRequest) -> RetrievalFilters:
    return RetrievalFilters(
        source_ids=tuple(payload.source_ids),
        document_ids=tuple(payload.document_ids),
        source_kinds=tuple(str(k) for k in payload.source_kinds),
        trust_classes=tuple(str(t) for t in payload.trust_classes),
    )


async def _audit_search(
    audit: AuditService,
    request: Request,
    principal: Principal,
    payload: SearchRequest,
    diagnostics: RetrievalDiagnostics,
    result_ids: list[uuid.UUID],
    *,
    action: str,
) -> None:
    await audit.record(
        AuditEventCreate(
            action=action,
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.search",
            resource_id=str(diagnostics.embedding_space_id),
            context={
                # Hash and length, never the text. See the module docstring.
                "query_hash": payload.query_hash,
                "query_length": len(payload.query),
                "mode": diagnostics.mode.value,
                "strategy": diagnostics.strategy.value,
                "embedding_space_id": str(diagnostics.embedding_space_id),
                "requested_k": diagnostics.requested_k,
                "returned_count": diagnostics.returned_count,
                "degraded": diagnostics.degraded,
                "degradation_reason": diagnostics.degradation_reason,
                "filters": {
                    "source_ids": [str(i) for i in payload.source_ids],
                    "document_ids": [str(i) for i in payload.document_ids],
                    "source_kinds": [str(k) for k in payload.source_kinds],
                    "trust_classes": [str(t) for t in payload.trust_classes],
                },
                "result_chunk_ids": [str(i) for i in result_ids],
                "total_latency_ms": round(diagnostics.total_latency_ms, 2),
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )


@router.post(
    "/search", response_model=SearchResponse, summary="Retrieve knowledge passages"
)
async def search(
    request: Request,
    payload: SearchRequest,
    principal: ViewerPrincipal,
    retrieval: RetrievalDep,
    spaces: SpacesDep,
    audit: AuditDep,
) -> SearchResponse:
    """Search the corpus this principal is permitted to read.

    Sensitivity, trust and lifecycle are applied in SQL before any content
    reaches this handler, so the results below are already what the caller may
    see. The diagnostics say whether they are also *complete*.
    """
    space = (
        await spaces.get(payload.embedding_space_id)
        if payload.embedding_space_id
        else await spaces.default_space()
    )
    result = await retrieval.retrieve(
        payload.query,
        principal,
        space=space,
        mode=payload.mode,
        filters=_filters(payload),
        k=payload.k,
    )
    await _audit_search(
        audit,
        request,
        principal,
        payload,
        result.diagnostics,
        [row.chunk_id for row in result.results],
        action="knowledge.search",
    )
    return SearchResponse(
        query_hash=payload.query_hash,
        query_length=len(payload.query),
        results=[_chunk(row) for row in result.results],
        diagnostics=_diagnostics(result.diagnostics),
    )


@router.post(
    "/evidence",
    response_model=EvidenceResponse,
    summary="Retrieve passages as a citable evidence bundle",
)
async def evidence(
    request: Request,
    payload: EvidenceRequest,
    principal: ViewerPrincipal,
    retrieval: RetrievalDep,
    spaces: SpacesDep,
    mentions: MentionsDep,
    audit: AuditDep,
) -> EvidenceResponse:
    """The same retrieval, packaged for a model to read and cite.

    Milestone 3 stops here. It runs no generation, executes no tool and returns
    no statement it was not given: ``prompt_render`` is the text a caller would
    place in a *user* message, with each block delimited, numbered and labelled
    as data. Anything flagged as injection-shaped is marked rather than removed,
    because a security corpus legitimately contains material about injection.
    """
    space = (
        await spaces.get(payload.embedding_space_id)
        if payload.embedding_space_id
        else await spaces.default_space()
    )
    result = await retrieval.retrieve(
        payload.query,
        principal,
        space=space,
        mode=payload.mode,
        filters=_filters(payload),
        k=payload.k,
    )
    chunk_ids = [row.chunk_id for row in result.results]
    grouped = await mentions.for_chunks(chunk_ids)
    bundle = EvidenceBundle.from_result(result)

    await _audit_search(
        audit,
        request,
        principal,
        payload,
        result.diagnostics,
        chunk_ids,
        action="knowledge.evidence",
    )
    return EvidenceResponse(
        query_hash=payload.query_hash,
        query_length=len(payload.query),
        citations=[
            CitationRead(
                index=c.index,
                chunk_id=c.chunk_id,
                version_id=c.version_id,
                document_id=c.document_id,
                source_id=c.source_id,
                document_title=c.document_title,
                source_title=c.source_title,
                external_ref=c.external_ref,
                ordinal=c.ordinal,
                heading_path=list(c.heading_path),
                trust_class=c.trust_class,
                sensitivity=c.sensitivity,
                retrieval_method=c.retrieval_method,
                rank=c.rank,
                score=c.score,
                injection_suspected=c.injection_suspected,
            )
            for c in bundle.citations
        ],
        contents=list(bundle.contents),
        mentions={
            chunk_id: [AssetMentionRead.model_validate(m) for m in rows]
            for chunk_id, rows in grouped.items()
        },
        prompt_render=(
            bundle.render_for_prompt() if payload.include_prompt_render else None
        ),
        diagnostics=_diagnostics(result.diagnostics),
    )


# ---------------------------------------------------------------------------
# Embedding spaces
# ---------------------------------------------------------------------------


@router.get(
    "/embedding-spaces",
    response_model=list[EmbeddingSpaceRead],
    summary="List embedding spaces",
)
async def list_spaces(
    principal: ViewerPrincipal, spaces: SpacesDep
) -> list[EmbeddingSpaceRead]:
    del principal
    return [EmbeddingSpaceRead.model_validate(s) for s in await spaces.list_spaces()]


@router.post(
    "/embedding-spaces",
    response_model=EmbeddingSpaceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an embedding space",
)
async def register_space(
    request: Request,
    payload: EmbeddingSpaceCreate,
    principal: ViewerPrincipal,
    spaces: SpacesDep,
    audit: AuditDep,
) -> EmbeddingSpaceRead:
    """Register a comparable vector population and create its partition.

    Admin-only, checked in the handler rather than by an alias because there is
    no admin-only alias in Milestone 2's set and inventing one for a single
    endpoint would put the same rule in two places. Registration creates a
    physical partition and an HNSW index; it is a schema-shaped act.

    The space starts **unverified**: nothing may be embedded into it until
    someone has observed what the provider actually does with task prefixes.
    """
    if not principal.has_role(Role.ADMIN):
        raise AuthorizationError(
            "Registering an embedding space requires the admin role.",
            context={"required_roles": ["admin"]},
        )
    space = await spaces.register(
        SpaceRegistration(
            space_key=payload.space_key,
            provider=payload.provider,
            model=payload.model,
            dimensions=payload.dimensions,
            model_digest=payload.model_digest,
            document_prefix=payload.document_prefix,
            query_prefix=payload.query_prefix,
            max_input_tokens=payload.max_input_tokens,
            normalize_vectors=payload.normalize_vectors,
            make_default=payload.make_default,
        )
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.embedding_space.register",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.embedding_space",
            resource_id=str(space.id),
            context={
                "space_key": space.space_key,
                "provider": space.provider,
                "model": space.model,
                "model_digest": space.model_digest,
                "dimensions": space.dimensions,
                "partition": space.partition_relation,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return EmbeddingSpaceRead.model_validate(space)


@router.post(
    "/embedding-spaces/{space_id}/verify-prefixes",
    response_model=EmbeddingSpaceRead,
    summary="Record that a human verified the provider's prefix behaviour",
)
async def verify_prefixes(
    request: Request,
    space_id: uuid.UUID,
    payload: PrefixVerification,
    principal: ViewerPrincipal,
    spaces: SpacesDep,
    audit: AuditDep,
) -> EmbeddingSpaceRead:
    """The gate that stands between a registered space and any stored vector.

    Prefix behaviour is part of embedding-space identity: embedding documents
    with one prefix and queries with another produces incomparable vectors with
    no error anywhere, and changing a prefix after content exists silently
    invalidates the corpus. So this is an attested act with a subject and a
    timestamp, not a default.
    """
    if not principal.has_role(Role.ADMIN):
        raise AuthorizationError(
            "Verifying embedding prefixes requires the admin role.",
            context={"required_roles": ["admin"]},
        )
    space = await spaces.mark_prefixes_verified(space_id, principal.subject)
    await audit.record(
        AuditEventCreate(
            action="knowledge.embedding_space.verify_prefixes",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.embedding_space",
            resource_id=str(space_id),
            context={
                "space_key": space.space_key,
                "observed_document_prefix": payload.observed_document_prefix,
                "observed_query_prefix": payload.observed_query_prefix,
                "prefix_changes_vector": payload.prefix_changes_vector,
                "note": payload.note,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return EmbeddingSpaceRead.model_validate(space)


# ---------------------------------------------------------------------------
# Asset mentions
# ---------------------------------------------------------------------------


@router.post(
    "/versions/{version_id}/mentions/scan",
    response_model=MentionScanResult,
    summary="Scan a version for exact asset-identifier matches",
)
async def scan_mentions(
    request: Request,
    version_id: uuid.UUID,
    principal: OperatorPrincipal,
    mentions: MentionsDep,
    audit: AuditDep,
) -> MentionScanResult:
    """Link chunks to assets by exact identifier match, and nothing else.

    No entity extraction, no NLP, no fuzzy matching. Re-running is safe and
    idempotent, and re-running after new assets are inventoried is the intended
    way to link a document that was ingested before its hardware existed in the
    CMDB.
    """
    report = await mentions.link_version(version_id, principal)
    await audit.record(
        AuditEventCreate(
            action="knowledge.mentions.scan",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.version",
            resource_id=str(version_id),
            context={
                "chunks_scanned": report.chunks_scanned,
                "mentions_created": report.mentions_created,
                "ambiguous": report.ambiguous,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return MentionScanResult(
        version_id=version_id,
        chunks_scanned=report.chunks_scanned,
        candidates_considered=report.candidates_considered,
        mentions_created=report.mentions_created,
        ambiguous=report.ambiguous,
    )


@router.post(
    "/chunks/{chunk_id}/mentions",
    response_model=AssetMentionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Explicitly associate a chunk with an asset",
)
async def associate_mention(
    request: Request,
    chunk_id: uuid.UUID,
    payload: ExplicitMentionCreate,
    principal: OperatorPrincipal,
    mentions: MentionsDep,
    audit: AuditDep,
) -> AssetMentionRead:
    """The escape hatch for what exact matching cannot see.

    A runbook that calls a switch "the core switch" and never writes its serial
    is unlinkable by any honest exact matcher. This records a named person's
    assertion instead - the accountability, not a similarity score, is the
    control.
    """
    mention = await mentions.associate(
        chunk_id=chunk_id,
        asset_id=payload.asset_id,
        principal=principal,
        mention_text=payload.mention_text,
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.mentions.associate",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.chunk",
            resource_id=str(chunk_id),
            context={"asset_id": str(payload.asset_id)},
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return AssetMentionRead.model_validate(mention)


@router.get(
    "/chunks/{chunk_id}/mentions",
    response_model=list[AssetMentionRead],
    summary="List a chunk's asset mentions",
)
async def list_mentions(
    chunk_id: uuid.UUID, principal: ViewerPrincipal, mentions: MentionsDep
) -> list[AssetMentionRead]:
    del principal
    grouped = await mentions.for_chunks([chunk_id])
    return [AssetMentionRead.model_validate(m) for m in grouped.get(chunk_id, [])]
