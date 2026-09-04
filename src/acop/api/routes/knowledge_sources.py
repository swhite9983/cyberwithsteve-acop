"""Knowledge source endpoints: register, list, reclassify, retire.

There is no DELETE here, or anywhere in the knowledge API. Retiring stops
material being retrieved; deleting would strand every citation that already
pointed at it, which turns a previously auditable answer into an unverifiable
one.
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
    get_knowledge_catalog_service,
)
from acop.api.transaction import TransactionalRoute
from acop.models.audit import AuditOutcome
from acop.models.knowledge_vocabulary import SourceKind
from acop.schemas.audit import AuditEventCreate
from acop.schemas.knowledge import SourceCreate, SourceRead, SourceReclassify
from acop.services import AuditService
from acop.services.knowledge import KnowledgeCatalogService, SourceRegistration

router = APIRouter(
    prefix="/knowledge", tags=["knowledge-sources"], route_class=TransactionalRoute
)

CatalogDep = Annotated[KnowledgeCatalogService, Depends(get_knowledge_catalog_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


@router.post(
    "/sources",
    response_model=SourceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a knowledge source",
)
async def create_source(
    request: Request,
    payload: SourceCreate,
    principal: OperatorPrincipal,
    catalog: CatalogDep,
    audit: AuditDep,
) -> SourceRead:
    """Register where a body of knowledge comes from and how far it is trusted.

    Assigning ``AUTHORITATIVE_POLICY`` requires an approver: raising material to
    "this is our policy" is an approval act, and the endpoint refuses rather
    than silently downgrading the request.
    """
    source = await catalog.create_source(
        SourceRegistration(
            source_kind=payload.source_kind,
            title=payload.title,
            origin=payload.origin,
            trust_class=payload.trust_class,
            sensitivity=payload.sensitivity,
            uri=payload.uri,
            owner_subject=payload.owner_subject,
            metadata=payload.metadata,
        ),
        principal,
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.source.create",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.source",
            resource_id=str(source.id),
            context={
                "source_kind": source.source_kind,
                "trust_class": source.trust_class,
                "sensitivity": source.sensitivity,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return SourceRead.model_validate(source)


@router.get("/sources", response_model=list[SourceRead], summary="List sources")
async def list_sources(
    principal: ViewerPrincipal,
    catalog: CatalogDep,
    source_kind: Annotated[SourceKind | None, Query()] = None,
    include_retired: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[SourceRead]:
    rows = await catalog.list_sources(
        source_kind=str(source_kind) if source_kind else None,
        include_retired=include_retired,
        limit=limit,
        offset=offset,
    )
    del principal
    return [SourceRead.model_validate(row) for row in rows]


@router.get("/sources/{source_id}", response_model=SourceRead, summary="Read a source")
async def read_source(
    source_id: uuid.UUID, principal: ViewerPrincipal, catalog: CatalogDep
) -> SourceRead:
    del principal
    return SourceRead.model_validate(await catalog.get_source(source_id))


@router.post(
    "/sources/{source_id}/reclassify",
    response_model=SourceRead,
    summary="Change a source's trust class or classification",
)
async def reclassify_source(
    request: Request,
    source_id: uuid.UUID,
    payload: SourceReclassify,
    principal: ApproverPrincipal,
    catalog: CatalogDep,
    audit: AuditDep,
) -> SourceRead:
    """Reclassify, propagating a sensitivity change onto stored vectors.

    An operation rather than a PATCH because it is not a field edit: retrieval
    requires the source's sensitivity and its denormalised copy on every vector
    row to agree, so a change that touched only one would silently hide
    material. The audit record carries the count of rows repaired.
    """
    source, resynced = await catalog.reclassify_source(
        source_id,
        principal,
        trust_class=payload.trust_class,
        sensitivity=payload.sensitivity,
    )
    await audit.record(
        AuditEventCreate(
            action="knowledge.source.reclassify",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.source",
            resource_id=str(source_id),
            context={
                "trust_class": source.trust_class,
                "sensitivity": source.sensitivity,
                "vectors_resynced": resynced,
                "reason": payload.reason,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return SourceRead.model_validate(source)


@router.post(
    "/sources/{source_id}/retire",
    response_model=SourceRead,
    summary="Retire a source",
)
async def retire_source(
    request: Request,
    source_id: uuid.UUID,
    principal: ApproverPrincipal,
    catalog: CatalogDep,
    audit: AuditDep,
) -> SourceRead:
    source = await catalog.retire_source(source_id, principal)
    await audit.record(
        AuditEventCreate(
            action="knowledge.source.retire",
            outcome=AuditOutcome.SUCCESS,
            resource_type="knowledge.source",
            resource_id=str(source_id),
            context={"lifecycle_state": source.lifecycle_state},
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return SourceRead.model_validate(source)
