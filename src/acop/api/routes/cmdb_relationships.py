"""Relationship endpoints: assert, retire, list, and depth-1 traversal."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

from acop.api.deps import (
    OperatorPrincipal,
    ViewerPrincipal,
    get_audit_service,
    get_relationship_service,
)
from acop.api.transaction import TransactionalRoute
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.vocabulary import RelationshipType
from acop.schemas.audit import AuditEventCreate
from acop.schemas.relationship import (
    NeighbourList,
    RelationshipAssert,
    RelationshipAssertResult,
    RelationshipRead,
)
from acop.services import AuditService, RelationshipService
from acop.services.relationship import TOUCHED

router = APIRouter(
    prefix="/cmdb", tags=["cmdb-relationships"], route_class=TransactionalRoute
)

RelationshipServiceDep = Annotated[RelationshipService, Depends(get_relationship_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


@router.post(
    "/relationships",
    response_model=RelationshipAssertResult,
    status_code=status.HTTP_201_CREATED,
    summary="Assert an edge between two assets",
)
async def assert_relationship(
    request: Request,
    payload: RelationshipAssert,
    principal: OperatorPrincipal,
    relationships: RelationshipServiceDep,
    audit: AuditDep,
    response: Response,
) -> RelationshipAssertResult:
    """Assert an edge.

    A symmetric type has its endpoints canonicalised into UUID order first, so
    asserting A-to-B and B-to-A produce the same row rather than two rows for
    one cable.
    """
    outcome, edge, canonicalised = await relationships.assert_relationship(payload)
    await audit.record(
        AuditEventCreate(
            action="cmdb.relationship.assert"
            if outcome != TOUCHED
            else "cmdb.relationship.touch",
            outcome=AuditOutcome.SUCCESS,
            resource_type="cmdb.relationship",
            resource_id=str(edge.id),
            context={
                "relationship_type": edge.relationship_type,
                "is_symmetric": edge.is_symmetric,
                "canonicalised": canonicalised,
                "source_id": edge.source_id,
            },
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    if outcome == TOUCHED:
        response.status_code = status.HTTP_200_OK
    return RelationshipAssertResult(
        outcome=outcome,
        relationship=RelationshipRead.model_validate(edge),
        canonicalised=canonicalised,
    )


@router.get(
    "/relationships",
    response_model=list[RelationshipRead],
    summary="List relationships",
)
async def list_relationships(
    principal: ViewerPrincipal,
    relationships: RelationshipServiceDep,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    relationship_type: Annotated[RelationshipType | None, Query()] = None,
    direction: Annotated[str, Query(pattern="^(out|in|both)$")] = "both",
    include_closed: Annotated[bool, Query()] = False,
) -> list[RelationshipRead]:
    rows = await relationships.list_relationships(
        asset_id=asset_id,
        relationship_type=str(relationship_type) if relationship_type else None,
        direction=direction,
        include_closed=include_closed,
    )
    return [RelationshipRead.model_validate(row) for row in rows]


@router.post(
    "/relationships/{relationship_id}/retire",
    response_model=RelationshipRead,
    summary="Close an edge without deleting it",
)
async def retire_relationship(
    request: Request,
    relationship_id: uuid.UUID,
    principal: OperatorPrincipal,
    relationships: RelationshipServiceDep,
    audit: AuditDep,
) -> RelationshipRead:
    edge = await relationships.retire(relationship_id)
    await audit.record(
        AuditEventCreate(
            action="cmdb.relationship.retire",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.NOTICE,
            resource_type="cmdb.relationship",
            resource_id=str(edge.id),
            context={"relationship_type": edge.relationship_type},
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return RelationshipRead.model_validate(edge)


@router.get(
    "/assets/{asset_id}/related",
    response_model=NeighbourList,
    summary="Directly related assets, both directions",
)
async def related_assets(
    asset_id: uuid.UUID,
    principal: ViewerPrincipal,
    relationships: RelationshipServiceDep,
) -> NeighbourList:
    """Depth 1 only. Recursive traversal is Milestone 8."""
    return NeighbourList(
        asset_id=asset_id, neighbours=await relationships.neighbours(asset_id)
    )
