"""Asset and identifier endpoints.

There is no ``DELETE`` verb anywhere in the CMDB API. Retirement is a
``POST``, so nobody can infer destructive semantics from the method, and an
accidental ``DELETE`` has nothing to hit.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

from acop.api.deps import (
    OperatorPrincipal,
    ViewerPrincipal,
    get_asset_service,
    get_audit_service,
    get_fact_service,
    get_identity_resolver,
)
from acop.api.transaction import TransactionalRoute
from acop.core.exceptions import IdentityConflictError
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.vocabulary import AttestationAction
from acop.schemas.asset import (
    AssetCreate,
    AssetDetail,
    AssetPage,
    AssetRead,
    AssetUpdate,
    IdentifierInput,
    IdentifierRead,
    ResolutionResult,
    ResolveRequest,
)
from acop.schemas.audit import AuditEventCreate
from acop.schemas.fact import DesiredFactCreate, FactRead
from acop.services import AssetService, AuditService, FactService, IdentityResolver
from acop.services.asset import DEFAULT_PAGE_SIZE

router = APIRouter(prefix="/cmdb", tags=["cmdb-assets"], route_class=TransactionalRoute)

AssetServiceDep = Annotated[AssetService, Depends(get_asset_service)]
ResolverDep = Annotated[IdentityResolver, Depends(get_identity_resolver)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]
FactServiceDep = Annotated[FactService, Depends(get_fact_service)]


async def _audit(
    audit: AuditService,
    request: Request,
    principal: object,
    action: str,
    *,
    resource_type: str,
    resource_id: str | None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    severity: AuditSeverity = AuditSeverity.INFO,
    message: str | None = None,
    context: dict[str, object] | None = None,
) -> None:
    """Write one audit record for a CMDB mutation.

    A ``DENIED`` outcome is routed to ``record_denial``, which writes on its
    own connection. The caller is about to raise, and the request transaction -
    including anything written into it - is about to be rolled back. Dispatching
    on the outcome rather than at each call site means a future denial cannot
    be added that silently vanishes.

    ``permission_class`` is left unset: permission classes describe *tool*
    execution, and a CMDB write changes ACOP's own store, not infrastructure.
    Assigning one now would pre-empt the Milestone 4 registry.
    """
    event = AuditEventCreate(
        action=action,
        outcome=outcome,
        severity=severity,
        resource_type=resource_type,
        resource_id=resource_id,
        message=message,
        context=context or {},
    )
    write = audit.record_denial if outcome is AuditOutcome.DENIED else audit.record
    await write(
        event,
        principal,  # type: ignore[arg-type]
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )


@router.post(
    "/assets",
    response_model=AssetDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create an asset",
)
async def create_asset(
    request: Request,
    payload: AssetCreate,
    principal: OperatorPrincipal,
    assets: AssetServiceDep,
    resolver: ResolverDep,
    audit: AuditDep,
    response: Response,
) -> AssetDetail:
    """Create an asset, resolving identity first when identifiers are supplied.

    Supplying identifiers makes a collector's create idempotent by
    construction: the same call twice produces one asset.
    """
    if payload.identifiers:
        try:
            resolution = await resolver.resolve(
                asset_type=payload.asset_type,
                display_name=payload.display_name,
                identifiers=payload.identifiers,
                principal=principal,
            )
        except IdentityConflictError as exc:
            await _audit(
                audit,
                request,
                principal,
                "cmdb.identity.conflict",
                resource_type="cmdb.asset",
                resource_id=None,
                outcome=AuditOutcome.DENIED,
                severity=AuditSeverity.WARNING,
                message="Identifiers matched more than one asset; refused to guess.",
                context=exc.context,
            )
            raise
        asset = resolution.asset
        created = resolution.outcome == "CREATED"
    else:
        resolution = await resolver.resolve(
            asset_type=payload.asset_type,
            display_name=payload.display_name,
            identifiers=[],
            principal=principal,
        )
        asset = resolution.asset
        created = True

    if payload.description is not None:
        asset.description = payload.description

    await _audit(
        audit,
        request,
        principal,
        "cmdb.asset.create" if created else "cmdb.asset.match",
        resource_type="cmdb.asset",
        resource_id=str(asset.id),
        message=f"Asset {'created' if created else 'matched'}.",
        context={"asset_type": asset.asset_type},
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return await _detail(assets, asset.id)


@router.post(
    "/assets/resolve",
    response_model=ResolutionResult,
    summary="Resolve identifiers to exactly one asset",
    responses={409: {"description": "Identifiers matched more than one asset."}},
)
async def resolve_asset(
    request: Request,
    payload: ResolveRequest,
    principal: OperatorPrincipal,
    resolver: ResolverDep,
    audit: AuditDep,
    response: Response,
) -> ResolutionResult:
    """The contract every future discovery source is built on.

    On a multi-match this writes nothing and returns 409 naming both
    candidates. Refusing is recoverable; guessing welds two machines into one
    record permanently.
    """
    try:
        resolution = await resolver.resolve(
            asset_type=payload.asset_type,
            display_name=payload.display_name,
            identifiers=payload.identifiers,
            principal=principal,
            create_if_missing=payload.create_if_missing,
        )
    except IdentityConflictError as exc:
        await _audit(
            audit,
            request,
            principal,
            "cmdb.identity.conflict",
            resource_type="cmdb.asset",
            resource_id=None,
            outcome=AuditOutcome.DENIED,
            severity=AuditSeverity.WARNING,
            message="Identifiers matched more than one asset; refused to guess.",
            context=exc.context,
        )
        raise

    await _audit(
        audit,
        request,
        principal,
        "cmdb.asset.create" if resolution.outcome == "CREATED" else "cmdb.asset.match",
        resource_type="cmdb.asset",
        resource_id=str(resolution.asset.id),
        context={"outcome": resolution.outcome},
    )
    if resolution.outcome == "CREATED":
        response.status_code = status.HTTP_201_CREATED
    return ResolutionResult(
        outcome=resolution.outcome,
        asset=AssetRead.model_validate(resolution.asset),
        matched_on=list(resolution.matched_on),
    )


@router.get("/assets", response_model=AssetPage, summary="List and search assets")
async def list_assets(
    principal: ViewerPrincipal,
    assets: AssetServiceDep,
    asset_type: Annotated[str | None, Query()] = None,
    lifecycle_state: Annotated[str | None, Query()] = None,
    q: Annotated[str | None, Query(description="Display-name prefix.")] = None,
    identifier: Annotated[
        str | None, Query(description="Filter by 'namespace:value'.")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = DEFAULT_PAGE_SIZE,
    cursor: Annotated[str | None, Query()] = None,
) -> AssetPage:
    rows, next_cursor = await assets.list_assets(
        asset_type=asset_type,
        lifecycle_state=lifecycle_state,
        query_text=q,
        identifier=identifier,
        limit=limit,
        cursor=cursor,
    )
    return AssetPage(
        items=[AssetRead.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.get("/assets/{asset_id}", response_model=AssetDetail, summary="Inspect one asset")
async def get_asset(
    asset_id: uuid.UUID, principal: ViewerPrincipal, assets: AssetServiceDep
) -> AssetDetail:
    return await _detail(assets, asset_id)


@router.patch("/assets/{asset_id}", response_model=AssetDetail, summary="Update an asset")
async def update_asset(
    request: Request,
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    principal: OperatorPrincipal,
    assets: AssetServiceDep,
    audit: AuditDep,
) -> AssetDetail:
    asset = await assets.update(asset_id, payload)
    await _audit(
        audit,
        request,
        principal,
        "cmdb.asset.update",
        resource_type="cmdb.asset",
        resource_id=str(asset.id),
        context={"fields": sorted(payload.model_dump(exclude_none=True))},
    )
    return await _detail(assets, asset.id)


@router.post(
    "/assets/{asset_id}/retire",
    response_model=AssetDetail,
    summary="Retire an asset without deleting anything",
)
async def retire_asset(
    request: Request,
    asset_id: uuid.UUID,
    principal: OperatorPrincipal,
    assets: AssetServiceDep,
    audit: AuditDep,
) -> AssetDetail:
    """Close the asset's live claims and edges. Nothing is deleted."""
    asset, closed_facts, closed_edges = await assets.retire(asset_id)
    await _audit(
        audit,
        request,
        principal,
        "cmdb.asset.retire",
        resource_type="cmdb.asset",
        resource_id=str(asset.id),
        severity=AuditSeverity.NOTICE,
        message="Asset retired; history preserved.",
        context={"closed_facts": closed_facts, "closed_relationships": closed_edges},
    )
    return await _detail(assets, asset.id)


@router.get(
    "/assets/{asset_id}/identifiers",
    response_model=list[IdentifierRead],
    summary="List an asset's identifiers",
)
async def list_identifiers(
    asset_id: uuid.UUID, principal: ViewerPrincipal, assets: AssetServiceDep
) -> list[IdentifierRead]:
    await assets.get(asset_id)
    rows = await assets.identifiers(asset_id)
    return [IdentifierRead.model_validate(row) for row in rows]


@router.post(
    "/assets/{asset_id}/identifiers",
    response_model=IdentifierRead,
    status_code=status.HTTP_201_CREATED,
    summary="Attach an identifier",
    responses={409: {"description": "Value already attached to another asset."}},
)
async def attach_identifier(
    request: Request,
    asset_id: uuid.UUID,
    payload: IdentifierInput,
    principal: OperatorPrincipal,
    assets: AssetServiceDep,
    audit: AuditDep,
) -> IdentifierRead:
    identifier = await assets.attach_identifier(asset_id, payload)
    await _audit(
        audit,
        request,
        principal,
        "cmdb.identifier.attach",
        resource_type="cmdb.identifier",
        resource_id=str(identifier.id),
        context={
            "namespace": identifier.namespace,
            "unique_in_namespace": identifier.unique_in_namespace,
        },
    )
    return IdentifierRead.model_validate(identifier)


@router.post(
    "/identifiers/{identifier_id}/retire",
    response_model=IdentifierRead,
    summary="Retire an identifier, freeing the value for reuse",
)
async def retire_identifier(
    request: Request,
    identifier_id: uuid.UUID,
    principal: OperatorPrincipal,
    assets: AssetServiceDep,
    audit: AuditDep,
) -> IdentifierRead:
    identifier = await assets.retire_identifier(identifier_id)
    await _audit(
        audit,
        request,
        principal,
        "cmdb.identifier.retire",
        resource_type="cmdb.identifier",
        resource_id=str(identifier.id),
        context={"namespace": identifier.namespace},
    )
    return IdentifierRead.model_validate(identifier)


@router.post(
    "/assets/{asset_id}/desired-facts",
    response_model=FactRead,
    status_code=status.HTTP_201_CREATED,
    summary="Declare an approved desired configuration",
)
async def create_desired_fact(
    request: Request,
    asset_id: uuid.UUID,
    payload: DesiredFactCreate,
    principal: OperatorPrincipal,
    facts: FactServiceDep,
    audit: AuditDep,
) -> FactRead:
    """A statement of intent, on the axis independent of observation."""
    fact = await facts.create_desired(
        asset_id,
        payload,
        principal,
        request_id=getattr(request.state, "request_id", None),
    )
    await _audit(
        audit,
        request,
        principal,
        "cmdb.fact.approve",
        resource_type="cmdb.fact",
        resource_id=str(fact.id),
        severity=AuditSeverity.NOTICE,
        message="Desired configuration declared.",
        context={
            "predicate": fact.predicate,
            "fact_kind": fact.fact_kind,
            "value_type": fact.value_type,
            "attestation": AttestationAction.APPROVE.value,
        },
    )
    return FactRead.model_validate(fact)


async def _detail(assets: AssetService, asset_id: uuid.UUID) -> AssetDetail:
    asset = await assets.get(asset_id)
    identifiers = await assets.identifiers(asset_id, include_retired=False)
    fact_count, edge_count = await assets.counts(asset_id)
    detail = AssetDetail.model_validate(asset)
    detail.identifiers = [IdentifierRead.model_validate(row) for row in identifiers]
    detail.live_fact_count = fact_count
    detail.relationship_count = edge_count
    return detail
