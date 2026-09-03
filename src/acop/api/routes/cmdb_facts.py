"""Fact endpoints: assert, read, history, conflicts, and trust transitions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

from acop.api.deps import (
    ApproverPrincipal,
    OperatorPrincipal,
    ViewerPrincipal,
    get_audit_service,
    get_fact_service,
)
from acop.core.exceptions import SecretRejectedError
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.vocabulary import AttestationAction, FactKind
from acop.schemas.audit import AuditEventCreate
from acop.schemas.fact import (
    AttestationRead,
    EffectiveValue,
    FactAssert,
    FactAssertResult,
    FactHistory,
    FactRead,
    PredicateConflict,
    TrustTransition,
)
from acop.services import AuditService, FactService
from acop.services.fact import TOUCHED

router = APIRouter(prefix="/cmdb", tags=["cmdb-facts"])

FactServiceDep = Annotated[FactService, Depends(get_fact_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


async def _audit_fact(
    audit: AuditService,
    request: Request,
    principal: object,
    action: str,
    fact_id: str | None,
    *,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    severity: AuditSeverity = AuditSeverity.INFO,
    message: str | None = None,
    context: dict[str, object] | None = None,
) -> None:
    """Audit a fact mutation.

    The context carries the predicate and types but **not the value**: the
    value already lives in ``asset_fact`` with full history, so copying it
    doubles the storage of the field most likely to contain something
    sensitive and doubles the surface a secret can leak into.

    A ``DENIED`` outcome is written out of band. A rejected secret is refused
    by raising, which rolls the request back; an in-transaction record of that
    rejection would be rolled back with it, leaving the one event a reviewer
    most wants unrecorded.
    """
    event = AuditEventCreate(
        action=action,
        outcome=outcome,
        severity=severity,
        resource_type="cmdb.fact",
        resource_id=fact_id,
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
    "/assets/{asset_id}/facts",
    response_model=FactAssertResult,
    status_code=status.HTTP_201_CREATED,
    summary="Assert a fact about an asset",
    responses={422: {"description": "Secret-bearing or malformed predicate."}},
)
async def assert_fact(
    request: Request,
    asset_id: uuid.UUID,
    payload: FactAssert,
    principal: OperatorPrincipal,
    facts: FactServiceDep,
    audit: AuditDep,
    response: Response,
) -> FactAssertResult:
    """Assert a claim.

    An unchanged re-assertion advances ``last_seen_at`` and creates no row -
    the property that makes a five-minute discovery sweep survivable. It is
    still audited, under the distinct action ``cmdb.fact.touch`` so it can be
    retention-tiered separately once collectors arrive.
    """
    try:
        outcome, fact, superseded, redacted = await facts.assert_fact(asset_id, payload)
    except SecretRejectedError as exc:
        await _audit_fact(
            audit,
            request,
            principal,
            "cmdb.fact.secret_rejected",
            None,
            outcome=AuditOutcome.DENIED,
            severity=AuditSeverity.WARNING,
            message="Fact rejected: predicate or value appeared to carry a secret.",
            context={"asset_id": str(asset_id), **exc.context},
        )
        raise

    action = {
        "CREATED": "cmdb.fact.assert",
        "SUPERSEDED": "cmdb.fact.supersede",
        "TOUCHED": "cmdb.fact.touch",
    }[outcome]
    await _audit_fact(
        audit,
        request,
        principal,
        action,
        str(fact.id),
        context={
            "predicate": fact.predicate,
            "fact_kind": fact.fact_kind,
            "value_type": fact.value_type,
            "source_type": fact.source_type,
            "source_id": fact.source_id,
            "verification_status": fact.verification_status,
            "superseded_fact_id": str(superseded) if superseded else None,
            "json_keys_redacted": redacted,
        },
    )
    if outcome == TOUCHED:
        response.status_code = status.HTTP_200_OK
    return FactAssertResult(
        outcome=outcome,
        fact=FactRead.model_validate(fact),
        superseded_fact_id=superseded,
        json_keys_redacted=redacted,
    )


@router.get(
    "/assets/{asset_id}/facts",
    response_model=list[FactRead],
    summary="Live facts for an asset",
)
async def list_facts(
    asset_id: uuid.UUID,
    principal: ViewerPrincipal,
    facts: FactServiceDep,
    fact_kind: Annotated[FactKind | None, Query()] = None,
    predicate: Annotated[str | None, Query()] = None,
) -> list[FactRead]:
    rows = await facts.live_facts(
        asset_id,
        fact_kind=str(fact_kind) if fact_kind else None,
        predicate=predicate,
    )
    return [FactRead.model_validate(row) for row in rows]


@router.get(
    "/assets/{asset_id}/facts/{predicate}/history",
    response_model=FactHistory,
    summary="Every interval ever recorded for one predicate",
)
async def fact_history(
    asset_id: uuid.UUID,
    predicate: str,
    principal: ViewerPrincipal,
    facts: FactServiceDep,
) -> FactHistory:
    rows = await facts.history(asset_id, predicate)
    attestations = await facts.attestations([row.id for row in rows])
    return FactHistory(
        asset_id=asset_id,
        predicate=predicate,
        intervals=[FactRead.model_validate(row) for row in rows],
        attestations=[AttestationRead.model_validate(item) for item in attestations],
    )


@router.get(
    "/assets/{asset_id}/conflicts",
    response_model=list[PredicateConflict],
    summary="Predicates where live sources disagree",
)
async def list_conflicts(
    asset_id: uuid.UUID, principal: ViewerPrincipal, facts: FactServiceDep
) -> list[PredicateConflict]:
    return await facts.conflicts(asset_id)


@router.get(
    "/assets/{asset_id}/facts/{predicate}/effective",
    response_model=EffectiveValue,
    summary="Current value and the basis for it",
)
async def effective_value(
    asset_id: uuid.UUID,
    predicate: str,
    principal: ViewerPrincipal,
    facts: FactServiceDep,
    fact_kind: Annotated[FactKind, Query()] = FactKind.OBSERVED_STATE,
) -> EffectiveValue:
    """Report the value, or report honestly that it is unresolved.

    No conflict resolution happens here. Milestone 8 replaces only the
    ``UNRESOLVED`` case.
    """
    return await facts.effective(asset_id, predicate, str(fact_kind))


@router.get(
    "/facts/{fact_id}/attestations",
    response_model=list[AttestationRead],
    summary="Immutable trust-transition history for one fact",
)
async def fact_attestations(
    fact_id: uuid.UUID, principal: ViewerPrincipal, facts: FactServiceDep
) -> list[AttestationRead]:
    rows = await facts.attestations([fact_id])
    return [AttestationRead.model_validate(row) for row in rows]


@router.post(
    "/facts/{fact_id}/verify",
    response_model=FactRead,
    summary="Confirm an observation is accurate",
    responses={409: {"description": "AI inference, or another claim holds authority."}},
)
async def verify_fact(
    request: Request,
    fact_id: uuid.UUID,
    payload: TrustTransition,
    principal: ApproverPrincipal,
    facts: FactServiceDep,
    audit: AuditDep,
) -> FactRead:
    """Verification changes trust, never the value."""
    return await _transition(
        request, fact_id, AttestationAction.VERIFY, payload, principal, facts, audit
    )


@router.post(
    "/facts/{fact_id}/revoke",
    response_model=FactRead,
    summary="Withdraw authoritative standing",
)
async def revoke_fact(
    request: Request,
    fact_id: uuid.UUID,
    payload: TrustTransition,
    principal: ApproverPrincipal,
    facts: FactServiceDep,
    audit: AuditDep,
) -> FactRead:
    """Withdraw verification or approval without deleting anything.

    The fact keeps its value and provenance; the immutable record of who
    verified it, when, who revoked it and when survives in
    ``fact_attestation``. Verification must be reversible or a mistake would
    be permanent.
    """
    return await _transition(
        request, fact_id, AttestationAction.REVOKE, payload, principal, facts, audit
    )


async def _transition(
    request: Request,
    fact_id: uuid.UUID,
    action: AttestationAction,
    payload: TrustTransition,
    principal: object,
    facts: FactService,
    audit: AuditService,
) -> FactRead:
    fact = await facts.transition(
        fact_id,
        action,
        principal,  # type: ignore[arg-type]
        reason=payload.reason,
        request_id=getattr(request.state, "request_id", None),
    )
    await _audit_fact(
        audit,
        request,
        principal,
        f"cmdb.fact.{action.value.lower()}",
        str(fact.id),
        severity=AuditSeverity.NOTICE,
        message=f"Fact {action.value.lower()}d.",
        context={
            "predicate": fact.predicate,
            "fact_kind": fact.fact_kind,
            "verification_status": fact.verification_status,
            "reason_supplied": payload.reason is not None,
        },
    )
    return FactRead.model_validate(fact)
