"""Health, liveness and readiness endpoints.

Three endpoints rather than one, because three different consumers want three
different things:

``GET /health/live``
    Is the process running? No dependency calls at all. This is what a
    container orchestrator restarts on. A liveness probe that touches the
    database will restart a healthy API container during a database blip - a
    classic self-inflicted outage.

``GET /health/ready``
    Should traffic be routed here? Checks dependencies, returns ``503`` when the
    service cannot do its job.

``GET /health``
    What is actually wrong? The full report from section 36 of the design
    brief, always ``200`` so that the body can be read and displayed. This is
    the endpoint for humans and for the dashboard.

All three are unauthenticated: a probe that requires a credential is a probe
that fails during a credential problem. The report is therefore written to
contain no secrets and no raw upstream error text.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from acop import __version__
from acop.api.deps import get_health_service
from acop.schemas.health import (
    ComponentStatus,
    HealthReport,
    LivenessResponse,
    ReadinessResponse,
)
from acop.services import HealthService

router = APIRouter(tags=["health"])


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Returns 200 whenever the process is able to serve requests. "
    "Performs no dependency checks by design.",
)
async def liveness() -> LivenessResponse:
    return LivenessResponse(status="alive", version=__version__)


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    responses={503: {"description": "A required dependency is unavailable."}},
)
async def readiness(
    response: Response,
    health: Annotated[HealthService, Depends(get_health_service)],
) -> ReadinessResponse:
    report = await health.report()
    overall = ComponentStatus(report.status)
    # Degraded stays in service: ACOP with a missing model can still serve its
    # own data, and removing it from rotation would make the outage worse.
    if overall is ComponentStatus.UNHEALTHY:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status=overall, components=report.components)


@router.get(
    "/health",
    response_model=HealthReport,
    summary="Full health report",
    description="Reports each dependency independently. Every component status "
    "is the result of a real connectivity check.",
)
async def health_report(
    health: Annotated[HealthService, Depends(get_health_service)],
    fresh: Annotated[
        bool,
        Query(description="Bypass the short-lived probe cache and re-check now."),
    ] = False,
) -> HealthReport:
    return await health.report(use_cache=not fresh)
