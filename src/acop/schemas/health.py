"""Health response schemas."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ComponentStatus(StrEnum):
    """Health state of a single component.

    Three states rather than two. ``degraded`` is the state where ACOP is
    serving requests correctly but a capability is missing - the configured
    model is not pulled, say. Collapsing that into ``unhealthy`` would cause an
    orchestrator to restart a container that is working; collapsing it into
    ``healthy`` would hide a real problem.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentCheck(BaseModel):
    """Detailed result of one dependency probe."""

    model_config = ConfigDict(use_enum_values=True)

    status: ComponentStatus
    latency_ms: float | None = Field(
        default=None, description="Round-trip time of the probe, in milliseconds."
    )
    message: str | None = Field(
        default=None,
        description=(
            "Operator-facing summary. Deliberately categorical rather than a raw "
            "upstream error string, so that an unauthenticated probe cannot be "
            "used to enumerate internal infrastructure."
        ),
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthReport(BaseModel):
    """Aggregate health of ACOP and its dependencies.

    ``components`` matches the shape specified in section 36 of the design brief
    exactly - a flat map of component name to status string - so that anything
    written against that contract keeps working. ``details`` carries the richer
    per-component data that operators and dashboards need.
    """

    model_config = ConfigDict(use_enum_values=True)

    status: ComponentStatus
    version: str
    environment: str
    checked_at: datetime
    cached: bool = Field(
        default=False,
        description="True when this report was served from the short-lived cache.",
    )
    components: dict[str, str]
    details: dict[str, ComponentCheck]


class LivenessResponse(BaseModel):
    """Response from the liveness probe."""

    status: str = "alive"
    version: str


class ReadinessResponse(BaseModel):
    """Response from the readiness probe."""

    model_config = ConfigDict(use_enum_values=True)

    status: ComponentStatus
    components: dict[str, str]
