"""Audit record schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from acop.models.audit import AuditOutcome, AuditSeverity


class AuditEventCreate(BaseModel):
    """Input for writing an audit record.

    Identity is supplied as a ``Principal`` at the service boundary, not here,
    so that a caller cannot fabricate a subject.
    """

    model_config = ConfigDict(use_enum_values=True)

    action: str = Field(max_length=128)
    outcome: AuditOutcome
    severity: AuditSeverity = AuditSeverity.INFO
    resource_type: str | None = Field(default=None, max_length=64)
    resource_id: str | None = Field(default=None, max_length=255)
    permission_class: str | None = Field(default=None, max_length=32)
    message: str | None = Field(default=None, max_length=1024)
    context: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = Field(
        default=None,
        description="Defaults to now. Set explicitly for backfilled events.",
    )


class AuditEventRead(BaseModel):
    """Audit record as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    occurred_at: datetime
    recorded_at: datetime
    principal_subject: str
    principal_type: str
    principal_issuer: str
    auth_method: str
    action: str
    resource_type: str | None
    resource_id: str | None
    permission_class: str | None
    outcome: str
    severity: str
    message: str | None
    request_id: str | None
    source_address: str | None
    context: dict[str, Any]
