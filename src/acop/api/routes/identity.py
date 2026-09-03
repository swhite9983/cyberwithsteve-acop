"""Identity introspection.

``GET /whoami`` exists for a specific reason: it is the smallest end-to-end
exercise of the identity contract. It authenticates a caller, resolves a
provider-neutral :class:`~acop.auth.principal.Principal`, writes an audit
record using only the four neutral identity fields, and returns what the
platform believes about the caller.

When OIDC is introduced, this endpoint's response shape must not change. That
is the acceptance test for provider neutrality.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from acop.api.deps import CurrentPrincipal, get_audit_service
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.schemas.audit import AuditEventCreate
from acop.services import AuditService

router = APIRouter(tags=["identity"])


class WhoAmIResponse(BaseModel):
    """The platform's provider-neutral view of the caller."""

    subject: str = Field(description="Opaque stable identifier for the caller.")
    principal_type: str
    issuer: str = Field(
        description="Authority that asserted this identity for this request."
    )
    auth_method: str
    display_name: str
    roles: list[str]
    authenticated_at: datetime


@router.get(
    "/whoami",
    response_model=WhoAmIResponse,
    summary="Describe the authenticated caller",
)
async def whoami(
    request: Request,
    principal: CurrentPrincipal,
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> WhoAmIResponse:
    await audit.record(
        AuditEventCreate(
            action="identity.whoami",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            resource_type="principal",
            resource_id=principal.subject,
            message="Caller introspected their own identity.",
        ),
        principal,
        source_address=getattr(request.state, "source_address", None),
        user_agent=getattr(request.state, "user_agent", None),
    )
    return WhoAmIResponse(
        subject=principal.subject,
        principal_type=principal.principal_type.value,
        issuer=principal.issuer,
        auth_method=principal.auth_method.value,
        display_name=principal.display_name,
        roles=sorted(principal.roles),
        authenticated_at=principal.authenticated_at,
    )
