"""The tool catalog: what exists, and what an operator may take out of service.

**``GET /tools`` returns only what the caller could actually invoke.**
Enumerating capabilities someone cannot use is reconnaissance: it tells an
attacker exactly which privilege to go and acquire. The filter is by the tool's
declared ``required_roles`` against the caller's effective roles, and prohibited
tools are absent from every listing regardless of role.

**Disable and enable are the reason the database owns lifecycle at all.**
During an incident an operator must be able to take a misbehaving tool out of
service immediately and attributably, without a redeploy. Both are POSTs with a
required reason, both are audited, and neither can change anything else about
the tool - a disabled tool's permission class, schema and adapter binding are
still whatever the code says.

There is no DELETE. Removing a tool is removing its declaration from the
catalog and letting reconciliation retire the row, which preserves every
invocation that referenced it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.api.deps import (
    AdminPrincipal,
    ViewerPrincipal,
    get_audit_service,
    get_session,
)
from acop.api.transaction import TransactionalRoute
from acop.auth.principal import Principal, Role
from acop.core.exceptions import NotFoundError
from acop.models.audit import AuditOutcome, AuditSeverity
from acop.models.tool import ToolRegistration
from acop.models.tool_vocabulary import ToolLifecycle, effective_roles
from acop.schemas.audit import AuditEventCreate
from acop.schemas.tools import ToolAdminView, ToolDescriptor, ToolLifecycleRequest
from acop.services import AuditService
from acop.tools.contract import ToolDefinition
from acop.tools.registry import all_definitions, get_definition

router = APIRouter(prefix="/tools", tags=["tools"], route_class=TransactionalRoute)

SessionDep = Annotated[AsyncSession, Depends(get_session)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]


def _descriptor(definition: ToolDefinition, lifecycle: ToolLifecycle) -> ToolDescriptor:
    """Build the caller-facing view, field by field.

    Constructed rather than dumped, so a field added to ``ToolDefinition``
    tomorrow is not disclosed by accident. ``adapter_id`` is the one that
    matters: it never appears here.
    """
    return ToolDescriptor(
        tool_name=definition.tool_name,
        tool_version=definition.tool_version,
        description=definition.description,
        permission_class=definition.permission_class.value,
        approval_required=definition.approval_policy.approval_required,
        min_approvals=definition.approval_policy.min_approvals,
        validation_required=definition.validation_required,
        target_type=definition.target_type.value,
        target_asset_types=sorted(definition.target_asset_types),
        required_roles=sorted(definition.required_roles),
        timeout_seconds=definition.timeout_seconds,
        idempotency=definition.idempotency.value,
        lifecycle_state=lifecycle.value,
        input_schema=definition.input_model.model_json_schema(),
        output_schema=definition.output_model.model_json_schema(),
    )


def _admin_view(definition: ToolDefinition, row: ToolRegistration) -> ToolAdminView:
    base = _descriptor(definition, ToolLifecycle(row.lifecycle_state))
    return ToolAdminView(
        **base.model_dump(),
        capability_tags=sorted(definition.capability_tags),
        prohibited=definition.prohibited,
        contract_hash=row.contract_hash,
        approval_ttl_seconds=definition.approval_policy.ttl_seconds,
        distinct_approvers_required=(
            definition.approval_policy.distinct_approvers_required
        ),
        sensitivity=definition.sensitivity.value,
        first_registered_at=row.first_registered_at,
        disabled_at=row.disabled_at,
        disabled_by_subject=row.disabled_by_subject,
        disabled_reason=row.disabled_reason,
        retired_at=row.retired_at,
    )


def _invocable_by(definition: ToolDefinition, principal: Principal) -> bool:
    """Whether this caller could invoke this tool at all.

    Prohibited tools are invisible to everyone, admin included. They are not
    invocable by anyone, so listing them would be listing something the caller
    cannot use - the exact reconnaissance this filter exists to prevent.
    """
    if definition.prohibited:
        return False
    held = {role.value for role in effective_roles(principal.roles)}
    return set(definition.required_roles).issubset(held)


async def _registrations(
    session: AsyncSession,
) -> dict[tuple[str, str], ToolRegistration]:
    rows = (await session.execute(select(ToolRegistration))).scalars().all()
    return {(row.tool_name, row.tool_version): row for row in rows}


@router.get("", response_model=list[ToolDescriptor])
async def list_tools(
    principal: ViewerPrincipal, session: SessionDep
) -> list[ToolDescriptor]:
    """Tools this caller could invoke, ACTIVE only."""
    registrations = await _registrations(session)
    out: list[ToolDescriptor] = []
    for definition in all_definitions():
        row = registrations.get(definition.key)
        if row is None or row.lifecycle_state != ToolLifecycle.ACTIVE.value:
            continue
        if not _invocable_by(definition, principal):
            continue
        out.append(_descriptor(definition, ToolLifecycle.ACTIVE))
    return out


@router.get("/{tool_name}", response_model=ToolDescriptor)
async def get_tool(
    tool_name: str, principal: ViewerPrincipal, session: SessionDep
) -> ToolDescriptor:
    """The highest ACTIVE version of one tool."""
    registrations = await _registrations(session)
    candidates = [
        (definition, registrations.get(definition.key))
        for definition in all_definitions()
        if definition.tool_name == tool_name
    ]
    live = [
        (definition, row)
        for definition, row in candidates
        if row is not None
        and row.lifecycle_state == ToolLifecycle.ACTIVE.value
        and _invocable_by(definition, principal)
    ]
    if not live:
        # Deliberately the same 404 whether the tool does not exist, is
        # disabled, or is one this caller may not use. Distinguishing them
        # would turn the endpoint into an oracle.
        raise NotFoundError(f"No invocable tool named {tool_name!r}.")
    definition, _ = max(live, key=lambda pair: pair[0].tool_version)
    return _descriptor(definition, ToolLifecycle.ACTIVE)


@router.get("/{tool_name}/versions", response_model=list[ToolAdminView])
async def list_versions(
    tool_name: str, principal: ViewerPrincipal, session: SessionDep
) -> list[ToolAdminView]:
    """Every version of a tool.

    Non-admins see only ACTIVE versions they could invoke. Admins see
    DISABLED and RETIRED too, because during an incident "why is this not
    running" is the question, and the answer is in the lifecycle row.
    """
    is_admin = principal.has_role(Role.ADMIN)
    registrations = await _registrations(session)
    out: list[ToolAdminView] = []
    for definition in all_definitions():
        if definition.tool_name != tool_name:
            continue
        row = registrations.get(definition.key)
        if row is None:
            continue
        if not is_admin:
            if row.lifecycle_state != ToolLifecycle.ACTIVE.value:
                continue
            if not _invocable_by(definition, principal):
                continue
        out.append(_admin_view(definition, row))
    if not out:
        raise NotFoundError(f"No tool named {tool_name!r}.")
    return out


@router.post("/{tool_name}/disable", response_model=ToolAdminView)
async def disable_tool(
    tool_name: str,
    payload: ToolLifecycleRequest,
    principal: AdminPrincipal,
    session: SessionDep,
    audit: AuditDep,
) -> ToolAdminView:
    """Take one tool version out of service, now, with attribution."""
    row, definition = await _lifecycle_target(session, tool_name, payload.tool_version)
    row.lifecycle_state = ToolLifecycle.DISABLED.value
    row.disabled_at = datetime.now(UTC)
    row.disabled_by_subject = principal.subject
    row.disabled_reason = payload.reason
    await session.flush()
    await audit.record(
        AuditEventCreate(
            action="tool.disable",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.WARNING,
            resource_type="tool_registration",
            resource_id=str(row.id),
            permission_class=definition.permission_class.value,
            message=f"{tool_name}@{payload.tool_version} disabled.",
            context={"reason": payload.reason},
        ),
        principal,
    )
    return _admin_view(definition, row)


@router.post("/{tool_name}/enable", response_model=ToolAdminView)
async def enable_tool(
    tool_name: str,
    payload: ToolLifecycleRequest,
    principal: AdminPrincipal,
    session: SessionDep,
    audit: AuditDep,
) -> ToolAdminView:
    """Return a disabled tool to service.

    A RETIRED tool cannot be enabled here: retirement means the code
    declaration is gone, so there is nothing to enable. Restoring it is a
    deploy, which is the correct amount of ceremony.
    """
    row, definition = await _lifecycle_target(session, tool_name, payload.tool_version)
    if row.lifecycle_state == ToolLifecycle.RETIRED.value:
        raise NotFoundError(
            f"{tool_name}@{payload.tool_version} is retired. Restoring it "
            "requires the code declaration to return."
        )
    row.lifecycle_state = ToolLifecycle.ACTIVE.value
    row.disabled_at = None
    row.disabled_by_subject = None
    row.disabled_reason = None
    await session.flush()
    await audit.record(
        AuditEventCreate(
            action="tool.enable",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.NOTICE,
            resource_type="tool_registration",
            resource_id=str(row.id),
            permission_class=definition.permission_class.value,
            message=f"{tool_name}@{payload.tool_version} enabled.",
            context={"reason": payload.reason},
        ),
        principal,
    )
    return _admin_view(definition, row)


async def _lifecycle_target(
    session: AsyncSession, tool_name: str, tool_version: str
) -> tuple[ToolRegistration, ToolDefinition]:
    """The row and the declaration, both of which must exist."""
    row = (
        (
            await session.execute(
                select(ToolRegistration).where(
                    ToolRegistration.tool_name == tool_name,
                    ToolRegistration.tool_version == tool_version,
                )
            )
        )
        .scalars()
        .first()
    )
    definition = get_definition(tool_name, tool_version)
    if row is None or definition is None:
        raise NotFoundError(f"No tool {tool_name}@{tool_version}.")
    return row, definition


__all__ = ["router"]
