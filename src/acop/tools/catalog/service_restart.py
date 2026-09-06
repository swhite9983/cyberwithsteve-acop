"""``test.service.restart`` — Class 2, the complete change path.

This is the tool the milestone is really built around. It proves request →
approval → final gate → execute → validate end to end, plus separation of
duties, envelope binding, approval expiry, idempotency, and the distinction
between "the adapter said yes" and "the change happened".

``min_approvals=1`` and a one-hour TTL are the Class 2 defaults. The strength
of a Class 2 control is that *someone other than the requester* agreed, not
that several people did.

``idempotency=KEYED`` with ``max_attempts=1``: a restart is safe to repeat in
the sense that the end state is the same, but repeating it is still a second
outage, so the framework deduplicates by key rather than retrying.
"""

from __future__ import annotations

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    APPROVAL_AUTHORITY_ROLES,
    IdempotencyKind,
    TargetKind,
)
from acop.models.vocabulary import AssetType
from acop.tools.catalog.schemas import ServiceRestartIn, ServiceRestartOut
from acop.tools.contract import ApprovalPolicy, RetryPolicy, ToolDefinition
from acop.tools.registry import register

SERVICE_RESTART = register(
    ToolDefinition(
        tool_name="test.service.restart",
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
        description="Restart a simulated service. Requires approval and validation.",
        input_model=ServiceRestartIn,
        output_model=ServiceRestartOut,
        adapter_id="test.simulated",
        required_roles=frozenset({Role.OPERATOR.value}),
        target_type=TargetKind.ASSET,
        target_asset_types=frozenset({AssetType.SERVICE.value}),
        capability_tags=frozenset({"service.restart"}),
        approval_policy=ApprovalPolicy(
            approval_required=True,
            min_approvals=1,
            approver_roles=frozenset(role.value for role in APPROVAL_AUTHORITY_ROLES),
            distinct_approvers_required=False,
            ttl_seconds=3600,
            self_approval_permitted=False,
        ),
        validation_required=True,
        validation_delay_seconds=0.05,
        timeout_seconds=30.0,
        idempotency=IdempotencyKind.KEYED,
        adapter_idempotent=True,
        retry_policy=RetryPolicy(max_attempts=1),
        sensitivity=Sensitivity.INTERNAL,
    )
)

__all__ = ["SERVICE_RESTART"]
