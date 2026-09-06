"""``test.prohibited.shell_exec`` — the tool that must never run.

It exists so the prohibition mechanism is proven rather than asserted. Every
setting on it is deliberately *permissive*: admin may request it, approval is
possible, the adapter is bound. It is still denied — for viewer, operator,
approver and admin alike, at the request-time gate and again at the final
execution gate even if a defect drove it to ``APPROVED``.

``allow_registration_for_testing`` is the single escape hatch for import rule 6
and exactly one tool may carry it, asserted by a unit test. It permits
*registration*, not execution: gate 3 denies every invocation regardless, and
the adapter raises if it is ever reached.

``intent`` is prose, not a command. A field named ``command`` would be refused
by import rule 11 and this tool could not be declared at all — leaving nothing
to prove the prohibition against.
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
from acop.tools.catalog.schemas import NeverOut, ProhibitedIn
from acop.tools.contract import ApprovalPolicy, RetryPolicy, ToolDefinition
from acop.tools.registry import register

PROHIBITED_SHELL_EXEC = register(
    ToolDefinition(
        tool_name="test.prohibited.shell_exec",
        tool_version="1.0",
        permission_class=PermissionClass.PROHIBITED,
        description="Never executes. Exists to prove the prohibition mechanism.",
        input_model=ProhibitedIn,
        output_model=NeverOut,
        adapter_id="test.simulated",
        # Deliberately permissive, and still denied.
        required_roles=frozenset({Role.ADMIN.value}),
        target_type=TargetKind.ASSET,
        target_asset_types=frozenset({AssetType.HOST.value}),
        capability_tags=frozenset({"arbitrary.shell"}),
        prohibited=True,
        allow_registration_for_testing=True,
        approval_policy=ApprovalPolicy(
            approval_required=True,
            min_approvals=1,
            approver_roles=frozenset(role.value for role in APPROVAL_AUTHORITY_ROLES),
            ttl_seconds=300,
        ),
        validation_required=True,
        timeout_seconds=5.0,
        idempotency=IdempotencyKind.NON_IDEMPOTENT,
        adapter_idempotent=False,
        retry_policy=RetryPolicy(max_attempts=1),
        sensitivity=Sensitivity.CONFIDENTIAL,
    )
)

__all__ = ["PROHIBITED_SHELL_EXEC"]
