"""``test.security.rotate_key`` — Class 3, strength through policy not role.

The tool that proves the R2 correction. ``required_roles`` is ``{operator}``,
**not** ``{admin}``: an operator may *request* a high-risk change and an
approver may approve it, because clearance and approval authority are separate
axes. Making Class 3 admin-only would mean the only people who can approve
high-risk work are the people most able to bypass the control.

Class 3 strength is expressed here instead:

* ``min_approvals=2`` with ``distinct_approvers_required`` — two-person
  control, enforced by a partial unique index so the same subject cannot supply
  both approvals even if the service layer were wrong;
* a 900-second TTL, so an approval given under pressure does not sit valid for
  an hour.

``adapter_idempotent=False`` and ``max_attempts=1``: rotating a key twice
produces a second key, so there is no safe retry.
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
from acop.tools.catalog.schemas import RotateKeyIn, RotateKeyOut
from acop.tools.contract import ApprovalPolicy, RetryPolicy, ToolDefinition
from acop.tools.registry import register

ROTATE_KEY = register(
    ToolDefinition(
        tool_name="test.security.rotate_key",
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_3_HIGH_RISK_CHANGE,
        description=(
            "Rotate a simulated credential slot. Two distinct approvers required."
        ),
        input_model=RotateKeyIn,
        output_model=RotateKeyOut,
        adapter_id="test.simulated",
        # Operator, not admin. Clearance and approval authority are separate.
        required_roles=frozenset({Role.OPERATOR.value}),
        target_type=TargetKind.ASSET,
        target_asset_types=frozenset({AssetType.DEVICE.value, AssetType.HOST.value}),
        capability_tags=frozenset({"credential.rotate"}),
        approval_policy=ApprovalPolicy(
            approval_required=True,
            min_approvals=2,
            approver_roles=frozenset(role.value for role in APPROVAL_AUTHORITY_ROLES),
            distinct_approvers_required=True,
            ttl_seconds=900,
            self_approval_permitted=False,
        ),
        validation_required=True,
        validation_delay_seconds=0.0,
        timeout_seconds=20.0,
        idempotency=IdempotencyKind.KEYED,
        adapter_idempotent=False,
        retry_policy=RetryPolicy(max_attempts=1),
        sensitivity=Sensitivity.CONFIDENTIAL,
        # Explicit rather than inherited from the output model, so that adding
        # a field to RotateKeyOut is a deliberate act that must also be added
        # here before it can leave the boundary.
        output_allow_list=frozenset(
            {"asset_id", "key_slot", "key_identifier", "rotated_at"}
        ),
    )
)

__all__ = ["ROTATE_KEY"]
