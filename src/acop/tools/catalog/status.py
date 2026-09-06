"""``test.device.status`` — Class 1, read-only, against the real CMDB.

Reads Milestone 2 inventory rather than inventing a reply, so the Class 1 path
is proven against real data: a retired asset or one of the wrong type produces
a genuine ``INVALID_TARGET`` from the policy engine instead of a fabricated
success from the adapter.

``required_roles`` is ``{viewer}`` — the class minimum — because reading
whether a device answers is not a privileged act. The tool could raise it; it
does not need to.
"""

from __future__ import annotations

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import IdempotencyKind, TargetKind, ToolErrorCategory
from acop.models.vocabulary import AssetType
from acop.tools.catalog.schemas import DeviceStatusIn, DeviceStatusOut
from acop.tools.contract import RetryPolicy, ToolDefinition
from acop.tools.registry import register

DEVICE_STATUS = register(
    ToolDefinition(
        tool_name="test.device.status",
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_1_READ_ONLY,
        description="Report an asset's reachability and, optionally, its known facts.",
        input_model=DeviceStatusIn,
        output_model=DeviceStatusOut,
        adapter_id="test.simulated",
        required_roles=frozenset({Role.VIEWER.value}),
        target_type=TargetKind.ASSET,
        target_asset_types=frozenset(
            {
                AssetType.DEVICE.value,
                AssetType.HOST.value,
                AssetType.VM.value,
                AssetType.SERVICE.value,
            }
        ),
        timeout_seconds=10.0,
        idempotency=IdempotencyKind.NATURALLY_IDEMPOTENT,
        adapter_idempotent=True,
        retry_policy=RetryPolicy(
            max_attempts=2,
            retry_on=frozenset(
                {
                    ToolErrorCategory.ADAPTER_UNAVAILABLE,
                    ToolErrorCategory.TARGET_UNAVAILABLE,
                }
            ),
        ),
        sensitivity=Sensitivity.INTERNAL,
    )
)

__all__ = ["DEVICE_STATUS"]
