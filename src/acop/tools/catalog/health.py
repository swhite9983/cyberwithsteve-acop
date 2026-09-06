"""``acop.system.health`` — Class 0, ACOP reporting on itself.

The simplest possible real tool, and the one that proves the framework against
something that genuinely does work rather than a stub returning a constant.
Class 0 and ``TargetKind.NONE`` coincide by import rule 7: nothing outside ACOP
is touched, so there is nothing to name as a target.
"""

from __future__ import annotations

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import IdempotencyKind, TargetKind
from acop.tools.catalog.schemas import EmptyInput, HealthSummaryOut
from acop.tools.contract import RetryPolicy, ToolDefinition
from acop.tools.registry import register

SYSTEM_HEALTH = register(
    ToolDefinition(
        tool_name="acop.system.health",
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_0_INFORMATION,
        description="Report ACOP's own health and the status of its dependencies.",
        input_model=EmptyInput,
        output_model=HealthSummaryOut,
        adapter_id="acop.local",
        required_roles=frozenset({Role.VIEWER.value}),
        target_type=TargetKind.NONE,
        timeout_seconds=5.0,
        idempotency=IdempotencyKind.NATURALLY_IDEMPOTENT,
        adapter_idempotent=True,
        # Two attempts because a health probe that lost a connection tells you
        # about the connection, not about health.
        retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=0.5),
        sensitivity=Sensitivity.INTERNAL,
    )
)

__all__ = ["SYSTEM_HEALTH"]
