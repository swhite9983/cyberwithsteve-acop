"""``acop.test.echo_metadata`` — Class 0, deliberately boring.

Its correct output is fully determined, which makes it the right instrument for
three properties that are otherwise awkward to test: that the invocation
record, the execution envelope and the HTTP response agree; that an undeclared
field such as ``api_key`` is *rejected* rather than redacted; and that envelope
canonicalisation is stable regardless of the order keys arrived in.
"""

from __future__ import annotations

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import IdempotencyKind, TargetKind
from acop.tools.catalog.schemas import EchoIn, EchoOut
from acop.tools.contract import RetryPolicy, ToolDefinition
from acop.tools.registry import register

ECHO_METADATA = register(
    ToolDefinition(
        tool_name="acop.test.echo_metadata",
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_0_INFORMATION,
        description="Return the invocation's own metadata. Changes nothing.",
        input_model=EchoIn,
        output_model=EchoOut,
        adapter_id="acop.local",
        required_roles=frozenset({Role.VIEWER.value}),
        target_type=TargetKind.NONE,
        timeout_seconds=2.0,
        idempotency=IdempotencyKind.NATURALLY_IDEMPOTENT,
        adapter_idempotent=True,
        retry_policy=RetryPolicy(max_attempts=1),
        sensitivity=Sensitivity.INTERNAL,
    )
)

__all__ = ["ECHO_METADATA"]
