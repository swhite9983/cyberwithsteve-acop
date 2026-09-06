"""The adapter boundary: where ACOP stops and the outside world begins.

An adapter is the *only* thing in ACOP allowed to talk to something that is not
ACOP. Everything above it - policy, approval, the state machine, the audit
record - is bookkeeping about an act that happens here.

Three rules define the boundary, and they are the reason this module is tiny:

1. **An adapter receives typed, validated input and a resolved target.** It
   never receives a caller's raw request, never a command, never a network
   locator. If it needs an address, it derives one from the asset's registered
   identifiers and its own configuration - both of which are ACOP's, not the
   caller's. That is what makes server-side request forgery structurally
   impossible rather than merely unlikely.

2. **An adapter owns its credentials and never sees a caller's.** Tool input
   schemas may not carry secret-bearing fields (import rule 9), so there is no
   channel through which a credential could arrive from outside.

3. **An adapter reports an outcome, not a state.** It returns
   :class:`AdapterResult` saying what it observed. Whether that becomes
   ``EXECUTED``, ``FAILED`` or ``TIMED_OUT`` is the framework's decision, and
   the framework does not delegate it. An adapter that could set the state
   could report success for a change that did not happen.

**Registration is code-only, by construction.** :data:`ADAPTER_REGISTRY` is a
module-level dict populated by :func:`register_adapter` at import. There is no
function anywhere that resolves an adapter from a database value, which is
mechanism 1 of the Capability Binding Invariant (G5). A unit test asserts this
module imports nothing from :mod:`acop.models.tool`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from acop.models.tool_vocabulary import AdapterOutcome, TargetKind


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """What the adapter is to act on, already resolved and authorised.

    The adapter is handed identifiers ACOP looked up, not strings a caller
    supplied. ``identifiers`` carries the asset's registered external
    identifiers (M2) so an adapter can find the thing without ever being told
    where it is.
    """

    kind: TargetKind
    asset_id: uuid.UUID | None = None
    display_name: str = ""
    asset_type: str = ""
    identifiers: dict[str, str] = field(default_factory=dict)
    external_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AdapterServices:
    """ACOP's own resources, handed to an adapter that needs them.

    Deliberately narrow, and deliberately not a service locator. An adapter
    that needs to read the CMDB or report ACOP's own health gets a handle here;
    it does not import a global, and it never receives anything derived from
    the caller. Widening this is a design decision, not a convenience: every
    entry is another thing an adapter can reach.
    """

    database: Any = None
    settings: Any = None
    health: Any = None


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Everything an adapter is permitted to know about an invocation."""

    invocation_id: uuid.UUID
    tool_name: str
    tool_version: str
    target: ResolvedTarget
    #: The validated input, as a plain mapping. Guaranteed secret-free by
    #: import rule 9 and shape-checked by the tool's own Pydantic model.
    payload: dict[str, Any]
    #: Hard deadline in seconds. An adapter may finish sooner; it cannot extend
    #: this, because the dispatcher enforces it from outside with a timeout.
    timeout_seconds: float
    #: Attempt number, 1-based. Present so a naturally idempotent adapter can
    #: log a retry, never so it can behave differently on one.
    attempt: int = 1
    services: AdapterServices = field(default_factory=AdapterServices)


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """What the adapter observed.

    ``payload`` is validated against the tool's ``output_model`` and then
    sanitized before it is stored or returned. An adapter cannot widen what
    leaves the boundary by putting extra keys here.
    """

    outcome: AdapterOutcome
    payload: dict[str, Any] = field(default_factory=dict)
    #: Advisory text for a human, captured before the change. ACOP performs no
    #: automatic rollback; this is a note, not a mechanism.
    rollback_hint: dict[str, Any] = field(default_factory=dict)
    #: Internal detail for the structured log. Never persisted, never returned.
    internal_detail: str = ""


@runtime_checkable
class ToolAdapter(Protocol):
    """The contract every adapter satisfies.

    ``validate`` is a *separate observation*, not a re-read of what ``execute``
    returned. That separation is the entire reason ``EXECUTED`` and
    ``SUCCEEDED`` are different states: an adapter that validated by echoing
    its own return value would confirm nothing.
    """

    adapter_id: str

    async def execute(self, request: AdapterRequest) -> AdapterResult:
        """Perform the action. May raise; the dispatcher normalises."""
        ...

    async def validate(self, request: AdapterRequest) -> AdapterResult:
        """Observe whether the intended change is in effect."""
        ...


#: Code-only adapter registry. Populated at import; never from the database.
ADAPTER_REGISTRY: dict[str, ToolAdapter] = {}


def register_adapter(adapter: ToolAdapter) -> ToolAdapter:
    """Bind an adapter under its ``adapter_id``.

    Raises:
        ValueError: An adapter is already registered under that id. Silently
            replacing one would let import order decide which code executes.
    """
    existing = ADAPTER_REGISTRY.get(adapter.adapter_id)
    if existing is not None and existing is not adapter:
        raise ValueError(
            f"Adapter {adapter.adapter_id!r} is already registered. "
            "Import order must not decide which code executes."
        )
    ADAPTER_REGISTRY[adapter.adapter_id] = adapter
    return adapter


def resolve_adapter(adapter_id: str) -> ToolAdapter | None:
    """Return the adapter bound to ``adapter_id``, or ``None``.

    The only lookup path in ACOP, and its argument comes from a code-declared
    :class:`~acop.tools.contract.ToolDefinition` - never from a row.
    """
    return ADAPTER_REGISTRY.get(adapter_id)


__all__ = [
    "ADAPTER_REGISTRY",
    "AdapterRequest",
    "AdapterResult",
    "AdapterServices",
    "ResolvedTarget",
    "ToolAdapter",
    "register_adapter",
    "resolve_adapter",
]
