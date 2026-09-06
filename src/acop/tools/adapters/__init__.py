"""Adapters — the boundary between ACOP and everything else.

Importing this package registers every adapter, which must happen *before* the
catalog is imported: import rule 13 refuses a declaration whose adapter does
not resolve, and that check is the point at which a mis-bound tool becomes a
failed build rather than a runtime surprise.
"""

from acop.tools.adapters.base import (
    ADAPTER_REGISTRY,
    AdapterRequest,
    AdapterResult,
    AdapterServices,
    ResolvedTarget,
    ToolAdapter,
    register_adapter,
    resolve_adapter,
)
from acop.tools.adapters.local import LOCAL_ADAPTER, LocalAdapter
from acop.tools.adapters.simulated import (
    SIM_SLOW,
    SIM_STAYS_DOWN,
    SIM_UNREACHABLE,
    SIMULATED_ADAPTER,
    SimulatedAdapter,
    reset_simulation,
    simulated_state,
)

__all__ = [
    "ADAPTER_REGISTRY",
    "LOCAL_ADAPTER",
    "SIMULATED_ADAPTER",
    "SIM_SLOW",
    "SIM_STAYS_DOWN",
    "SIM_UNREACHABLE",
    "AdapterRequest",
    "AdapterResult",
    "AdapterServices",
    "LocalAdapter",
    "ResolvedTarget",
    "SimulatedAdapter",
    "ToolAdapter",
    "register_adapter",
    "reset_simulation",
    "resolve_adapter",
    "simulated_state",
]
