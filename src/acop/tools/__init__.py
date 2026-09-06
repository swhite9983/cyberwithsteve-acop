"""The Milestone 4 tool framework.

Importing this package brings up the whole capability surface: adapters first
(so import rule 13 can bind), then the catalog, which registers every tool
through :func:`acop.tools.registry.register` and therefore runs all fourteen
import-time rules. A declaration that violates one fails the process here, not
a request later.
"""

from acop.tools.catalog import CATALOG
from acop.tools.contract import ApprovalPolicy, RetryPolicy, ToolDefinition
from acop.tools.registry import (
    CODE_REGISTRY,
    ToolRegistryReconciler,
    all_definitions,
    get_definition,
    register,
)

__all__ = [
    "CATALOG",
    "CODE_REGISTRY",
    "ApprovalPolicy",
    "RetryPolicy",
    "ToolDefinition",
    "ToolRegistryReconciler",
    "all_definitions",
    "get_definition",
    "register",
]
