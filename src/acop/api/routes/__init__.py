"""API route modules."""

from acop.api.routes import (
    cmdb_assets,
    cmdb_facts,
    cmdb_relationships,
    health,
    identity,
)

__all__ = [
    "cmdb_assets",
    "cmdb_facts",
    "cmdb_relationships",
    "health",
    "identity",
]
