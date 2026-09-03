"""Top-level API router.

Routes are registered here, one module per domain. Section 27 of the design
brief lists the eventual API surface; Milestone 2 implements health, identity
and the CMDB. Endpoints for incidents, changes and tools are added by the
milestone that implements the subsystem behind them, never as empty stubs.
"""

from __future__ import annotations

from fastapi import APIRouter

from acop.api.routes import (
    cmdb_assets,
    cmdb_facts,
    cmdb_relationships,
    health,
    identity,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)
api_router.include_router(cmdb_assets.router)
api_router.include_router(cmdb_facts.router)
api_router.include_router(cmdb_relationships.router)

__all__ = ["api_router"]
