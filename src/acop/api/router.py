"""Top-level API router.

Routes are registered here, one module per domain. Section 27 of the design
brief lists the eventual API surface; Milestone 1 deliberately implements only
health and identity. Endpoints for assets, incidents, changes and tools are
added by the milestone that implements the subsystem behind them, never as
empty stubs.
"""

from __future__ import annotations

from fastapi import APIRouter

from acop.api.routes import health, identity

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)

__all__ = ["api_router"]
