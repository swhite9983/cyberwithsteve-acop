"""Top-level API router.

Routes are registered here, one module per domain. Section 27 of the design
brief lists the eventual API surface; Milestones 1-4 implement health, identity,
the CMDB, knowledge and the tool framework. Endpoints for incidents and changes
are added by the milestone that implements the subsystem behind them, never as
empty stubs.
"""

from __future__ import annotations

from fastapi import APIRouter

from acop.api.routes import (
    cmdb_assets,
    cmdb_facts,
    cmdb_relationships,
    health,
    identity,
    knowledge_documents,
    knowledge_search,
    knowledge_sources,
    tool_invocations,
    tools,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)
api_router.include_router(cmdb_assets.router)
api_router.include_router(cmdb_facts.router)
api_router.include_router(cmdb_relationships.router)
api_router.include_router(knowledge_sources.router)
api_router.include_router(knowledge_documents.router)
api_router.include_router(knowledge_search.router)
api_router.include_router(tools.router)
api_router.include_router(tool_invocations.router)

__all__ = ["api_router"]
