"""FastAPI dependencies.

Shared, expensive objects (the database engine, the Ollama HTTP client, the
authenticator) are created once during application startup and stored on
``app.state``. These dependencies read them from there rather than
instantiating module-level singletons, so tests can build an isolated
application and nothing holds global mutable state.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from acop.ai.ollama import OllamaClient
from acop.api.transaction import bind_request_session, unbind_request_session
from acop.auth import Authenticator, PresentedCredentials, Principal, Role
from acop.config import Settings
from acop.core.exceptions import AuthenticationError, AuthorizationError
from acop.db import Database
from acop.services import (
    AssetService,
    AuditService,
    FactService,
    HealthService,
    IdentityResolver,
    RelationshipService,
)
from acop.services.knowledge import (
    AssetMentionService,
    DocumentScreen,
    EmbeddingProvider,
    EmbeddingSpaceService,
    KnowledgeCatalogService,
    KnowledgeIngestService,
    KnowledgeRetrievalService,
    OllamaEmbeddingProvider,
    RetrievalConfig,
)


def get_settings_dep(request: Request) -> Settings:
    """Return the application settings."""
    # Starlette's app.state is untyped; cast once here so every call site
    # downstream is properly typed.
    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    """Return the application database handle."""
    # Starlette's app.state is untyped; cast once here so every call site
    # downstream is properly typed.
    return cast(Database, request.app.state.database)


def get_ollama(request: Request) -> OllamaClient:
    """Return the shared Ollama client."""
    # Starlette's app.state is untyped; cast once here so every call site
    # downstream is properly typed.
    return cast(OllamaClient, request.app.state.ollama)


def get_health_service(request: Request) -> HealthService:
    """Return the health service."""
    # Starlette's app.state is untyped; cast once here so every call site
    # downstream is properly typed.
    return cast(HealthService, request.app.state.health_service)


def get_authenticator(request: Request) -> Authenticator:
    """Return the authenticator."""
    # Starlette's app.state is untyped; cast once here so every call site
    # downstream is properly typed.
    return cast(Authenticator, request.app.state.authenticator)


async def get_session(
    database: Annotated[Database, Depends(get_database)],
) -> AsyncIterator[AsyncSession]:
    """Yield the request's database session.

    The transaction is **not** committed here. FastAPI unwinds the exit stack
    holding this dependency's teardown after the response has been sent, so a
    commit placed here is not guaranteed to have happened when the client reads
    the status code. :class:`acop.api.transaction.TransactionalRoute` commits
    instead, inside the endpoint call - see that module for the measurement
    that forced this.

    Publishing the session on a context variable is what lets the route wrapper
    reach it: the wrapper receives only the endpoint's solved arguments, and
    not every endpoint declares a session.
    """
    async with database.request_transaction() as session:
        tokens = bind_request_session(session)
        try:
            yield session
        finally:
            unbind_request_session(tokens)


def get_audit_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AuditService:
    """Return an audit service bound to the request's session.

    The database handle is supplied as well so a denial can be written outside
    that session. A refused request is rolled back, and a denial recorded
    inside it would be rolled back with it.
    """
    return AuditService(session, database=database)


def _presented_credentials(request: Request) -> PresentedCredentials:
    """Extract credential material from the request without leaking framework types."""
    client_host = request.client.host if request.client else None
    # X-Forwarded-For is recorded but not trusted for authorisation. It is
    # attacker-controlled unless a trusted proxy overwrites it; treating it as
    # evidence rather than fact is the correct posture until a proxy contract
    # exists.
    forwarded = request.headers.get("X-Forwarded-For")
    source = forwarded.split(",")[0].strip() if forwarded else client_host
    return PresentedCredentials(
        headers=dict(request.headers),
        source_address=(source or None) and source[:64],
        user_agent=request.headers.get("User-Agent"),
    )


async def get_principal(
    request: Request,
    authenticator: Annotated[Authenticator, Depends(get_authenticator)],
) -> Principal:
    """Authenticate the caller and return the resulting principal.

    Raises:
        AuthenticationError: Translated to HTTP 401 by the application's
            exception handler.
    """
    credentials = _presented_credentials(request)
    principal = await authenticator.authenticate(credentials)
    request.state.principal = principal
    request.state.source_address = credentials.source_address
    request.state.user_agent = credentials.user_agent
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_roles(
    *roles: str | Role,
) -> Callable[[Principal], Awaitable[Principal]]:
    """Build a dependency requiring at least one of ``roles``.

    Returns the dependency *callable*, which is then wrapped in an
    ``Annotated`` alias (see below). The earlier form returned ``Depends(...)``
    typed as ``object`` and was meant to be used as a parameter default: that
    does not typecheck under mypy strict, and ruff rejects a call in an
    argument default (B008). Milestone 2 is the first consumer, so it is fixed
    here rather than worked around.

    Role checks stay coarse. Fine-grained authorisation is a property of the
    tool registry (Milestone 4), where a permission class attaches to each
    individual operation; duplicating that at the HTTP layer would create two
    sources of truth.
    """
    required = tuple(role.value if isinstance(role, Role) else role for role in roles)

    async def _dependency(principal: CurrentPrincipal) -> Principal:
        if required and not principal.has_any_role(*required):
            raise AuthorizationError(
                f"Principal {principal.subject!r} lacks any of {required}",
                context={"required_roles": list(required)},
            )
        return principal

    return _dependency


#: Role-scoped identity aliases. Declared once, reused by every route, so the
#: authorisation requirement is visible in the signature.
ViewerPrincipal = Annotated[
    Principal,
    Depends(require_roles(Role.VIEWER, Role.OPERATOR, Role.APPROVER, Role.ADMIN)),
]
OperatorPrincipal = Annotated[
    Principal, Depends(require_roles(Role.OPERATOR, Role.ADMIN))
]
ApproverPrincipal = Annotated[
    Principal, Depends(require_roles(Role.APPROVER, Role.ADMIN))
]


# ---------------------------------------------------------------------------
# CMDB services
# ---------------------------------------------------------------------------
def get_asset_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AssetService:
    """Return an asset service bound to the request's session."""
    return AssetService(session)


def get_identity_resolver(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IdentityResolver:
    """Return an identity resolver bound to the request's session."""
    return IdentityResolver(session)


def get_fact_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FactService:
    """Return a fact service bound to the request's session."""
    return FactService(session)


def get_relationship_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RelationshipService:
    """Return a relationship service bound to the request's session."""
    return RelationshipService(session)


# ---------------------------------------------------------------------------
# Knowledge services (Milestone 3)
# ---------------------------------------------------------------------------
def get_embedding_provider(
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> EmbeddingProvider:
    """Return the configured embedding provider.

    Constructed per request rather than held on ``app.state`` because it owns
    no pooled resource - it opens an HTTP client per call and closes it. The
    production wiring only ever builds the Ollama provider; the deterministic
    one exists for tests and is never reachable from here.
    """
    return OllamaEmbeddingProvider(
        settings.knowledge_embedding_base_url,
        settings.knowledge_embedding_model,
        timeout_seconds=settings.knowledge_embedding_timeout_seconds,
        normalize=settings.knowledge_embedding_normalize,
        expected_dimensions=settings.knowledge_embedding_dimensions,
    )


def get_document_screen(
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> DocumentScreen:
    """Return the screening detector set, keyed with the deployment's salt."""
    return DocumentScreen(settings.knowledge_fingerprint_salt.get_secret_value())


def get_retrieval_config(
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> RetrievalConfig:
    return RetrievalConfig(
        k=settings.knowledge_retrieval_k,
        ann_overfetch=settings.knowledge_ann_overfetch,
        ann_candidate_cap=settings.knowledge_ann_candidate_cap,
        hnsw_ef_search=settings.knowledge_hnsw_ef_search,
        hnsw_iterative_scan=settings.knowledge_hnsw_iterative_scan,
        exact_fallback_enabled=settings.knowledge_exact_fallback_enabled,
        exact_max_rows=settings.knowledge_exact_max_rows,
        exact_timeout_ms=settings.knowledge_exact_timeout_ms,
        lexical_limit=settings.knowledge_lexical_limit,
    )


def get_embedding_space_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EmbeddingSpaceService:
    return EmbeddingSpaceService(session)


def get_knowledge_catalog_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> KnowledgeCatalogService:
    return KnowledgeCatalogService(session)


def get_knowledge_ingest_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    database: Annotated[Database, Depends(get_database)],
    screen: Annotated[DocumentScreen, Depends(get_document_screen)],
    embedder: Annotated[EmbeddingProvider, Depends(get_embedding_provider)],
) -> KnowledgeIngestService:
    """Return the ingest service.

    The database handle is supplied as well as the session because a *failed*
    attempt has to record itself outside the request transaction that is about
    to be rolled back - the same mechanism as ``AuditService.record_denial``.
    """
    return KnowledgeIngestService(
        session, screen=screen, embedder=embedder, database=database
    )


def get_knowledge_retrieval_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    embedder: Annotated[EmbeddingProvider, Depends(get_embedding_provider)],
    config: Annotated[RetrievalConfig, Depends(get_retrieval_config)],
) -> KnowledgeRetrievalService:
    return KnowledgeRetrievalService(session, embedder=embedder, config=config)


def get_asset_mention_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AssetMentionService:
    return AssetMentionService(session)


__all__ = [
    "ApproverPrincipal",
    "AuthenticationError",
    "CurrentPrincipal",
    "OperatorPrincipal",
    "ViewerPrincipal",
    "get_asset_mention_service",
    "get_asset_service",
    "get_audit_service",
    "get_authenticator",
    "get_database",
    "get_document_screen",
    "get_embedding_provider",
    "get_embedding_space_service",
    "get_fact_service",
    "get_health_service",
    "get_identity_resolver",
    "get_knowledge_catalog_service",
    "get_knowledge_ingest_service",
    "get_knowledge_retrieval_service",
    "get_ollama",
    "get_principal",
    "get_relationship_service",
    "get_retrieval_config",
    "get_session",
    "get_settings_dep",
    "require_roles",
]
