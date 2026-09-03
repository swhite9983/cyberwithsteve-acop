"""Application factory and entrypoint.

``create_app`` builds a fully wired application from a ``Settings`` instance.
Nothing is constructed at import time, so tests can build isolated applications
with different configuration and the module has no import side effects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from acop import __version__
from acop.ai.ollama import OllamaClient
from acop.api.middleware import CorrelationMiddleware, SecurityHeadersMiddleware
from acop.api.router import api_router
from acop.auth import ANONYMOUS_PRINCIPAL, ApiKeyBackend, Authenticator
from acop.config import Settings, get_settings
from acop.core.correlation import REQUEST_ID_HEADER, get_request_id
from acop.core.exceptions import AcopError
from acop.core.logging import configure_logging, get_logger
from acop.db import Database
from acop.services import HealthService

logger = get_logger(__name__)

DESCRIPTION = """
**CyberWithSteve ACOP** - Autonomous Cyber Operations Platform.

Milestone 1 (Foundation). This deployment exposes health reporting and identity
introspection only. Infrastructure integrations, agents, and any capability to
change infrastructure are introduced in later milestones and are deliberately
absent here.
"""


def _build_authenticator(settings: Settings) -> Authenticator:
    """Construct the authenticator for this deployment.

    Adding an identity provider later means appending one backend to this list.
    No endpoint, service, or persisted record changes.
    """
    backends = [
        ApiKeyBackend(settings.api_keys, header_name=settings.api_key_header),
    ]
    return Authenticator(
        backends,
        enabled=settings.auth_enabled,
        anonymous_principal=ANONYMOUS_PRINCIPAL,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ACOP application."""
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, log_format=settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Create and dispose long-lived resources.

        Startup deliberately does NOT fail when a dependency is unreachable.
        ACOP must start and then report the dependency as unhealthy, because a
        crash-looping container is far harder to diagnose than a running service
        whose health endpoint names the problem.
        """
        app.state.settings = settings
        app.state.database = Database(settings)
        app.state.ollama = OllamaClient(
            settings.ollama_base_url,
            model=settings.ollama_model,
            control_timeout=settings.ollama_control_timeout_seconds,
            generate_timeout=settings.ollama_generate_timeout_seconds,
            num_ctx=settings.ollama_num_ctx,
            keep_alive=settings.ollama_keep_alive,
        )
        app.state.authenticator = _build_authenticator(settings)
        app.state.health_service = HealthService(
            settings, app.state.database, app.state.ollama
        )

        logger.info(
            "acop.startup",
            version=__version__,
            environment=settings.environment.value,
            database_target=settings.safe_database_target,
            ollama_base_url=settings.ollama_base_url,
            ollama_model=settings.ollama_model,
            ollama_num_ctx=settings.ollama_num_ctx,
            auth_enabled=settings.auth_enabled,
            auth_backends=app.state.authenticator.backend_names,
            # Named to avoid the "api_key" fragment, which the redactor would
            # otherwise mask. The redactor is right to be aggressive; a count
            # is not a secret, so the field is renamed rather than the rule
            # weakened.
            credentials_configured=len(settings.api_keys),
        )
        if not settings.auth_enabled:
            logger.warning(
                "acop.auth.disabled",
                message=(
                    "Authentication is disabled. Every caller resolves to the "
                    "anonymous principal. Never use this outside development."
                ),
            )

        try:
            yield
        finally:
            await app.state.ollama.aclose()
            await app.state.database.dispose()
            logger.info("acop.shutdown")

    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version=__version__,
        root_path=settings.api_root_path,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    # Middleware executes in reverse registration order, so correlation is
    # registered last to make it the outermost layer - every log line emitted
    # by anything below it carries the request ID.
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=[REQUEST_ID_HEADER],
        )
    app.add_middleware(CorrelationMiddleware)

    @app.exception_handler(AcopError)
    async def _handle_acop_error(_request: Request, exc: AcopError) -> JSONResponse:
        """Translate application errors into responses.

        The response carries a stable machine-readable ``code`` and a generic
        message. The detailed cause goes to the logs, keyed by request ID, so an
        operator can find it without the API disclosing internals to the caller.
        """
        logger.warning(
            "api.error",
            code=exc.code,
            error_type=type(exc).__name__,
            detail=exc.internal_message,
            # Nested rather than splatted: a context key such as "event" would
            # otherwise collide with structlog's own field names.
            context=exc.context,
        )
        headers = {}
        if exc.http_status == 401:
            # Signal the expected credential type without naming the header's
            # configured value, which is deployment-specific.
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.public_message,
                    "request_id": get_request_id(),
                }
            },
            headers=headers,
        )

    # An unreachable database is translated to DatabaseUnavailableError in
    # acop.db.session and handled above as an AcopError (503). Other SQLAlchemy
    # errors - a constraint violation, a programming error - are defects in
    # ACOP, and fall through to the handler below as a 500. Reporting those as
    # 503 would send an operator to look at healthy infrastructure.
    @app.exception_handler(Exception)
    async def _handle_unexpected(_request: Request, exc: Exception) -> JSONResponse:
        """Last resort. Returns a correlation ID and nothing else.

        The traceback goes to the logs, keyed by request ID. An operator can
        find it; a caller cannot read internals out of the response.
        """
        logger.exception("api.unhandled_error", error_type=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An internal error occurred.",
                    "request_id": get_request_id(),
                }
            },
        )

    app.include_router(api_router)
    return app


#: Module-level application for ``uvicorn acop.main:app``.
app = create_app()
