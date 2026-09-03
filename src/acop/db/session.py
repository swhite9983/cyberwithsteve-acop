"""Async database engine and session management.

Async SQLAlchemy is chosen deliberately. ACOP's dominant workload is waiting:
on Ollama for tens of seconds, on Cisco devices over SSH, on Proxmox and
Prometheus HTTP APIs. A synchronous stack would need a thread pool sized to the
worst-case concurrent investigation count. Converting a synchronous data layer
to async once agents, tools and collectors exist is a rewrite; starting async
costs almost nothing today. See ``docs/decisions/ADR-0001-async-sqlalchemy.md``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.exc import DBAPIError, InterfaceError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from acop.config import Settings
from acop.core.exceptions import DatabaseUnavailableError
from acop.core.logging import get_logger

logger = get_logger(__name__)


def _is_connection_failure(exc: BaseException) -> bool:
    """Distinguish "could not reach the database" from "the database said no".

    The distinction matters because they need different responses: an
    unreachable database is an infrastructure condition (503, and the health
    endpoint will agree), while a constraint violation is a defect in ACOP
    (500, and nothing is wrong with the infrastructure).

    ``OSError`` is treated as a connection failure deliberately: asyncpg raises
    ``ConnectionRefusedError`` on a failed connect and SQLAlchemy does not wrap
    it - verified against SQLAlchemy 2.0 with asyncpg. A ``DBAPIError`` only
    counts when the connection was actually invalidated, so an
    ``IntegrityError`` is not misreported as an outage.
    """
    if isinstance(exc, (OSError, InterfaceError, PoolTimeoutError)):
        return True
    return isinstance(exc, DBAPIError) and bool(exc.connection_invalidated)


class Database:
    """Owns the engine and session factory for one application instance.

    Held on ``app.state`` rather than as a module-level global so that tests can
    create isolated instances and so a future multi-tenant or read-replica
    configuration is not blocked by a hidden singleton (section 37: avoid global
    mutable state).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine = create_async_engine(
            settings.database_url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=settings.db_pool_pre_ping,
            connect_args={
                # asyncpg names this differently to psycopg; keeping it explicit
                # avoids a health check that hangs for the OS TCP timeout when
                # the database host is unreachable.
                "timeout": settings.db_connect_timeout_seconds,
                "server_settings": {"application_name": "acop-api"},
            },
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            autoflush=False,
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session, committing on success and rolling back on error.

        Connection-level failures are translated into
        :class:`~acop.core.exceptions.DatabaseUnavailableError`. This is not
        cosmetic: SQLAlchemy does **not** wrap the driver's connection errors,
        so an unreachable PostgreSQL escapes as a bare ``OSError``
        (``ConnectionRefusedError``) with an asyncpg traceback attached. Left
        untranslated, an infrastructure condition would surface to callers as
        an unclassified 500 while ``/health`` simultaneously reported the
        database as unhealthy - two contradictory signals during an incident.
        """
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception as exc:
                await self._safe_rollback(session)
                if _is_connection_failure(exc):
                    raise DatabaseUnavailableError(
                        f"Could not reach PostgreSQL at "
                        f"{self._settings.safe_database_target}: "
                        f"{type(exc).__name__}",
                        context={"target": self._settings.safe_database_target},
                    ) from exc
                raise

    @staticmethod
    async def _safe_rollback(session: AsyncSession) -> None:
        """Roll back, tolerating a connection that is already gone.

        A rollback against a dead connection raises again and would mask the
        original error, which is the more useful one.
        """
        try:
            await session.rollback()
        except Exception:
            logger.debug("database.rollback_failed_after_error")

    async def dispose(self) -> None:
        """Close all pooled connections. Called during application shutdown."""
        await self._engine.dispose()
        logger.info("database.disposed", target=self._settings.safe_database_target)
