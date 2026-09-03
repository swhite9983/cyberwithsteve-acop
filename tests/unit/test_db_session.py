"""Database error classification.

The distinction tested here is the one that determines whether an operator is
sent to look at infrastructure or at ACOP's own code, so it is worth pinning
down rather than leaving to whichever exception happens to escape.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    InterfaceError,
    ProgrammingError,
)
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from acop.config import Settings
from acop.core.exceptions import DatabaseUnavailableError, DependencyUnavailableError
from acop.db import Database
from acop.db.session import _is_connection_failure


class TestConnectionFailureClassification:
    def test_connection_refused_is_a_connection_failure(self) -> None:
        # asyncpg raises this bare; SQLAlchemy does not wrap it. Verified
        # against SQLAlchemy 2.0 + asyncpg - if this ever changes, an
        # unreachable database silently becomes an unclassified 500 again.
        assert _is_connection_failure(ConnectionRefusedError(111, "refused"))

    def test_os_error_is_a_connection_failure(self) -> None:
        assert _is_connection_failure(OSError("network unreachable"))

    def test_interface_error_is_a_connection_failure(self) -> None:
        assert _is_connection_failure(InterfaceError("stmt", None, Exception()))

    def test_pool_timeout_is_a_connection_failure(self) -> None:
        assert _is_connection_failure(PoolTimeoutError("pool exhausted"))

    def test_integrity_error_is_not_a_connection_failure(self) -> None:
        # A constraint violation is an ACOP defect, not an outage. Reporting it
        # as 503 would send an operator to inspect healthy infrastructure.
        error = IntegrityError("INSERT ...", None, Exception("duplicate key"))
        assert not _is_connection_failure(error)

    def test_programming_error_is_not_a_connection_failure(self) -> None:
        error = ProgrammingError("SELECT ...", None, Exception("no such column"))
        assert not _is_connection_failure(error)

    def test_invalidated_dbapi_error_is_a_connection_failure(self) -> None:
        error = DBAPIError("SELECT 1", None, Exception("server closed"))
        error.connection_invalidated = True
        assert _is_connection_failure(error)

    def test_value_error_is_not_a_connection_failure(self) -> None:
        assert not _is_connection_failure(ValueError("unrelated"))


class TestSessionTranslation:
    async def test_unreachable_database_raises_a_typed_error(
        self, offline_settings: Settings
    ) -> None:
        from sqlalchemy import text

        database = Database(offline_settings)
        try:
            with pytest.raises(DatabaseUnavailableError) as excinfo:
                async with database.session() as session:
                    await session.execute(text("SELECT 1"))
        finally:
            await database.dispose()

        # 503, so it agrees with what /health reports at the same moment.
        assert excinfo.value.http_status == 503
        assert excinfo.value.code == "database_unavailable"
        assert isinstance(excinfo.value, DependencyUnavailableError)

    async def test_error_message_carries_no_credentials(self, make_settings) -> None:
        from sqlalchemy import text

        # Distinctive canary, so this cannot pass by coincidence.
        canary = "LEAK-CANARY-4a81de03"
        database = Database(make_settings(postgres_port=1, postgres_password=canary))
        try:
            with pytest.raises(DatabaseUnavailableError) as excinfo:
                async with database.session() as session:
                    await session.execute(text("SELECT 1"))
        finally:
            await database.dispose()

        rendered = excinfo.value.internal_message + str(excinfo.value.context)
        assert canary not in rendered
