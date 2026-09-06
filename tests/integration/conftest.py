"""Shared helpers for database-backed integration tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config

from acop.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]


async def reset_test_database(settings: Settings) -> None:
    """Remove ACOP-managed schema objects while preserving shared extensions."""
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.alembic_database_url)
    await asyncio.to_thread(command.downgrade, config, "base")
