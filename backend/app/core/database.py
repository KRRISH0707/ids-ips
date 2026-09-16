from contextlib import asynccontextmanager
from typing import AsyncGenerator

import psycopg
from psycopg.rows import dict_row

from .config import get_settings

settings = get_settings()


def _build_dsn() -> str:
    return settings.db_url_psycopg


def get_sync_connection() -> psycopg.Connection:
    """Return a synchronous psycopg connection (dict row factory)."""
    return psycopg.connect(_build_dsn(), row_factory=dict_row)


@asynccontextmanager
async def get_async_connection() -> AsyncGenerator[psycopg.AsyncConnection, None]:
    """Async context-manager connection for use in FastAPI background tasks."""
    conn = await psycopg.AsyncConnection.connect(
        _build_dsn(),
        row_factory=dict_row,
    )
    try:
        yield conn
    finally:
        await conn.close()
