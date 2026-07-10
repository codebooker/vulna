"""Async database engine and session management.

Exposes a FastAPI dependency (``get_session``) yielding an
``AsyncSession`` bound to a per-request transaction, plus helpers to create and
dispose of the engine over the application lifecycle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _build_engine(settings: Settings) -> AsyncEngine:
    url = settings.sqlalchemy_database_uri
    connect_args: dict[str, object] = {}
    # aiosqlite needs a few tweaks so an in-memory/shared test DB behaves.
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_async_engine(
        url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )


def get_engine() -> AsyncEngine:
    """Return the process-wide async engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = _build_engine(get_settings())
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide async session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session wrapped in a transaction.

    The transaction is committed on success and rolled back on any exception,
    so route handlers and services never need to manage commit/rollback
    boundaries themselves.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Dispose of the engine and reset module state (used at shutdown/tests)."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
