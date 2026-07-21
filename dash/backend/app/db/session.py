"""Async database engine and session management.

Exposes a FastAPI dependency (``get_session``) yielding an
``AsyncSession`` bound to a per-request transaction, plus helpers to create and
dispose of the engine over the application lifecycle.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


@event.listens_for(Session, "after_begin")
def _apply_postgres_runtime_context(
    session: Session, _transaction: object, connection: Connection
) -> None:
    """Enter the restricted PostgreSQL role for every ORM transaction.

    The migration owner remains able to perform DDL, but application sessions
    immediately ``SET LOCAL ROLE`` into a non-owner role. With no tenant in
    ``session.info`` the RLS policies expose zero rows, making a forgotten
    request-context assignment fail closed.
    """
    if connection.dialect.name != "postgresql":
        return
    maintenance = bool(session.info.get("vulna_maintenance"))
    if maintenance:
        connection.exec_driver_sql("SET LOCAL ROLE vulna_maintenance")
    else:
        connection.exec_driver_sql("SET LOCAL ROLE vulna_runtime")
    organization_id = session.info.get("vulna_organization_id")
    if not maintenance and organization_id is not None:
        connection.execute(
            text("SELECT set_config('vulna.organization_id', :organization_id, true)"),
            {"organization_id": str(organization_id)},
        )


async def set_tenant_context(session: AsyncSession, organization_id: uuid.UUID) -> None:
    """Bind this session to one tenant for its complete lifetime."""
    existing = session.info.get("vulna_organization_id")
    if session.info.get("vulna_maintenance"):
        raise RuntimeError("A maintenance session cannot become tenant-scoped")
    if existing is not None and existing != organization_id:
        raise RuntimeError("Database tenant context cannot change within a session")
    session.info["vulna_organization_id"] = organization_id
    if session.get_bind().dialect.name == "postgresql":
        # Authentication normally starts the transaction before the tenant is
        # known. Apply it now; after a commit, the after_begin hook restores it.
        await session.execute(
            text("SELECT set_config('vulna.organization_id', :organization_id, true)"),
            {"organization_id": str(organization_id)},
        )


async def set_maintenance_context(session: AsyncSession) -> None:
    """Use the explicit BYPASSRLS role for trusted aggregate maintenance."""
    if session.info.get("vulna_organization_id") is not None:
        raise RuntimeError("A tenant-scoped session cannot become maintenance-scoped")
    session.info["vulna_maintenance"] = True
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SET LOCAL ROLE vulna_maintenance"))


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
