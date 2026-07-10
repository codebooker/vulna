"""Shared pytest fixtures for the VulnaDash backend.

Tests run against an in-memory SQLite database using a ``StaticPool`` so the
schema and data persist for the lifetime of a single test, all within the
test's event loop. The FastAPI ``get_session`` dependency is overridden to bind
to that database, so no PostgreSQL instance is required.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable

# A signing secret must exist before any settings are loaded. This is a test-only
# value and is never used outside the suite.
os.environ.setdefault("VULNA_SECRET_KEY", "test-only-secret-do-not-use-in-production")

import app.models  # noqa: F401  (register models on the metadata)
import pytest
import pytest_asyncio
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import get_session
from app.main import create_app
from app.models.enums import UserRole
from app.models.organization import Organization
from app.models.user import User
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

TEST_PASSWORD = "correct horse battery staple"


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """A fresh in-memory SQLite engine with the full schema created."""
    eng = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@pytest_asyncio.fixture
async def db_session(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """A session for arranging and inspecting database state directly in tests."""
    async with sessionmaker() as session:
        yield session


@pytest_asyncio.fixture
async def client(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """An HTTP client bound to the app with the DB dependency overridden.

    The ASGI transport does not run the application lifespan, so startup
    bootstrap/table-creation is handled by the ``engine`` fixture instead.
    """
    application = create_app()

    async def override_get_session() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    application.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


@pytest_asyncio.fixture
async def organization(db_session: AsyncSession) -> Organization:
    """A default organization to own test users and resources."""
    org = Organization(name="Test Org", slug="test-org", default_timezone="UTC")
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


UserFactory = Callable[..., Awaitable[User]]


@pytest_asyncio.fixture
async def make_user(db_session: AsyncSession, organization: Organization) -> UserFactory:
    """Factory fixture that creates a user with a given role."""
    counter = {"n": 0}

    async def _make(
        role: UserRole = UserRole.VIEWER,
        *,
        email: str | None = None,
        password: str = TEST_PASSWORD,
        is_active: bool = True,
    ) -> User:
        counter["n"] += 1
        user = User(
            organization_id=organization.id,
            email=email or f"user{counter['n']}@example.com",
            hashed_password=hash_password(password),
            full_name=f"User {counter['n']}",
            role=role,
            is_active=is_active,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _make


def auth_headers(user: User) -> dict[str, str]:
    """Build an Authorization header carrying a valid token for ``user``."""
    token = create_access_token(
        get_settings(),
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin(make_user: UserFactory) -> User:
    return await make_user(UserRole.ADMINISTRATOR)


@pytest_asyncio.fixture
async def viewer(make_user: UserFactory) -> User:
    return await make_user(UserRole.VIEWER)


@pytest.fixture
def admin_headers(admin: User) -> dict[str, str]:
    return auth_headers(admin)


@pytest.fixture
def viewer_headers(viewer: User) -> dict[str, str]:
    return auth_headers(viewer)
