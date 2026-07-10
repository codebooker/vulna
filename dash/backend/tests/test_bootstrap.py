"""Administrator-bootstrap tests."""

from __future__ import annotations

from app.core.config import get_settings
from app.models.enums import UserRole
from app.models.organization import Organization
from app.models.user import User
from app.services.bootstrap import (
    ensure_bootstrap_admin,
    ensure_default_organization,
    run_bootstrap,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def test_ensure_default_organization_is_idempotent(db_session: AsyncSession) -> None:
    settings = get_settings()
    org1 = await ensure_default_organization(db_session, settings)
    await db_session.commit()
    org2 = await ensure_default_organization(db_session, settings)
    await db_session.commit()
    assert org1.id == org2.id
    count = await db_session.scalar(
        select(func.count()).select_from(Organization).where(
            Organization.slug == settings.default_org_slug
        )
    )
    assert count == 1


async def test_bootstrap_admin_created_from_settings(db_session: AsyncSession) -> None:
    settings = get_settings().model_copy(
        update={
            "bootstrap_admin_email": "boot@example.com",
            "bootstrap_admin_password": "a-very-strong-password",
        }
    )
    admin = await ensure_bootstrap_admin(db_session, settings)
    await db_session.commit()
    assert admin is not None
    assert admin.role == UserRole.ADMINISTRATOR
    assert admin.email == "boot@example.com"
    assert admin.hashed_password != "a-very-strong-password"  # stored hashed


async def test_bootstrap_admin_not_created_without_credentials(
    db_session: AsyncSession,
) -> None:
    settings = get_settings().model_copy(
        update={"bootstrap_admin_email": None, "bootstrap_admin_password": None}
    )
    admin = await ensure_bootstrap_admin(db_session, settings)
    assert admin is None


async def test_bootstrap_admin_is_idempotent(db_session: AsyncSession) -> None:
    settings = get_settings().model_copy(
        update={
            "bootstrap_admin_email": "boot@example.com",
            "bootstrap_admin_password": "a-very-strong-password",
        }
    )
    await run_bootstrap(db_session, settings)
    await db_session.commit()
    # Second run must not create a second admin.
    second = await ensure_bootstrap_admin(db_session, settings)
    await db_session.commit()
    assert second is None
    admin_count = await db_session.scalar(
        select(func.count()).select_from(User).where(User.role == UserRole.ADMINISTRATOR)
    )
    assert admin_count == 1
