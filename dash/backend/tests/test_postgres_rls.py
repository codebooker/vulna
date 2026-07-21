"""PostgreSQL-only release gate for runtime-role tenant isolation."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import asyncpg
import pytest
from app.core.config import Settings
from app.db.session import set_maintenance_context, set_tenant_context
from app.models.site import Site
from app.services.bootstrap import run_bootstrap
from sqlalchemy import func, literal, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

POSTGRES_URL = os.getenv("VULNA_POSTGRES_RLS_TEST_URL")

pytestmark = [
    pytest.mark.release_gate,
    pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL RLS test URL is not configured"),
]


async def test_postgres_single_host_bootstrap_enters_default_tenant(tmp_path: Path) -> None:
    assert POSTGRES_URL is not None
    unique = uuid.uuid4().hex
    async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(async_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        default_org_name="RLS Bootstrap Organization",
        default_org_slug=f"rls-bootstrap-{unique}",
        default_site_name="RLS Bootstrap Site",
        default_site_code=f"RLS-{unique[:8]}",
        bootstrap_local_scout=True,
        bootstrap_dir=str(tmp_path),
        ca_key_path=str(tmp_path / "ca-key.pem"),
        ca_cert_path=str(tmp_path / "ca-cert.pem"),
    )
    try:
        async with factory() as session:
            await run_bootstrap(session, settings)
            assert session.info["vulna_organization_id"] is not None
            site = await session.scalar(select(Site).where(Site.code == settings.default_site_code))
            assert site is not None
            assert site.organization_id == session.info["vulna_organization_id"]
            await session.rollback()
    finally:
        await engine.dispose()


async def test_postgres_runtime_role_fails_closed_and_isolates_tenants() -> None:
    assert POSTGRES_URL is not None
    organization_one = uuid.uuid4()
    organization_two = uuid.uuid4()
    site_one = uuid.uuid4()
    site_two = uuid.uuid4()

    owner = await asyncpg.connect(POSTGRES_URL)
    try:
        await owner.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES ($1, 'RLS Org One', $2, 'UTC', '{}', '{}'),
                   ($3, 'RLS Org Two', $4, 'UTC', '{}', '{}')
            """,
            organization_one,
            f"rls-one-{organization_one.hex}",
            organization_two,
            f"rls-two-{organization_two.hex}",
        )
        await owner.execute(
            """
            INSERT INTO sites (id, organization_id, name, code, timezone, tags)
            VALUES ($1, $2, 'Site One', 'ONE', 'UTC', '[]'),
                   ($3, $4, 'Site Two', 'TWO', 'UTC', '[]')
            """,
            site_one,
            organization_one,
            site_two,
            organization_two,
        )

        async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        engine = create_async_engine(async_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                # The restricted runtime role is entered automatically. Without
                # an organization setting, protected tables expose no rows.
                assert await session.scalar(select(func.count()).select_from(Site)) == 0
                await set_tenant_context(session, organization_one)
                assert await session.scalar(select(func.count()).select_from(Site)) == 1
                assert await session.get(Site, site_two) is None
                await session.commit()
                # SET LOCAL is restored from session.info after every commit.
                assert await session.scalar(select(func.count()).select_from(Site)) == 1

            async with factory() as session:
                await set_tenant_context(session, organization_one)
                session.add(
                    Site(
                        id=uuid.uuid4(),
                        organization_id=organization_two,
                        name="Cross-tenant write",
                        code="DENY",
                        timezone="UTC",
                    )
                )
                with pytest.raises(DBAPIError):
                    await session.flush()

            async with factory() as session:
                # Worker sessions may discover a global maintenance task before
                # switching roles, so exercise the in-transaction transition.
                assert await session.scalar(select(literal(1))) == 1
                await set_maintenance_context(session)
                assert await session.scalar(select(func.count()).select_from(Site)) == 2
        finally:
            await engine.dispose()

        role = await owner.fetchrow(
            """
            SELECT rolsuper, rolbypassrls, rolcanlogin
              FROM pg_roles
             WHERE rolname = 'vulna_runtime'
            """
        )
        assert role is not None
        assert tuple(role) == (False, False, False)
        assert (
            await owner.fetchval(
                "SELECT COUNT(*) FROM pg_policies WHERE policyname = 'vulna_tenant_isolation'"
            )
            >= 40
        )
    finally:
        await owner.execute(
            "DELETE FROM organizations WHERE id = ANY($1::uuid[])",
            [organization_one, organization_two],
        )
        await owner.close()
