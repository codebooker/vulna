"""Single-host bootstrap: default site, auto-approve local Scout, component health."""

from __future__ import annotations

import uuid

from app.core.config import Settings
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import ProbeStatus
from app.models.probe import Probe
from app.models.site import Site
from app.services.bootstrap import run_bootstrap
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import generate_csr_pem


def _single_host_settings(tmp_path) -> Settings:
    return Settings(bootstrap_local_scout=True, bootstrap_dir=str(tmp_path))


async def test_bootstrap_creates_site_and_local_scout_token(
    db_session: AsyncSession, tmp_path
) -> None:
    settings = _single_host_settings(tmp_path)
    await run_bootstrap(db_session, settings)
    await db_session.commit()

    site = (
        await db_session.execute(select(Site).where(Site.code == settings.default_site_code))
    ).scalar_one()
    assert site.name == settings.default_site_name

    # The token secret is handed off via a 0600 file, not the API/UI.
    token_file = tmp_path / "local-scout-enroll.token"
    assert token_file.exists()
    assert token_file.read_text().strip()
    assert (token_file.stat().st_mode & 0o777) == 0o600

    tok = (
        await db_session.execute(
            select(EnrollmentToken).where(EnrollmentToken.auto_approve.is_(True))
        )
    ).scalar_one()
    assert tok.probe_name == settings.local_scout_name


async def test_bootstrap_is_idempotent(db_session: AsyncSession, tmp_path) -> None:
    settings = _single_host_settings(tmp_path)
    await run_bootstrap(db_session, settings)
    await run_bootstrap(db_session, settings)
    await db_session.commit()
    sites = (
        await db_session.execute(select(Site).where(Site.code == settings.default_site_code))
    ).scalars().all()
    tokens = (await db_session.execute(select(EnrollmentToken))).scalars().all()
    assert len(sites) == 1
    assert len([t for t in tokens if t.auto_approve]) == 1


async def test_auto_approve_token_enrolls_directly(
    client: AsyncClient, db_session: AsyncSession, tmp_path
) -> None:
    settings = _single_host_settings(tmp_path)
    await run_bootstrap(db_session, settings)
    await db_session.commit()
    secret = (tmp_path / "local-scout-enroll.token").read_text().strip()

    resp = await client.post(
        "/api/v1/probes/enroll", json={"token": secret, "csr_pem": generate_csr_pem()}
    )
    assert resp.status_code == 201, resp.text
    probe = await db_session.get(Probe, uuid.UUID(resp.json()["probe_id"]))
    assert probe is not None
    # Auto-approved (enrolled), but still no approved scope until the operator acts.
    assert probe.status == ProbeStatus.ENROLLED
    assert probe.approved_at is not None


async def test_disabled_by_default(db_session: AsyncSession) -> None:
    # Without the single-host flag, bootstrap creates no site or local-scout token.
    settings = Settings()  # bootstrap_local_scout defaults False
    await run_bootstrap(db_session, settings)
    await db_session.commit()
    tokens = (
        await db_session.execute(
            select(EnrollmentToken).where(EnrollmentToken.auto_approve.is_(True))
        )
    ).scalars().all()
    assert tokens == []


async def test_component_health_endpoint(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    resp = await client.get("/api/v1/system/component-health", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {
        "application",
        "database",
        "local_scout",
        "scanner_capabilities",
        "feeds",
    }
    assert body["application"] == "ok"
    assert body["database"] == "ok"
