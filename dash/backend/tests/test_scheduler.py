"""Scheduled scans: due-sweep fires a job and rolls the next run forward."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.models.scan_job import ScanJob  # noqa: E402
from app.models.scan_schedule import ScanSchedule
from app.services.scheduler import run_due_schedules
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _network_with_scout(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> dict[str, str]:
    probe = await enroll_probe(site_code="SCH", probe_name="sch")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Scheduled net",
                "ranges": [{"cidr": "10.20.0.0/24"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()
    return {"network_id": net["id"], **probe}


async def test_create_and_run_now(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    ctx = await _network_with_scout(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/schedules",
        json={"network_id": ctx["network_id"], "name": "Nightly", "interval_minutes": 1440},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    sid = created.json()["id"]

    run = await client.post(f"/api/v1/schedules/{sid}/run", headers=admin_headers)
    assert run.status_code == 200
    assert run.json()["last_job_id"] is not None
    assert run.json()["last_error"] is None


async def test_run_now_without_scout_reports_error(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    # A network with a range but no bound scout cannot dispatch.
    probe = await enroll_probe(site_code="NOSCOUT", probe_name="ns")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Orphan",
                "ranges": [{"cidr": "10.20.0.0/24"}],
            },
            headers=admin_headers,
        )
    ).json()
    sid = (
        await client.post(
            "/api/v1/schedules",
            json={"network_id": net["id"], "name": "x", "interval_minutes": 60},
            headers=admin_headers,
        )
    ).json()["id"]
    run = await client.post(f"/api/v1/schedules/{sid}/run", headers=admin_headers)
    assert run.status_code == 409
    assert "scout" in run.json()["detail"].lower()


async def test_run_now_skipped_while_network_under_test(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    ctx = await _network_with_scout(client, admin_headers, enroll_probe)
    sid = (
        await client.post(
            "/api/v1/schedules",
            json={"network_id": ctx["network_id"], "name": "S", "interval_minutes": 60},
            headers=admin_headers,
        )
    ).json()["id"]
    # First run creates an active (queued) job for the network.
    first = await client.post(f"/api/v1/schedules/{sid}/run", headers=admin_headers)
    assert first.status_code == 200 and first.json()["last_job_id"] is not None
    # Second run is refused: the network is already under test (no double-testing).
    second = await client.post(f"/api/v1/schedules/{sid}/run", headers=admin_headers)
    assert second.status_code == 409
    assert "under test" in second.json()["detail"].lower()


async def test_due_sweep_fires_and_advances(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    ctx = await _network_with_scout(client, admin_headers, enroll_probe)
    sid = (
        await client.post(
            "/api/v1/schedules",
            json={"network_id": ctx["network_id"], "name": "Every30", "interval_minutes": 30},
            headers=admin_headers,
        )
    ).json()["id"]

    # Make it due, then sweep.
    sched = await db_session.get(ScanSchedule, uuid.UUID(sid))
    due_at = datetime.now(UTC) - timedelta(minutes=1)
    sched.next_run_at = due_at
    await db_session.commit()

    fired = await run_due_schedules(db_session, get_settings())
    await db_session.commit()
    assert fired == 1

    await db_session.refresh(sched)
    # A job was created and the next run rolled forward past now.
    assert sched.last_job_id is not None
    next_run = sched.next_run_at
    if next_run.tzinfo is None:
        next_run = next_run.replace(tzinfo=UTC)  # SQLite returns naive datetimes
    assert next_run > datetime.now(UTC)
    jobs = await db_session.scalar(
        select(func.count()).select_from(ScanJob).where(ScanJob.id == sched.last_job_id)
    )
    assert jobs == 1

    # Not due anymore -> a second sweep fires nothing.
    assert await run_due_schedules(db_session, get_settings()) == 0
