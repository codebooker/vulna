"""Timeout reaper: stale scan jobs expire and unblock a waiting workflow."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.models.enums import JobStatus
from app.models.scan_job import ScanJob
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers, start_job_attempt

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _ready_probe(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> dict[str, str]:
    probe = await enroll_probe(site_code="RP", probe_name="rp")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    await client.post(
        "/api/v1/scopes",
        json={"site_id": probe["site_id"], "name": "lan", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    return probe


async def test_reap_endpoint_expires_overdue_job_and_fails_workflow(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    run_id = (
        await client.post(
            "/api/v1/workflows", json={"site_id": probe["site_id"]}, headers=admin_headers
        )
    ).json()["id"]
    # Advance the precheck -> dispatches the discovery job the run now waits on.
    job_id = (
        await client.post(
            f"/api/v1/workflows/{run_id}/advance",
            json={"outcome": "completed"},
            headers=admin_headers,
        )
    ).json()["scan_job_id"]
    assert job_id is not None

    # Simulate the scout stalling: push the job's deadline into the past.
    job = await db_session.get(ScanJob, uuid.UUID(job_id))
    job.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    reaped = await client.post("/api/v1/jobs/reap", headers=admin_headers)
    assert reaped.status_code == 200 and reaped.json()["reaped"] == 1

    await db_session.refresh(job)
    assert job.status == JobStatus.EXPIRED
    assert job.error_code == "timeout"

    # The workflow's discovery stage failed and the run moved on to its tail.
    detail = (await client.get(f"/api/v1/workflows/{run_id}", headers=admin_headers)).json()
    stages = {s["name"]: s["status"] for s in detail["stages_json"]}
    assert stages["discovery"] == "failed"
    active = {"running", "awaiting_approval"}
    current = next((s["name"] for s in detail["stages_json"] if s["status"] in active), None)
    assert current == "verification_scan"


async def test_reap_leaves_live_jobs_untouched(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert created.status_code == 201
    reaped = await client.post("/api/v1/jobs/reap", headers=admin_headers)
    assert reaped.json()["reaped"] == 0  # well within its deadline


async def test_reap_uses_signed_execution_limit_and_acknowledges_late_terminal_report(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.5"]},
        headers=admin_headers,
    )
    job = await db_session.get(ScanJob, uuid.UUID(created.json()["id"]))
    assert job is not None
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == str(job.id)

    now = datetime.now(UTC)
    job.status = JobStatus.RUNNING
    job.accepted_at = now - timedelta(minutes=3)
    job.started_at = now - timedelta(minutes=2)
    job.expires_at = now + timedelta(hours=1)
    job.limits_json = {**job.limits_json, "max_duration_seconds": 60}
    await db_session.commit()

    # The Scout gets one offline-detection window to publish its own terminal
    # outcome after enforcing the hard execution deadline locally.
    grace = await client.post("/api/v1/jobs/reap", headers=admin_headers)
    assert grace.status_code == 200 and grace.json()["reaped"] == 0
    await db_session.refresh(job)
    assert job.status == JobStatus.RUNNING

    job.accepted_at = now - timedelta(minutes=6)
    job.started_at = now - timedelta(minutes=5)
    await db_session.commit()
    reaped = await client.post("/api/v1/jobs/reap", headers=admin_headers)
    assert reaped.status_code == 200 and reaped.json()["reaped"] == 1
    await db_session.refresh(job)
    assert job.status == JobStatus.EXPIRED
    assert job.error_code == "max_duration_exceeded"

    # The reaper may win a narrow race with the Scout's own deadline handler.
    # Acknowledge that late terminal report while retaining the published expiry.
    late = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job.id}/status",
        json={"status": "cancelled", "error_code": "max_duration_exceeded"},
        headers={**probe_cert_headers(probe["fingerprint"]), **attempt_headers},
    )
    assert late.status_code == 204
    await db_session.refresh(job)
    assert job.status == JobStatus.EXPIRED
