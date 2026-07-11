"""Scan-job creation, delivery, cancellation, and status-report tests."""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.models.enums import JobStatus
from app.models.scan_job import ScanJob
from app.services.signing import get_signer
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _ready_probe(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    cidr: str = "10.20.0.0/24",
    site_code: str = "S1",
) -> dict[str, str]:
    """Enroll + approve a probe and give its site an approved scope."""
    probe = await enroll_probe(site_code=site_code, probe_name=f"p-{site_code}")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    await client.post(
        "/api/v1/scopes",
        json={"site_id": probe["site_id"], "name": "lan", "cidr": cidr},
        headers=admin_headers,
    )
    return probe


async def test_create_job_signs_and_queues(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"
    assert body["requested_targets_json"] == ["10.20.0.0/24"]


async def test_create_job_out_of_scope_rejected(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.99.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 422


async def test_create_job_requires_operator(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


async def test_create_job_requires_enrolled_probe(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    # Not approved -> still pending_enrollment.
    probe = await enroll_probe()
    await client.post(
        "/api/v1/scopes",
        json={"site_id": probe["site_id"], "name": "lan", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 409


async def test_jobs_next_delivers_signed_envelope(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.5"]},
        headers=admin_headers,
    )
    job_id = created.json()["id"]

    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/next",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert resp.status_code == 200
    envelope = resp.json()
    assert envelope["job_id"] == job_id
    assert envelope["targets"] == ["10.20.0.5/32"]
    assert get_signer().verify_document(envelope) is True

    # The job is now marked offered; a second poll returns nothing.
    again = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/next",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert again.status_code == 204


async def test_expired_job_is_not_delivered(
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
    job.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.add(job)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/next",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert resp.status_code == 204
    await db_session.refresh(job)
    assert job.status == JobStatus.EXPIRED


async def test_cancel_queued_job(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.5"]},
        headers=admin_headers,
    )
    job_id = created.json()["id"]
    cancel = await client.post(f"/api/v1/jobs/{job_id}/cancel", headers=admin_headers)
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"
    # A cancelled (queued) job is never delivered.
    poll = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/next",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert poll.status_code == 204


async def test_cancellation_appears_in_heartbeat(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.5"]},
        headers=admin_headers,
    )
    job_id = created.json()["id"]
    headers = probe_cert_headers(probe["fingerprint"])
    # Deliver the job (queued -> offered), then cancel it.
    await client.post(f"/api/v1/probes/{probe['probe_id']}/jobs/next", headers=headers)
    await client.post(f"/api/v1/jobs/{job_id}/cancel", headers=admin_headers)

    hb = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat", json={}, headers=headers
    )
    assert hb.status_code == 200
    assert job_id in hb.json()["cancellations"]


async def test_report_job_status(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.5"]},
        headers=admin_headers,
    )
    job_id = created.json()["id"]
    headers = probe_cert_headers(probe["fingerprint"])
    await client.post(f"/api/v1/probes/{probe['probe_id']}/jobs/next", headers=headers)

    for state in ("accepted", "running", "completed"):
        resp = await client.post(
            f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
            json={"status": state},
            headers=headers,
        )
        assert resp.status_code == 204

    got = await client.get(f"/api/v1/jobs/{job_id}", headers=admin_headers)
    assert got.json()["status"] == "completed"
    assert got.json()["finished_at"] is not None
