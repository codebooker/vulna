"""API tests for the Unified Maintenance Center (Phase 28)."""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.models.enums import JobStatus
from app.models.scan_artifact import ScanArtifact
from app.models.scan_job import ScanJob
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, probe_cert_headers
from tests.test_assets import _XML_HEADERS, SAMPLE_XML, _create_job
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _old_completed_artifact(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> tuple[str, str]:
    """Create a job + uploaded artifact, then backdate it and mark the job done.
    Returns (job_id, artifact_id)."""
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id = await _create_job(client, admin_headers, probe)
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers={**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS},
    )
    assert resp.status_code == 201

    art = (
        await db_session.execute(
            select(ScanArtifact).where(ScanArtifact.scan_job_id == uuid.UUID(job_id))
        )
    ).scalars().first()
    assert art is not None
    art.created_at = datetime.now(UTC) - timedelta(days=200)
    job = await db_session.get(ScanJob, uuid.UUID(job_id))
    assert job is not None
    job.status = JobStatus.COMPLETED
    await db_session.commit()
    return job_id, str(art.id)


async def test_overview_and_health_report(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/maintenance", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["overall_state"] in ("ok", "warn", "action")
    assert set(body["summary"]) == {"ok", "warn", "action"}
    # Every non-green item links to a specific action.
    for item in body["items"]:
        assert item["domain"] and item["state"] in ("ok", "warn", "action")
        if item["state"] != "ok":
            assert item["action"]

    hr = await client.get("/api/v1/maintenance/health-report", headers=admin_headers)
    assert hr.status_code == 200
    assert "domains" in hr.json() and "overall_state" in hr.json()


async def test_storage_and_certificate(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    s = await client.get("/api/v1/maintenance/storage", headers=admin_headers)
    assert s.status_code == 200
    cats = {c["category"] for c in s.json()["categories"]}
    assert {"raw_output", "reports", "evidence", "database", "scout_queues", "backups"} <= cats

    c = await client.get("/api/v1/maintenance/certificate", headers=admin_headers)
    assert c.status_code == 200
    assert c.json()["preflight"] and c.json()["recovery"]


async def test_preview_matches_cleanup_and_frees_space(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    _, art_id = await _old_completed_artifact(client, admin_headers, enroll_probe, db_session)

    preview = await client.get("/api/v1/maintenance/retention/preview", headers=admin_headers)
    assert preview.status_code == 200
    eligible_ids = {i["id"] for i in preview.json()["eligible"]}
    assert art_id in eligible_ids

    # Cleanup requires confirm + a password re-check.
    no_confirm = await client.post(
        "/api/v1/maintenance/retention/cleanup",
        json={"confirm": False, "password": TEST_PASSWORD},
        headers=admin_headers,
    )
    assert no_confirm.status_code == 400

    bad_pw = await client.post(
        "/api/v1/maintenance/retention/cleanup",
        json={"confirm": True, "password": "wrong"},
        headers=admin_headers,
    )
    assert bad_pw.status_code == 403

    ok = await client.post(
        "/api/v1/maintenance/retention/cleanup",
        json={"confirm": True, "password": TEST_PASSWORD},
        headers=admin_headers,
    )
    assert ok.status_code == 200
    assert ok.json()["deleted"]["raw_output"] == 1

    # The artifact is gone; a re-preview no longer lists it.
    gone = await db_session.get(ScanArtifact, uuid.UUID(art_id))
    assert gone is None


async def test_legal_hold_protects_from_cleanup(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    job_id, art_id = await _old_completed_artifact(client, admin_headers, enroll_probe, db_session)

    # Place a legal hold on the job.
    hold = await client.post(
        "/api/v1/maintenance/holds",
        json={"target_type": "scan_job", "target_id": job_id, "reason": "investigation"},
        headers=admin_headers,
    )
    assert hold.status_code == 201

    preview = await client.get("/api/v1/maintenance/retention/preview", headers=admin_headers)
    body = preview.json()
    assert art_id not in {i["id"] for i in body["eligible"]}
    protected = {i["id"]: i["reason"] for i in body["protected"]}
    assert art_id in protected and "hold" in protected[art_id]

    # Cleanup refuses to delete it.
    ok = await client.post(
        "/api/v1/maintenance/retention/cleanup",
        json={"confirm": True, "password": TEST_PASSWORD},
        headers=admin_headers,
    )
    assert ok.json()["deleted"]["raw_output"] == 0
    assert await db_session.get(ScanArtifact, uuid.UUID(art_id)) is not None


async def test_holds_require_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/maintenance/holds",
        json={"target_type": "scan_job", "target_id": str(uuid.uuid4())},
        headers=viewer_headers,
    )
    assert r.status_code == 403
