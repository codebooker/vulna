"""Scan-job creation, delivery, cancellation, and status-report tests."""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.auth.password import hash_password
from app.models.audit import AuditEvent
from app.models.enums import JobStatus, SiteAccessMode, UserRole
from app.models.organization import Organization
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.signing import get_signer
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import UserFactory, auth_headers, probe_cert_headers

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


async def test_network_job_is_bound_scoped_locked_and_disableable(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    networks = (await client.get("/api/v1/networks", headers=admin_headers)).json()
    network = next(n for n in networks if any(r["cidr"] == "10.20.0.0/24" for r in n["ranges"]))

    created = await client.post(
        "/api/v1/jobs",
        json={
            "network_id": network["id"],
            "probe_id": probe["probe_id"],
            "targets": ["10.20.0.5"],
        },
        headers=admin_headers,
    )
    assert created.status_code == 201
    assert created.json()["network_id"] == network["id"]

    duplicate = await client.post(
        "/api/v1/jobs",
        json={
            "network_id": network["id"],
            "probe_id": probe["probe_id"],
            "targets": ["10.20.0.6"],
        },
        headers=admin_headers,
    )
    assert duplicate.status_code == 422
    assert "already under test" in duplicate.json()["detail"]

    await client.post(f"/api/v1/jobs/{created.json()['id']}/cancel", headers=admin_headers)
    other = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Other",
                "ranges": [{"cidr": "10.30.0.0/24"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()
    outside = await client.post(
        "/api/v1/jobs",
        json={
            "network_id": other["id"],
            "probe_id": probe["probe_id"],
            "targets": ["10.20.0.5"],
        },
        headers=admin_headers,
    )
    assert outside.status_code == 422
    assert "outside the approved scope" in outside.json()["detail"]

    await client.patch(
        f"/api/v1/networks/{network['id']}",
        json={"enabled": False},
        headers=admin_headers,
    )
    disabled = await client.post(
        "/api/v1/jobs",
        json={
            "network_id": network["id"],
            "probe_id": probe["probe_id"],
            "targets": ["10.20.0.5"],
        },
        headers=admin_headers,
    )
    assert disabled.status_code == 422
    assert "disabled" in disabled.json()["detail"].lower()


async def test_cross_site_network_job_requires_access_to_the_network_site(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    houston = await _ready_probe(
        client, admin_headers, enroll_probe, cidr="10.61.0.0/24", site_code="HOU-AUTHZ"
    )
    salisbury = await _ready_probe(
        client, admin_headers, enroll_probe, cidr="10.62.0.0/24", site_code="SBY-AUTHZ"
    )
    networks = (await client.get("/api/v1/networks", headers=admin_headers)).json()
    salisbury_network = next(
        network for network in networks if network["site_id"] == salisbury["site_id"]
    )
    bound = await client.post(
        f"/api/v1/networks/{salisbury_network['id']}/scouts",
        json={"probe_id": houston["probe_id"], "is_primary": False},
        headers=admin_headers,
    )
    assert bound.status_code == 200

    operator = await make_user(UserRole.SECURITY_OPERATOR)
    assigned = await client.put(
        f"/api/v1/users/{operator.id}/site-access",
        json={"mode": SiteAccessMode.ASSIGNED.value, "site_ids": [houston["site_id"]]},
        headers=admin_headers,
    )
    assert assigned.status_code == 200
    await db_session.refresh(operator)

    denied = await client.post(
        "/api/v1/jobs",
        json={
            "network_id": salisbury_network["id"],
            "probe_id": houston["probe_id"],
            "targets": ["10.62.0.10"],
        },
        headers=auth_headers(operator),
    )
    assert denied.status_code == 404
    assert denied.json()["detail"] == "Network not found"


async def test_create_job_over_host_limit_rejected(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe(site_code="HL", probe_name="p-HL")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    # An approved /24 (256 hosts) but a maximum_hosts of 10.
    await client.post(
        "/api/v1/scopes",
        json={
            "site_id": probe["site_id"],
            "name": "lan",
            "cidr": "10.20.0.0/24",
            "maximum_hosts": 10,
        },
        headers=admin_headers,
    )
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 422
    assert "exceed" in resp.json()["detail"].lower()


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


async def test_scan_progress_eta_and_sanitized_operator_failure_log(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
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
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={"status": "accepted"},
        headers=headers,
    )
    progress = {
        "percent": 33,
        "current_stage": "vulnerability",
        "current_plugin": "nuclei",
        "stages_total": 3,
        "stages_completed": 1,
        "stages_run": 1,
        "stages_failed": 0,
        "stages_skipped": 0,
        "target_groups": 1,
        "target_addresses": 1,
        "elapsed_seconds": 15,
        "eta_seconds": 30,
    }
    reported = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={"status": "running", "progress": progress},
        headers=headers,
    )
    assert reported.status_code == 204

    got = await client.get(f"/api/v1/jobs/{job_id}", headers=viewer_headers)
    assert got.status_code == 200
    body = got.json()
    assert body["progress_percent"] == 33
    assert body["progress_json"]["stages_completed"] == 1
    assert body["estimated_completion_at"] is not None
    assert "failure_log_json" not in body

    regressed = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={
            "status": "running",
            "progress": {
                **progress,
                "percent": 0,
                "stages_completed": 0,
                "stages_run": 0,
                "eta_seconds": None,
            },
        },
        headers=headers,
    )
    assert regressed.status_code == 409

    failed = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={
            "status": "failed",
            "error_code": "scanner error!",
            "error_message": "nuclei failed password=hunter2 Bearer abc.def",
            "failure_details": [
                {
                    "code": "scanner_error",
                    "stage": "vulnerability",
                    "plugin": "nuclei",
                    "message": (
                        "request failed Authorization: Bearer very-secret "
                        "https://admin:password@example.test"
                    ),
                }
            ],
        },
        headers=headers,
    )
    assert failed.status_code == 204

    ordinary = await client.get(f"/api/v1/jobs/{job_id}", headers=viewer_headers)
    ordinary_text = ordinary.text
    assert "hunter2" not in ordinary_text
    assert "abc.def" not in ordinary_text
    assert "scanner_error" in ordinary_text
    denied = await client.get(f"/api/v1/jobs/{job_id}/diagnostics", headers=viewer_headers)
    assert denied.status_code == 403

    diagnostics = await client.get(f"/api/v1/jobs/{job_id}/diagnostics", headers=admin_headers)
    assert diagnostics.status_code == 200
    diagnostic_text = diagnostics.text
    assert "very-secret" not in diagnostic_text
    assert "admin:password" not in diagnostic_text
    assert "REDACTED" in diagnostic_text
    assert diagnostics.json()["failures"][0]["plugin"] == "nuclei"

    cannot_reopen = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={"status": "running", "progress": progress},
        headers=headers,
    )
    assert cannot_reopen.status_code == 409

    audit_actions = set(
        (
            await db_session.execute(
                select(AuditEvent.action).where(AuditEvent.target_id == job_id)
            )
        ).scalars()
    )
    assert {"job.failure_recorded", "job.diagnostics_viewed"} <= audit_actions


async def test_scan_diagnostics_cannot_cross_organizations(
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
    other_org = Organization(name="Other diagnostics", slug=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other_org)
    await db_session.flush()
    other_admin = User(
        organization_id=other_org.id,
        email=f"other-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("password-1234-strong"),
        role=UserRole.ADMINISTRATOR,
    )
    db_session.add(other_admin)
    await db_session.commit()
    response = await client.get(
        f"/api/v1/jobs/{created.json()['id']}/diagnostics",
        headers=auth_headers(other_admin),
    )
    assert response.status_code == 404


async def test_scan_observability_contract_is_additive_in_openapi(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()
    assert "/api/v1/jobs/{job_id}/diagnostics" in schema["paths"]
    job_read = schema["components"]["schemas"]["JobRead"]["properties"]
    assert {
        "progress_percent",
        "progress_json",
        "estimated_completion_at",
        "last_progress_at",
    } <= job_read.keys()
    status_update = schema["components"]["schemas"]["JobStatusUpdate"]["properties"]
    assert {"progress", "failure_details"} <= status_update.keys()
