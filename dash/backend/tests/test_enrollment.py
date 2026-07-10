"""Probe enrollment API tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.audit import AuditEvent
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import ProbeStatus
from app.models.probe import Probe
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import generate_csr_pem


async def _mint_token(client: AsyncClient, admin_headers: dict[str, str]) -> tuple[str, str]:
    site = await client.post(
        "/api/v1/sites", json={"name": "S", "code": "HQ"}, headers=admin_headers
    )
    site_id = site.json()["id"]
    resp = await client.post(
        "/api/v1/probes/enrollment-tokens",
        json={"site_id": site_id, "probe_name": "probe-1"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    # The secret is returned exactly once.
    assert body["token"] and body["short_code"]
    return body["token"], site_id


async def test_enroll_success_issues_certificate(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    token, site_id = await _mint_token(client, admin_headers)
    resp = await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": generate_csr_pem()}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "BEGIN CERTIFICATE" in body["certificate_pem"]
    assert "BEGIN CERTIFICATE" in body["ca_certificate_pem"]
    assert len(body["certificate_fingerprint"]) == 64
    assert body["site_id"] == site_id

    probe = await db_session.get(Probe, uuid.UUID(body["probe_id"]))
    assert probe is not None
    assert probe.status == ProbeStatus.PENDING_ENROLLMENT
    assert probe.certificate_fingerprint == body["certificate_fingerprint"]
    assert probe.enrolled_at is not None


async def test_reused_token_fails(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    token, _ = await _mint_token(client, admin_headers)
    first = await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": generate_csr_pem()}
    )
    assert first.status_code == 201
    second = await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": generate_csr_pem()}
    )
    assert second.status_code == 400


async def test_unknown_token_fails(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/probes/enroll", json={"token": "vscout_bogus", "csr_pem": generate_csr_pem()}
    )
    assert resp.status_code == 400


async def test_expired_token_fails(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    token, _ = await _mint_token(client, admin_headers)
    # Backdate the token's expiry.
    row = (await db_session.execute(select(EnrollmentToken))).scalar_one()
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.add(row)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": generate_csr_pem()}
    )
    assert resp.status_code == 400


async def test_enroll_rejects_bad_csr(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    token, _ = await _mint_token(client, admin_headers)
    resp = await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": "not a real csr"}
    )
    assert resp.status_code == 422


async def test_enrollment_token_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    site = await client.post(
        "/api/v1/sites", json={"name": "S", "code": "HQ"}, headers=admin_headers
    )
    resp = await client.post(
        "/api/v1/probes/enrollment-tokens",
        json={"site_id": site.json()["id"], "probe_name": "p"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


async def test_enroll_records_audit(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    token, _ = await _mint_token(client, admin_headers)
    await client.post(
        "/api/v1/probes/enroll", json={"token": token, "csr_pem": generate_csr_pem()}
    )
    actions = {
        row[0]
        for row in (await db_session.execute(select(AuditEvent.action))).all()
    }
    assert "probe.enrollment_token_created" in actions
    assert "probe.enrolled" in actions
