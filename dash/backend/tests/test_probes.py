"""Probe heartbeat, lifecycle, and job-polling tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from httpx import AsyncClient

from tests.conftest import probe_cert_headers

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def test_heartbeat_updates_probe_and_marks_online(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat",
        json={
            "agent_version": "0.2.0",
            "hostname": "scout-a",
            "capabilities": ["nmap"],
            "health": {"cpu_percent": 5.0},
        },
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["probe_status"] == "pending_enrollment"
    assert body["certificate"]["fingerprint"] == probe["fingerprint"]
    assert body["heartbeat_interval_seconds"] > 0

    # The probe now shows as online with the reported inventory.
    got = await client.get(f"/api/v1/probes/{probe['probe_id']}", headers=admin_headers)
    assert got.json()["online"] is True
    assert got.json()["agent_version"] == "0.2.0"
    assert got.json()["capabilities"] == ["nmap"]


async def test_heartbeat_requires_client_cert(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(f"/api/v1/probes/{probe['probe_id']}/heartbeat", json={})
    assert resp.status_code == 401


async def test_heartbeat_unknown_cert_is_rejected(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat",
        json={},
        headers=probe_cert_headers("0" * 64),
    )
    assert resp.status_code == 401


async def test_heartbeat_cert_probe_mismatch(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    a = await enroll_probe(site_code="A", probe_name="a")
    b = await enroll_probe(site_code="B", probe_name="b")
    # Present A's certificate against B's probe id.
    resp = await client.post(
        f"/api/v1/probes/{b['probe_id']}/heartbeat",
        json={},
        headers=probe_cert_headers(a["fingerprint"]),
    )
    assert resp.status_code == 403


async def test_jobs_next_returns_204_when_enrolled(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/next",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert resp.status_code == 204


async def test_approve_moves_probe_to_enrolled(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "enrolled"
    assert resp.json()["approved_at"] is not None


async def test_update_probe_renames_and_persists(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe(probe_name="old-name")
    resp = await client.patch(
        f"/api/v1/probes/{probe['probe_id']}",
        json={"name": "edge-scout", "description": "Ground floor closet"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "edge-scout"
    assert resp.json()["description"] == "Ground floor closet"
    # Persisted across a fresh read.
    got = await client.get(f"/api/v1/probes/{probe['probe_id']}", headers=admin_headers)
    assert got.json()["name"] == "edge-scout"


async def test_update_probe_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.patch(
        f"/api/v1/probes/{probe['probe_id']}", json={"name": "x"}, headers=viewer_headers
    )
    assert resp.status_code == 403


async def test_revoked_probe_cannot_heartbeat_or_poll(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    revoke = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/revoke", headers=admin_headers
    )
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"

    headers = probe_cert_headers(probe["fingerprint"])
    hb = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat", json={}, headers=headers
    )
    assert hb.status_code == 403
    jobs = await client.post(f"/api/v1/probes/{probe['probe_id']}/jobs/next", headers=headers)
    assert jobs.status_code == 403


async def test_revoke_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/revoke", headers=viewer_headers
    )
    assert resp.status_code == 403


async def test_viewer_can_list_probes(
    client: AsyncClient, viewer_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    await enroll_probe()
    resp = await client.get("/api/v1/probes", headers=viewer_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
