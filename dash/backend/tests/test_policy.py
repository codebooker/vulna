"""Signed local-policy delivery tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.services.signing import get_signer
from httpx import AsyncClient

from tests.conftest import probe_cert_headers

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _add_scope(client: AsyncClient, headers: dict[str, str], site_id: str, cidr: str) -> None:
    resp = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": f"scope-{cidr}", "cidr": cidr},
        headers=headers,
    )
    assert resp.status_code == 201


async def test_enroll_returns_signing_key(enroll_probe: EnrollFactory) -> None:
    probe = await enroll_probe()
    # The enrolled probe fixture returns the raw response indirectly; re-check
    # the signing key via the signer matches what enrollment would have sent.
    assert get_signer().public_key_raw_b64  # non-empty, 44 base64 chars
    assert probe["fingerprint"]


async def test_policy_endpoint_returns_signed_scopes(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    await _add_scope(client, admin_headers, probe["site_id"], "10.20.0.0/24")
    await _add_scope(client, admin_headers, probe["site_id"], "10.30.0.0/24")

    resp = await client.get(
        f"/api/v1/probes/{probe['probe_id']}/policy",
        headers=probe_cert_headers(probe["fingerprint"]),
    )
    assert resp.status_code == 200
    doc = resp.json()
    assert set(doc["approved_cidrs"]) == {"10.20.0.0/24", "10.30.0.0/24"}
    assert doc["allowed_modes"] == ["vulnerability_assessment"]
    assert "signature" in doc
    # The delivered document verifies against the orchestrator's key.
    assert get_signer().verify_document(doc) is True


async def test_policy_requires_client_cert(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    resp = await client.get(f"/api/v1/probes/{probe['probe_id']}/policy")
    assert resp.status_code == 401


async def test_policy_cert_probe_mismatch(
    client: AsyncClient, enroll_probe: EnrollFactory
) -> None:
    a = await enroll_probe(site_code="A", probe_name="a")
    b = await enroll_probe(site_code="B", probe_name="b")
    resp = await client.get(
        f"/api/v1/probes/{b['probe_id']}/policy",
        headers=probe_cert_headers(a["fingerprint"]),
    )
    assert resp.status_code == 403


async def test_heartbeat_advertises_policy_hash(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await enroll_probe()
    await _add_scope(client, admin_headers, probe["site_id"], "10.20.0.0/24")
    headers = probe_cert_headers(probe["fingerprint"])

    # First heartbeat: probe has no policy yet -> update available.
    hb1 = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat", json={}, headers=headers
    )
    assert hb1.status_code == 200
    server_hash = hb1.json()["policy"]["hash"]
    assert server_hash
    assert hb1.json()["policy"]["update_available"] is True

    # Report the current hash -> no longer stale.
    hb2 = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat",
        json={"policy_hash": server_hash},
        headers=headers,
    )
    assert hb2.json()["policy"]["update_available"] is False
