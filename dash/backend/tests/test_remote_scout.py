"""Remote-Scout enrollment command and self-revocation (Phase 20)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.services.remote_scout import build_install_commands
from httpx import AsyncClient

from tests.conftest import generate_csr_pem, probe_cert_headers

EnrolledProbe = dict[str, str]


# --------------------------------------------------------------------------- #
# Pure: install-command assembly
# --------------------------------------------------------------------------- #


def test_build_install_commands() -> None:
    cmds = build_install_commands("https://vulna.example.com/", "vscout_secret", "remote-1")
    uni = cmds["universal"]
    # Uses the signature-verifying bootstrap and passes the token via env, not argv.
    assert "install-scout.sh" in uni
    assert "VULNA_ENROLL_TOKEN=vscout_secret" in uni
    assert "https://vulna.example.com" in uni
    assert "https://vulna.example.com//" not in uni  # trailing slash trimmed
    assert "vscout_secret" in cmds["container"]
    assert cmds["cloud_init"].startswith("#cloud-config")


# --------------------------------------------------------------------------- #
# Add VulnaScout command endpoint
# --------------------------------------------------------------------------- #


async def _make_site(client: AsyncClient, admin_headers: dict[str, str], code: str) -> str:
    site = await client.post(
        "/api/v1/sites", json={"name": "HQ", "code": code}, headers=admin_headers
    )
    return site.json()["id"]


async def test_enrollment_command_mints_usable_single_use_token(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _make_site(client, admin_headers, "HQ")
    r = await client.post(
        "/api/v1/probes/enrollment-command",
        json={"site_id": site_id, "probe_name": "remote-1"},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["token"] and body["short_code"]
    assert body["token"] in body["commands"]["universal"]
    assert "install-scout.sh" in body["commands"]["universal"]

    # The minted token really enrolls a probe (single-use).
    first = await client.post(
        "/api/v1/probes/enroll",
        json={"token": body["token"], "csr_pem": generate_csr_pem()},
    )
    assert first.status_code == 201
    second = await client.post(
        "/api/v1/probes/enroll",
        json={"token": body["token"], "csr_pem": generate_csr_pem()},
    )
    assert second.status_code != 201  # token already consumed


async def test_enrollment_command_requires_admin(
    client: AsyncClient, admin_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    site_id = await _make_site(client, admin_headers, "HQ2")
    r = await client.post(
        "/api/v1/probes/enrollment-command",
        json={"site_id": site_id},
        headers=viewer_headers,
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Self-revocation (reset)
# --------------------------------------------------------------------------- #


async def test_self_revoke_kills_identity(
    client: AsyncClient,
    enroll_probe: Callable[..., Awaitable[EnrolledProbe]],
) -> None:
    probe = await enroll_probe()
    headers = probe_cert_headers(probe["fingerprint"])

    revoke = await client.post("/api/v1/probes/self-revoke", headers=headers)
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"

    # The old identity can no longer heartbeat.
    hb = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/heartbeat",
        json={"agent_version": "1.0.0"},
        headers=headers,
    )
    assert hb.status_code == 403
