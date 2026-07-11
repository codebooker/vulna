"""VulnaRelay tests (Phase 16, opt-in)."""

from __future__ import annotations

import json

from app.models.enums import RelayStatus
from app.services.relay import egress_decision, validate_egress_cidrs
from httpx import AsyncClient

from tests.conftest import generate_csr_pem, probe_cert_headers

ENROLLED = RelayStatus.ENROLLED


# --- pure egress decision (fail-closed) ------------------------------------- #


def test_egress_allows_in_scope_when_up() -> None:
    d = egress_decision("10.1.2.3", ["10.0.0.0/8"], [], status=ENROLLED, tunnel_up=True)
    assert d.allowed is True


def test_egress_blocks_out_of_scope() -> None:
    d = egress_decision("8.8.8.8", ["10.0.0.0/8"], [], status=ENROLLED, tunnel_up=True)
    assert d.allowed is False and "scope" in d.reason.lower()


def test_egress_blocks_denied_range() -> None:
    d = egress_decision(
        "10.9.9.9", ["10.0.0.0/8"], ["10.9.0.0/16"], status=ENROLLED, tunnel_up=True
    )
    assert d.allowed is False and "denied" in d.reason.lower()


def test_egress_blocks_when_tunnel_down() -> None:
    d = egress_decision("10.1.2.3", ["10.0.0.0/8"], [], status=ENROLLED, tunnel_up=False)
    assert d.allowed is False and "tunnel" in d.reason.lower()


def test_egress_blocks_when_killed() -> None:
    d = egress_decision("10.1.2.3", ["10.0.0.0/8"], [], status=RelayStatus.KILLED, tunnel_up=True)
    assert d.allowed is False and "kill" in d.reason.lower()


def test_egress_blocks_when_not_enrolled() -> None:
    d = egress_decision(
        "10.1.2.3", ["10.0.0.0/8"], [], status=RelayStatus.PENDING_ENROLLMENT, tunnel_up=True
    )
    assert d.allowed is False


def test_validate_egress_cidrs_rejects_public_by_default() -> None:
    assert validate_egress_cidrs(["10.0.0.0/24"]) == ["10.0.0.0/24"]
    try:
        validate_egress_cidrs(["8.8.8.8/32"])
        raised = False
    except Exception:
        raised = True
    assert raised


# --- API: off by default, enrollment, kill switch, egress ------------------- #


async def test_relay_mode_off_by_default(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    s = await client.get("/api/v1/relays/settings", headers=admin_headers)
    assert s.status_code == 200 and s.json()["enabled"] is False
    # Operations are refused while disabled.
    cmd = await client.post(
        "/api/v1/relays/enrollment-command", json={"name": "site-b"}, headers=admin_headers
    )
    assert cmd.status_code == 409


async def test_enable_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.post("/api/v1/relays/settings", json={"enabled": True}, headers=viewer_headers)
    assert r.status_code == 403


async def _enable_and_enroll(
    client: AsyncClient, admin_headers: dict[str, str]
) -> str:
    await client.post("/api/v1/relays/settings", json={"enabled": True}, headers=admin_headers)
    cmd = await client.post(
        "/api/v1/relays/enrollment-command", json={"name": "site-b"}, headers=admin_headers
    )
    assert cmd.status_code == 200
    token = cmd.json()["token"]
    reg = await client.post(
        "/api/v1/relays/register",
        json={"token": token, "csr_pem": generate_csr_pem(), "tunnel_public_key": "wg-pub-key"},
    )
    assert reg.status_code == 200
    # The relay is never handed job-signing keys or scanner credentials.
    text = json.dumps(reg.json()).lower()
    for banned in ("signing", "private_key", "scanner_credential", "job_signing"):
        assert banned not in text
    return cmd.json()["relay_id"]


async def test_enroll_scope_and_egress_and_killswitch(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    relay_id = await _enable_and_enroll(client, admin_headers)

    # Approve an egress scope and bring the tunnel up via a heartbeat.
    scope = await client.post(
        f"/api/v1/relays/{relay_id}/scope",
        json={"approved_cidrs": ["10.0.0.0/8"]},
        headers=admin_headers,
    )
    assert scope.status_code == 200
    fp = next(
        r["certificate_fingerprint"]
        for r in (await client.get("/api/v1/relays", headers=admin_headers)).json()["relays"]
        if r["id"] == relay_id
    )
    hb = await client.post(
        "/api/v1/relays/heartbeat",
        json={"tunnel_up": True, "health": {}},
        headers=probe_cert_headers(fp),
    )
    assert hb.status_code == 200 and hb.json()["tunnel_up"] is True

    # In-scope egress is allowed; out-of-scope is blocked at the central egress.
    ok = await client.post(
        f"/api/v1/relays/{relay_id}/egress-check",
        json={"target": "10.1.2.3"},
        headers=admin_headers,
    )
    assert ok.json()["allowed"] is True
    blocked = await client.post(
        f"/api/v1/relays/{relay_id}/egress-check", json={"target": "8.8.8.8"}, headers=admin_headers
    )
    assert blocked.json()["allowed"] is False

    # Kill switch: everything is blocked immediately.
    kill = await client.post(f"/api/v1/relays/{relay_id}/kill", headers=admin_headers)
    assert kill.json()["status"] == "killed" and kill.json()["tunnel_up"] is False
    after = await client.post(
        f"/api/v1/relays/{relay_id}/egress-check",
        json={"target": "10.1.2.3"},
        headers=admin_headers,
    )
    assert after.json()["allowed"] is False and "kill" in after.json()["reason"].lower()

    # A killed relay's heartbeat is refused (tunnel must stay down).
    refused = await client.post(
        "/api/v1/relays/heartbeat", json={"tunnel_up": True}, headers=probe_cert_headers(fp)
    )
    assert refused.status_code == 403

    # Resume clears the kill switch.
    resumed = await client.post(f"/api/v1/relays/{relay_id}/resume", headers=admin_headers)
    assert resumed.json()["status"] == "enrolled"
