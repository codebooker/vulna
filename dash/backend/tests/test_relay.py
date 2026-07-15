"""VulnaRelay tests (Phase 16, opt-in)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

from app.models.enums import RelayStatus
from app.models.network import NetworkScout
from app.models.network_scope import NetworkScope
from app.services.relay import egress_decision, validate_egress_cidrs
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import generate_csr_pem, probe_cert_headers

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

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


def test_egress_blocks_broad_target_overlapping_denied_host() -> None:
    # A denied single host inside a broad approved target must block the whole
    # target (overlap semantics), not slip through because it isn't fully denied.
    d = egress_decision(
        "10.9.0.0/16", ["10.0.0.0/8"], ["10.9.9.9/32"], status=ENROLLED, tunnel_up=True
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


async def test_relay_mode_is_off_by_default(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    s = await client.get("/api/v1/relays/settings", headers=admin_headers)
    assert s.status_code == 200 and s.json()["enabled"] is False
    # Enrollment remains unavailable until an administrator explicitly opts in.
    site = (
        await client.post(
            "/api/v1/sites",
            json={"name": "Relay default site", "code": "RELAY-DEF"},
            headers=admin_headers,
        )
    ).json()
    cmd = await client.post(
        "/api/v1/relays/enrollment-command",
        json={"name": "site-b", "site_id": site["id"]},
        headers=admin_headers,
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
    site = (
        await client.post(
            "/api/v1/sites",
            json={"name": "Relay site", "code": "RELAY-SITE"},
            headers=admin_headers,
        )
    ).json()
    cmd = await client.post(
        "/api/v1/relays/enrollment-command",
        json={"name": "site-b", "site_id": site["id"]},
        headers=admin_headers,
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
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    enroll_probe: EnrollFactory,
) -> None:
    central = await enroll_probe(site_code="CENTRAL", probe_name="local-scout")
    approved = await client.post(
        f"/api/v1/probes/{central['probe_id']}/approve", headers=admin_headers
    )
    assert approved.status_code == 200
    relay_id = await _enable_and_enroll(client, admin_headers)

    # Approve an egress scope and bring the tunnel up via a heartbeat.
    scope = await client.post(
        f"/api/v1/relays/{relay_id}/scope",
        json={
            "approved_cidrs": ["10.0.0.0/8"],
            "denied_cidrs": ["10.9.0.0/16"],
            "allow_public_addresses": False,
        },
        headers=admin_headers,
    )
    assert scope.status_code == 200
    scope_count = await db_session.scalar(select(func.count()).select_from(NetworkScope))
    assert scope_count == 1  # Relay scope is materialized for normal job policy/dispatch.
    binding_count = await db_session.scalar(
        select(func.count()).select_from(NetworkScout).where(
            NetworkScout.probe_id == uuid.UUID(central["probe_id"])
        )
    )
    assert binding_count == 1  # central Scout is dispatched through this relay network
    primary = await db_session.scalar(
        select(NetworkScout.is_primary).where(
            NetworkScout.probe_id == uuid.UUID(central["probe_id"])
        )
    )
    assert primary is True
    serialized = next(
        item
        for item in (await client.get("/api/v1/relays", headers=admin_headers)).json()["relays"]
        if item["id"] == relay_id
    )
    assert serialized["denied_cidrs"] == ["10.9.0.0/16"]
    assert serialized["allow_public_addresses"] is False
    central_policy = await client.get(
        f"/api/v1/probes/{central['probe_id']}/policy",
        headers=probe_cert_headers(central["fingerprint"]),
    )
    assert central_policy.status_code == 200
    assert central_policy.json()["denied_cidrs"] == ["10.9.0.0/16"]
    network_id = await db_session.scalar(select(NetworkScope.network_id))
    denied_job = await client.post(
        "/api/v1/jobs",
        json={
            "probe_id": central["probe_id"],
            "network_id": str(network_id),
            "targets": ["10.9.1.1"],
            "mode": "vulnerability_assessment",
        },
        headers=admin_headers,
    )
    assert denied_job.status_code == 422
    assert "denied scope" in denied_job.json()["detail"].lower()

    # A Scout enrolled at the relay site must not receive the Relay-managed
    # range, even though the site's default network binds it. Otherwise an API
    # caller could explicitly select that Scout and bypass Relay egress policy.
    enrollment = await client.post(
        "/api/v1/probes/enrollment-tokens",
        json={"site_id": serialized["site_id"], "probe_name": "branch-scout"},
        headers=admin_headers,
    )
    branch = await client.post(
        "/api/v1/probes/enroll",
        json={"token": enrollment.json()["token"], "csr_pem": generate_csr_pem()},
    )
    branch_body = branch.json()
    await client.post(
        f"/api/v1/probes/{branch_body['probe_id']}/approve", headers=admin_headers
    )
    branch_policy = await client.get(
        f"/api/v1/probes/{branch_body['probe_id']}/policy",
        headers=probe_cert_headers(branch_body["certificate_fingerprint"]),
    )
    assert "10.0.0.0/8" not in branch_policy.json()["approved_cidrs"]
    bypass = await client.post(
        "/api/v1/jobs",
        json={
            "probe_id": branch_body["probe_id"],
            "network_id": str(network_id),
            "targets": ["10.1.2.3"],
            "mode": "vulnerability_assessment",
        },
        headers=admin_headers,
    )
    assert bypass.status_code == 422
    assert "no approved scopes" in bypass.json()["detail"].lower()
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

    config = await client.get(
        "/api/v1/relays/config", headers=probe_cert_headers(fp)
    )
    assert config.status_code == 200
    assert config.json()["endpoint"] == "relay.test:51820"
    assert config.json()["tunnel_address"].startswith("10.254.0.")

    internal = await client.get(
        "/api/v1/relays/egress/config",
        headers={"X-Vulna-Relay-Egress-Token": "test-only-relay-egress-token"},
    )
    assert internal.status_code == 200
    assert internal.json()["peers"][0]["id"] == relay_id
    refused_internal = await client.get("/api/v1/relays/egress/config")
    assert refused_internal.status_code == 401

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

    revoked = await client.delete(f"/api/v1/relays/{relay_id}", headers=admin_headers)
    assert revoked.status_code == 200 and revoked.json()["revoked"] is True
    assert await db_session.scalar(select(func.count()).select_from(NetworkScope)) == 0


async def test_disabling_relay_mode_fails_closed(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    relay_id = await _enable_and_enroll(client, admin_headers)
    await client.post(
        f"/api/v1/relays/{relay_id}/scope",
        json={"approved_cidrs": ["10.0.0.0/8"]},
        headers=admin_headers,
    )
    fp = next(
        r["certificate_fingerprint"]
        for r in (await client.get("/api/v1/relays", headers=admin_headers)).json()["relays"]
        if r["id"] == relay_id
    )
    # Turn relay mode OFF while a relay is still enrolled.
    await client.post("/api/v1/relays/settings", json={"enabled": False}, headers=admin_headers)

    # Egress is blocked at the central egress ...
    blocked = await client.post(
        f"/api/v1/relays/{relay_id}/egress-check",
        json={"target": "10.1.2.3"},
        headers=admin_headers,
    )
    assert blocked.json()["allowed"] is False and "disabled" in blocked.json()["reason"].lower()

    # ... and a heartbeat cannot mark the tunnel up.
    hb = await client.post(
        "/api/v1/relays/heartbeat",
        json={"tunnel_up": True, "health": {}},
        headers=probe_cert_headers(fp),
    )
    assert hb.status_code == 200 and hb.json()["tunnel_up"] is False
