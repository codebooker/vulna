"""Guided first-run: advisory detection, scope guardrails, recovery codes, state."""

from __future__ import annotations

import pytest
from app.models.user import User
from app.services import onboarding as ob
from app.services.scopes import ScopeValidationError
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# --------------------------------------------------------------------------- #
# Pure logic
# --------------------------------------------------------------------------- #


def test_scope_preview_private_ok() -> None:
    p = ob.scope_preview("10.20.30.0/24")
    assert p["cidr"] == "10.20.30.0/24"
    assert p["is_private"] is True
    assert p["requires_confirmation"] is False
    assert p["host_estimate"] == 254


def test_scope_preview_rejects_default_route() -> None:
    with pytest.raises(ScopeValidationError):
        ob.scope_preview("0.0.0.0/0")
    with pytest.raises(ScopeValidationError):
        ob.scope_preview("::/0")


def test_scope_preview_rejects_malformed() -> None:
    with pytest.raises(ScopeValidationError):
        ob.scope_preview("not-a-cidr")


def test_scope_preview_public_denied_by_default() -> None:
    with pytest.raises(ScopeValidationError):
        ob.scope_preview("8.8.8.0/24")


def test_scope_preview_public_with_optin_warns_and_confirms() -> None:
    p = ob.scope_preview("8.8.8.0/24", allow_public=True)
    assert p["is_private"] is False
    assert p["requires_confirmation"] is True
    assert any("public" in w.lower() for w in p["warnings"])


def test_scope_preview_broad_range_requires_confirmation() -> None:
    p = ob.scope_preview("10.0.0.0/16")  # ~65k hosts
    assert p["requires_confirmation"] is True
    assert p["warnings"]


def test_demo_target_is_private_loopback() -> None:
    p = ob.scope_preview(ob.DEMO_TARGET)
    assert p["is_private"] is True
    assert p["host_estimate"] == 1
    assert p["requires_confirmation"] is False


def test_network_candidates_filters_public_and_malformed() -> None:
    health = {
        "network_candidates": [
            "10.0.0.0/24",  # private, keep
            "192.168.1.5/24",  # normalizes to .0/24, keep
            "8.8.8.0/24",  # public, drop
            "0.0.0.0/0",  # default route, drop
            "garbage",  # malformed, drop
            "10.0.0.0/24",  # duplicate, dedup
        ]
    }
    got = ob.network_candidates_from_health(health)
    assert got == ["10.0.0.0/24", "192.168.1.0/24"]


def test_network_candidates_empty_when_absent() -> None:
    assert ob.network_candidates_from_health(None) == []
    assert ob.network_candidates_from_health({"other": 1}) == []


def test_scan_summary_standard_preset() -> None:
    s = ob.scan_summary("standard", ["10.0.0.0/24"], retention_days=90)
    assert s["preset"] == "standard"
    assert s["intrusive"] is False
    assert s["active_web"] is False
    assert s["host_estimate"] == 254
    assert "90 days" in s["data_retention"]


def test_scan_summary_rejects_public_target() -> None:
    with pytest.raises(ScopeValidationError):
        ob.scan_summary("standard", ["8.8.8.0/24"], retention_days=90)


def test_scan_summary_unknown_preset() -> None:
    with pytest.raises(ValueError):
        ob.scan_summary("nope", ["10.0.0.0/24"], retention_days=90)


# --------------------------------------------------------------------------- #
# Recovery codes (service, with DB)
# --------------------------------------------------------------------------- #


async def test_recovery_codes_generate_and_consume(
    db_session: AsyncSession, admin: User
) -> None:
    codes = await ob.generate_recovery_codes(db_session, admin, count=5)
    assert len(codes) == 5
    assert len(admin.recovery_codes_json) == 5
    # stored values are hashes, not the plaintext codes
    assert all(code not in admin.recovery_codes_json for code in codes)

    # a valid code verifies and is consumed one-time
    assert await ob.verify_and_consume_recovery_code(db_session, admin, codes[0]) is True
    assert len(admin.recovery_codes_json) == 4
    assert await ob.verify_and_consume_recovery_code(db_session, admin, codes[0]) is False
    # a wrong code fails
    assert await ob.verify_and_consume_recovery_code(db_session, admin, "aaaa-bbbb-cccc") is False


# --------------------------------------------------------------------------- #
# API + resumable state
# --------------------------------------------------------------------------- #


async def test_state_created_and_resumable(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/onboarding/state", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["current_step"] == "admin"

    # complete a step; it advances and is idempotent
    body = {"step": "recovery_codes"}
    step_url = "/api/v1/onboarding/state/complete-step"
    r1 = await client.post(step_url, json=body, headers=admin_headers)
    r2 = await client.post(step_url, json=body, headers=admin_headers)
    assert r1.status_code == 200 and r2.status_code == 200
    completed = r2.json()["completed_steps"]
    assert completed.count("recovery_codes") == 1  # no duplicate on refresh


async def test_scope_preview_endpoint_guardrails(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    ok = await client.post(
        "/api/v1/onboarding/scope-preview", json={"cidr": "192.168.0.0/24"}, headers=admin_headers
    )
    assert ok.status_code == 200
    assert ok.json()["is_private"] is True

    for bad in ["0.0.0.0/0", "::/0", "not-a-cidr"]:
        r = await client.post(
            "/api/v1/onboarding/scope-preview", json={"cidr": bad}, headers=admin_headers
        )
        assert r.status_code == 422, bad

    pub = await client.post(
        "/api/v1/onboarding/scope-preview", json={"cidr": "1.1.1.0/24"}, headers=admin_headers
    )
    assert pub.status_code == 422  # public denied by default


async def test_recovery_codes_endpoint_returns_once(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post("/api/v1/onboarding/recovery-codes", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()["codes"]) == ob.RECOVERY_CODE_COUNT


async def test_presets_summary_and_demo(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    presets = await client.get("/api/v1/onboarding/scan-presets", headers=admin_headers)
    keys = [p["key"] for p in presets.json()["presets"]]
    assert "standard" in keys

    summary = await client.post(
        "/api/v1/onboarding/scan-summary",
        json={"preset": "standard", "targets": ["10.1.0.0/24"]},
        headers=admin_headers,
    )
    assert summary.status_code == 200
    assert summary.json()["intrusive"] is False

    demo = await client.get("/api/v1/onboarding/demo-target", headers=admin_headers)
    assert demo.json()["cidr"] == "127.0.0.1/32"


async def test_network_candidates_no_scout(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/onboarding/network-candidates", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["candidates"] == []
    # advisory note must make clear nothing is approved
    assert "approve" in r.json()["note"].lower()
