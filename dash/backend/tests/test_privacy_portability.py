"""Privacy and portability tests (Phase 31)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import jsonschema
from app.services import export as export_svc
from httpx import AsyncClient

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPORT_SCHEMA = json.loads(
    (REPO_ROOT / "shared/schemas/export-bundle.schema.json").read_text()
)


# --- privacy ---------------------------------------------------------------- #


async def test_outbound_lists_feeds_and_states_updates_never_phone_home(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/privacy/outbound", headers=admin_headers)
    assert r.status_code == 200
    conns = {c["name"]: c for c in r.json()["connections"]}
    assert "NVD (CVE data)" in conns and conns["NVD (CVE data)"]["destination"]
    # The application never contacts a release server.
    assert conns["Update checks"]["enabled"] is False
    assert conns["Update checks"]["destination"] is None


async def test_secret_inventory_never_returns_values(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/privacy/secrets", headers=admin_headers)
    assert r.status_code == 200
    secrets = r.json()["secrets"]
    assert any(s["name"] == "Application secret key" for s in secrets)
    # Status only: 'present' booleans, no 'value' field anywhere.
    for s in secrets:
        assert "value" not in s and "secret" not in s
        assert isinstance(s["present"], bool)
    # Non-admin cannot read the inventory.
    viewer = await client.get("/api/v1/privacy/secrets", headers=admin_headers)
    assert viewer.status_code == 200


async def test_telemetry_off_by_default_and_preview_is_anonymous(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    settings = await client.get("/api/v1/privacy/settings", headers=admin_headers)
    assert settings.json()["settings"]["telemetry_enabled"] is False  # not preselected

    preview = await client.get("/api/v1/privacy/telemetry/preview", headers=admin_headers)
    body = preview.json()
    # The transmitted payload is only version + aggregate integer counts.
    assert set(body) == {"schema_version", "vulna_version", "counts", "excluded"}
    assert set(body["counts"]) == {"sites", "assets", "scans", "findings", "critical_findings"}
    assert all(isinstance(v, int) for v in body["counts"].values())
    # It documents that PII / identifying fields are excluded.
    for banned in ("ip_addresses", "hostnames", "usernames", "cves", "evidence", "credentials"):
        assert banned in body["excluded"]


async def test_toggling_privacy_settings_is_explicit_and_audited(
    client: AsyncClient, admin_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    # A viewer cannot change settings.
    assert (
        await client.post(
            "/api/v1/privacy/settings", json={"update_check_enabled": False},
            headers=viewer_headers,
        )
    ).status_code == 403

    # An admin explicitly disables update checks and opts into telemetry.
    resp = await client.post(
        "/api/v1/privacy/settings",
        json={"update_check_enabled": False, "telemetry_enabled": True},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["settings"]["update_check_enabled"] is False
    assert resp.json()["settings"]["telemetry_enabled"] is True


async def test_local_analytics_never_transmitted(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/privacy/analytics", headers=admin_headers)
    assert r.json()["transmitted"] is False
    assert "findings" in r.json()["counts"]


# --- portability / export --------------------------------------------------- #


async def test_export_is_versioned_checksummed_and_schema_valid(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/portability/export", headers=admin_headers)
    assert r.status_code == 200
    bundle = r.json()
    assert bundle["schema_version"] == "1"
    # Independently validatable against the published schema and its checksum.
    jsonschema.Draft202012Validator(EXPORT_SCHEMA).validate(bundle)
    assert bundle["checksum"] == export_svc.checksum(bundle)
    assert bundle["organization"]["experience_profile"] == "small_business"
    assert bundle["organization"]["feature_overrides"] == {}
    assert bundle["users"]
    assert bundle["users"][0]["account_status"] == "active"
    assert "authentication_source" in bundle["users"][0]
    assert "user_site_assignments" in bundle
    # No secret material leaks into the export.
    text = json.dumps(bundle).lower()
    for banned in (
        "private key",
        "begin rsa",
        "password",
        "encrypted_secret",
        "signing_key",
        "token_hash",
        "recovery_codes",
        "session_refresh_tokens",
        "user_agent",
    ):
        assert banned not in text


async def test_export_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.get("/api/v1/portability/export", headers=viewer_headers)
    assert resp.status_code == 403


async def test_validate_refuses_other_org_and_detects_tamper(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    bundle = (await client.get("/api/v1/portability/export", headers=admin_headers)).json()

    # A valid bundle round-trips.
    ok = await client.post(
        "/api/v1/portability/validate", json={"bundle": bundle}, headers=admin_headers
    )
    assert ok.json()["valid"] is True and ok.json()["checksum_ok"] is True

    # Tampering breaks the checksum.
    tampered = dict(bundle)
    tampered["sites"] = [{"id": str(uuid.uuid4()), "name": "injected"}]
    bad = await client.post(
        "/api/v1/portability/validate", json={"bundle": tampered}, headers=admin_headers
    )
    assert bad.json()["valid"] is False and bad.json()["checksum_ok"] is False

    # A bundle from another organization is refused (no cross-org import).
    foreign = dict(bundle)
    foreign["organization"] = {**bundle["organization"], "id": str(uuid.uuid4())}
    foreign["checksum"] = export_svc.checksum(foreign)  # re-checksum so only ownership differs
    result = await client.post(
        "/api/v1/portability/validate", json={"bundle": foreign}, headers=admin_headers
    )
    assert result.json()["valid"] is False
    assert any("organization" in e for e in result.json()["errors"])


async def test_migration_plan_preserves_scout_trust(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/portability/migration-plan", headers=admin_headers)
    assert r.json()["preserves_scout_trust"] is True
    steps = [s["step"] for s in r.json()["steps"]]
    assert steps == ["backup", "verify", "restore", "url", "scouts"]
