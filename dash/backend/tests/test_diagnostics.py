"""Vulna Doctor diagnostics, support bundle, timeline, and safe repairs (Phase 26)."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.models.enums import ProbeStatus
from app.models.probe import Probe
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

EnrolledProbe = dict[str, str]


async def test_diagnostics_shape(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.get("/api/v1/diagnostics", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert set(body["summary"]) == {"ok", "warn", "fail"}
    assert len(body["checks"]) > 5
    # Every failing/warning check names component, impact, data-safety, and next step.
    for c in body["checks"]:
        assert c["component"] and c["status"] in ("ok", "warn", "fail")
        assert "data_safety" in c
        if c["status"] != "ok":
            assert c["impact"] and c["next_step"]


async def test_seeded_expired_scout_cert_is_diagnosed(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    enroll_probe: Callable[..., Awaitable[EnrolledProbe]],
) -> None:
    probe = await enroll_probe()
    row = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    assert row is not None
    row.status = ProbeStatus.ENROLLED
    row.certificate_expires_at = datetime.now(UTC) - timedelta(days=1)  # expired
    db_session.add(row)
    await db_session.commit()

    r = await client.get("/api/v1/diagnostics", headers=admin_headers)
    checks = {c["component"]: c for c in r.json()["checks"]}
    assert checks["certificate_scouts"]["status"] == "fail"
    assert "re-enroll" in checks["certificate_scouts"]["next_step"].lower()


async def test_support_bundle_is_redacted(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/diagnostics/support-bundle", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    # Manifest documents which sections/fields are shared.
    sections = {m["section"] for m in body["manifest"]}
    assert {"system", "diagnostics", "probes"} <= sections
    # The allowlist build yields a clean secret scan.
    assert body["secret_scan"]["clean"] is True
    # No secret material appears anywhere in the serialized bundle.
    blob = str(body["bundle"]).lower()
    for bad in ("password", "-----begin", "ghp_", "token", "fingerprint"):
        assert bad not in blob


async def test_support_bundle_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/diagnostics/support-bundle", headers=viewer_headers)
    assert r.status_code == 403


async def test_repair_requires_confirmation_and_allowlist(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    # Unknown action rejected.
    bad = await client.post(
        "/api/v1/diagnostics/repair", json={"action": "delete_everything", "confirm": True},
        headers=admin_headers,
    )
    assert bad.status_code == 422

    # Known action without confirmation rejected.
    unconfirmed = await client.post(
        "/api/v1/diagnostics/repair", json={"action": "recreate_storage_dirs"},
        headers=admin_headers,
    )
    assert unconfirmed.status_code == 400

    # Confirmed, allowlisted action runs.
    ok = await client.post(
        "/api/v1/diagnostics/repair",
        json={"action": "recreate_storage_dirs", "confirm": True},
        headers=admin_headers,
    )
    assert ok.status_code == 200
    assert ok.json()["action"] == "recreate_storage_dirs"


async def test_repair_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/diagnostics/repair",
        json={"action": "recreate_storage_dirs", "confirm": True},
        headers=viewer_headers,
    )
    assert r.status_code == 403


async def test_timeline(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    # Trigger an audited action so the timeline has content.
    await client.post(
        "/api/v1/sites", json={"name": "HQ", "code": "TL1"}, headers=admin_headers
    )
    r = await client.get("/api/v1/diagnostics/timeline", headers=admin_headers)
    assert r.status_code == 200
    assert isinstance(r.json()["events"], list)
