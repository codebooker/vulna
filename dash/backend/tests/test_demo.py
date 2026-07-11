"""Safe demo mode tests (Phase 30)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient


async def test_enable_seeds_sample_data_then_disable_removes_it(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    # Initially no demo data.
    before = await client.get("/api/v1/assets", headers=admin_headers)
    assert before.json()["total"] == 0

    enabled = await client.post("/api/v1/demo/enable", headers=admin_headers)
    assert enabled.status_code == 200
    assert enabled.json()["demo_mode"] is True and enabled.json()["seeded"] is True

    assets = await client.get("/api/v1/assets", headers=admin_headers)
    names = {a["canonical_name"] for a in assets.json()["items"]}
    # Sample hosts use reserved documentation ranges only.
    assert names == {"198.51.100.10", "203.0.113.20"}

    findings = await client.get("/api/v1/findings", headers=admin_headers)
    assert findings.json()["total"] >= 3

    # Enabling again is idempotent (no duplicate site/assets).
    again = await client.post("/api/v1/demo/enable", headers=admin_headers)
    assert again.json()["created"] is False
    assert (await client.get("/api/v1/assets", headers=admin_headers)).json()["total"] == 2

    # Disable removes the seeded data.
    disabled = await client.post("/api/v1/demo/disable", headers=admin_headers)
    assert disabled.status_code == 200
    assert (await client.get("/api/v1/assets", headers=admin_headers)).json()["total"] == 0
    assert (await client.get("/api/v1/findings", headers=admin_headers)).json()["total"] == 0


async def test_demo_mode_blocks_real_scan_jobs(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    await client.post("/api/v1/demo/enable", headers=admin_headers)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": str(uuid.uuid4()), "targets": ["203.0.113.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 403
    assert "demo mode" in resp.json()["detail"].lower()

    status = await client.get("/api/v1/demo/status", headers=admin_headers)
    assert status.json()["demo_mode"] is True


async def test_demo_enable_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.post("/api/v1/demo/enable", headers=viewer_headers)
    assert resp.status_code == 403
