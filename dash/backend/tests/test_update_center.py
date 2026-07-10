"""Web update center is display-only (Phase 24)."""

from __future__ import annotations

from httpx import AsyncClient


async def test_update_center_display_only(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/system/update", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["current_version"]
    assert body["channel"] == "stable"
    assert "stable" in body["channels"]
    # Separates the update types and points to the verifying CLI.
    assert "VulnaScout" in body["update_types"]
    assert "vulna update" in body["how_to_apply"]
    # No forced remote update path.
    assert "opt-in" in body["note"]


async def test_update_center_requires_auth(client: AsyncClient) -> None:
    r = await client.get("/api/v1/system/update")
    assert r.status_code == 401
