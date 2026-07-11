"""Web backup center is display-only (Phase 25)."""

from __future__ import annotations

from httpx import AsyncClient


async def test_backup_center(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.get("/api/v1/system/backups", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "ca" in body["contents"] and "database" in body["contents"]
    assert "s3-compatible" in body["destinations"]
    assert body["retention_days"] == 30
    assert "vulna backup verify" in body["how_to_verify"]
    # States what cannot be recovered if the key is lost.
    assert "cannot be recovered" in body["warning"]


async def test_backup_center_requires_auth(client: AsyncClient) -> None:
    r = await client.get("/api/v1/system/backups")
    assert r.status_code == 401
