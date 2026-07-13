"""Tests for the health and system endpoints."""

from __future__ import annotations

from httpx import AsyncClient


async def test_health_ok(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "VulnaDash"
    assert "version" not in body


async def test_system_health(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/system/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "VulnaDash"}


async def test_system_info_requires_authentication(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    assert (await client.get("/api/v1/system/info")).status_code == 401
    resp = await client.get("/api/v1/system/info", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "VulnaDash"
    assert body["api_version"] == "v1"
    assert "environment" in body


async def test_openapi_available(client: AsyncClient) -> None:
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "VulnaDash API"
