"""Tests for the Phase 0 health and system endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "VulnaDash"
    assert body["version"]


def test_system_health(client: TestClient) -> None:
    resp = client.get("/api/v1/system/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_system_info(client: TestClient) -> None:
    resp = client.get("/api/v1/system/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "VulnaDash"
    assert body["api_version"] == "v1"
    assert "environment" in body


def test_openapi_available(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "VulnaDash API"
