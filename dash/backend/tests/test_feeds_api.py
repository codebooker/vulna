"""API tests for the VulnaWatch feed dashboard, sync trigger, and CVE lookup."""

from __future__ import annotations

import pytest
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.organization import Organization
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_intelligence_parsers import KEV_SAMPLE


class _StubFetcher:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def fetch(self, url: str, *, params: object = None) -> bytes:
        return self.body


async def test_feed_health_lists_all_sources(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.get("/api/v1/feeds/health", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    sources = {row["source"] for row in body}
    assert sources == {"nvd", "kev", "epss"}
    assert all(row["status"] == "never_synced" for row in body)


async def test_admin_can_trigger_sync_and_health_reflects_it(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Keep the sync offline by stubbing the HTTP fetcher.
    monkeypatch.setattr("app.api.v1.feeds.HttpFetcher", lambda: _StubFetcher(KEV_SAMPLE))

    resp = await client.post("/api/v1/feeds/kev/sync", headers=admin_headers)
    assert resp.status_code == 200
    result = resp.json()
    assert result["source"] == "kev"
    assert result["status"] == "ok"
    assert result["records_processed"] == 2

    health = await client.get("/api/v1/feeds/health", headers=viewer_headers)
    kev = next(r for r in health.json() if r["source"] == "kev")
    assert kev["status"] == "ok"
    assert kev["last_success_at"] is not None


async def test_viewer_cannot_trigger_sync(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.post("/api/v1/feeds/nvd/sync", headers=viewer_headers)
    assert resp.status_code == 403


async def test_unauthenticated_cannot_read_health(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/feeds/health")
    assert resp.status_code == 401


async def test_get_cve_with_enrichment(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    viewer_headers: dict[str, str],
) -> None:
    db_session.add(
        CveRecord(cve_id="CVE-2021-44228", description="Log4Shell", cwe_ids_json=["CWE-502"])
    )
    db_session.add(
        ThreatIntelEnrichment(cve_id="CVE-2021-44228", is_kev=True, epss_score=0.975)
    )
    await db_session.commit()

    resp = await client.get("/api/v1/cve/CVE-2021-44228", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cve"]["cve_id"] == "CVE-2021-44228"
    assert body["enrichment"]["is_kev"] is True
    assert body["enrichment"]["epss_score"] == pytest.approx(0.975)


async def test_get_unknown_cve_404(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    resp = await client.get("/api/v1/cve/CVE-0000-0000", headers=viewer_headers)
    assert resp.status_code == 404
