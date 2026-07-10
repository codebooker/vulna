"""Prometheus /metrics endpoint: aggregates present, sensitive data absent."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.models.enums import FeedSource, FeedStatus
from app.models.feed_health import FeedHealth
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_remediation import _finding

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def test_metrics_exposes_aggregates(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    await _finding(client, admin_headers, enroll_probe)
    resp = await client.get("/metrics")  # unauthenticated, internal scrape
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    for name in (
        "vulna_build_info",
        "vulna_findings_by_severity",
        "vulna_findings_by_status",
        "vulna_probes_by_status",
        "vulna_scan_jobs_by_status",
        "vulna_probes_online",
    ):
        assert f"# TYPE {name} gauge" in body, name
    # Prometheus exposition format lines.
    assert 'vulna_findings_by_severity{severity="medium"}' in body


async def test_metrics_have_no_sensitive_labels(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    # The nuclei fixture creates a finding titled "TLS 1.0 detected" on 10.20.0.5.
    await _finding(client, admin_headers, enroll_probe)
    body = (await client.get("/metrics")).text
    # No finding titles, descriptions, or asset IPs may appear in metrics.
    assert "TLS 1.0" not in body
    assert "10.20.0.5" not in body
    assert "CVE-" not in body
    # No sensitive label keys.
    assert 'title="' not in body and 'ip="' not in body and 'evidence="' not in body


async def test_metrics_feed_freshness(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(
        FeedHealth(
            source=FeedSource.NVD,
            status=FeedStatus.OK,
            last_success_at=datetime.now(UTC),
            records_processed=1234,
        )
    )
    await db_session.commit()
    body = (await client.get("/metrics")).text
    assert 'vulna_feed_up{source="nvd"} 1' in body
    assert 'vulna_feed_last_success_timestamp_seconds{source="nvd"}' in body
    assert 'vulna_feed_records_processed{source="nvd"} 1234' in body
