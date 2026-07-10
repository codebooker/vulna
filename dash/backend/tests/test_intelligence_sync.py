"""Integration tests for VulnaWatch sync, enrichment, and feed health.

These exercise the Phase 7 acceptance criteria against the database:
* an existing finding receives CVSS/KEV/EPSS enrichment,
* a simulated KEV update raises a change event,
* a feed failure is recorded (visible),
* rate-limit retries work (the sync degrades but still succeeds).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.core.config import get_settings
from app.intelligence.fetchers import FetchError
from app.models.change_event import ChangeEvent
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.enums import (
    ChangeEventType,
    FeedSource,
    FeedStatus,
    FindingType,
    Severity,
)
from app.models.feed_health import FeedHealth
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.site import Site
from app.services import intelligence as intel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_intelligence_parsers import EPSS_SAMPLE, KEV_SAMPLE, NVD_SAMPLE

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)


class _StaticFetcher:
    """Returns fixed bytes; optionally fails a number of times first."""

    def __init__(self, body: bytes, fail_times: int = 0) -> None:
        self.body = body
        self.fail_times = fail_times
        self.calls = 0

    async def fetch(self, url: str, *, params: object = None) -> bytes:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise FetchError("rate limited")
        return self.body


async def _no_sleep(_: float) -> None:
    return None


async def _make_finding(
    session: AsyncSession, org: Organization, *, cve_ids: list[str], cvss: float | None = None
) -> Finding:
    site = Site(organization_id=org.id, name="S", code="S1")
    session.add(site)
    await session.flush()
    finding = Finding(
        organization_id=org.id,
        site_id=site.id,
        scanner_name="nuclei",
        canonical_finding_key="k-" + "-".join(cve_ids),
        finding_type=FindingType.VULNERABILITY,
        title="Apache Log4j RCE",
        severity=Severity.HIGH,
        cvss_score=cvss,
        cve_ids_json=cve_ids,
    )
    session.add(finding)
    await session.flush()
    return finding


async def test_nvd_sync_populates_cve_and_enriches_cvss(
    db_session: AsyncSession, organization: Organization
) -> None:
    finding = await _make_finding(db_session, organization, cve_ids=["CVE-2021-44228"])
    settings = get_settings()
    summary = await intel.sync_nvd(
        db_session, _StaticFetcher(NVD_SAMPLE), settings=settings, now=NOW, sleep=_no_sleep
    )
    assert summary.status == FeedStatus.OK
    assert summary.records_processed == 2

    record = await db_session.get(CveRecord, "CVE-2021-44228")
    assert record is not None and record.cwe_ids_json == ["CWE-502"]

    assert finding.cvss_score == 10.0  # enriched from NVD CVSS v3.1

    fh = await db_session.get(FeedHealth, FeedSource.NVD)
    assert fh is not None and fh.status == FeedStatus.OK and fh.last_success_at is not None


async def test_kev_sync_raises_change_event_and_flags_finding(
    db_session: AsyncSession, organization: Organization
) -> None:
    finding = await _make_finding(db_session, organization, cve_ids=["CVE-2021-44228"], cvss=10.0)
    settings = get_settings()

    summary = await intel.sync_kev(
        db_session, _StaticFetcher(KEV_SAMPLE), settings=settings, now=NOW, sleep=_no_sleep
    )
    assert summary.status == FeedStatus.OK
    assert summary.change_events == 1

    assert finding.known_exploited is True

    events = (
        (await db_session.execute(select(ChangeEvent))).scalars().all()
    )
    kev_events = [e for e in events if e.event_type == ChangeEventType.CVE_ADDED_TO_KEV]
    assert len(kev_events) == 1
    assert kev_events[0].asset_id == finding.asset_id
    assert "KEV" in kev_events[0].summary

    enrichment = await db_session.get(ThreatIntelEnrichment, "CVE-2021-44228")
    assert enrichment is not None and enrichment.is_kev is True
    assert enrichment.known_ransomware_use is True


async def test_kev_resync_does_not_duplicate_event(
    db_session: AsyncSession, organization: Organization
) -> None:
    await _make_finding(db_session, organization, cve_ids=["CVE-2021-44228"], cvss=10.0)
    settings = get_settings()
    for _ in range(2):
        await intel.sync_kev(
            db_session, _StaticFetcher(KEV_SAMPLE), settings=settings, now=NOW, sleep=_no_sleep
        )
    events = (await db_session.execute(select(ChangeEvent))).scalars().all()
    kev_events = [e for e in events if e.event_type == ChangeEventType.CVE_ADDED_TO_KEV]
    assert len(kev_events) == 1  # only the first sync (False -> True) fires


async def test_epss_sync_enriches_and_crosses_threshold(
    db_session: AsyncSession, organization: Organization
) -> None:
    finding = await _make_finding(db_session, organization, cve_ids=["CVE-2021-44228"], cvss=10.0)
    settings = get_settings()  # default epss_alert_threshold = 0.5

    summary = await intel.sync_epss(
        db_session, _StaticFetcher(EPSS_SAMPLE), settings=settings, now=NOW, sleep=_no_sleep
    )
    assert summary.status == FeedStatus.OK

    assert finding.epss_score == pytest.approx(0.97540)
    assert finding.epss_percentile == pytest.approx(0.99980)

    events = (await db_session.execute(select(ChangeEvent))).scalars().all()
    crossings = [e for e in events if e.event_type == ChangeEventType.EPSS_THRESHOLD_CROSSED]
    assert len(crossings) == 1  # 0.9754 >= 0.5 threshold


async def test_sync_failure_is_recorded(
    db_session: AsyncSession, organization: Organization
) -> None:
    settings = get_settings()
    fetcher = _StaticFetcher(KEV_SAMPLE, fail_times=99)
    summary = await intel.sync_kev(
        db_session, fetcher, settings=settings, now=NOW, retries=2, sleep=_no_sleep
    )
    assert summary.status == FeedStatus.FAILED
    assert summary.error is not None

    fh = await db_session.get(FeedHealth, FeedSource.KEV)
    assert fh is not None
    assert fh.status == FeedStatus.FAILED
    assert fh.error and "rate limited" in fh.error
    assert fh.last_success_at is None


async def test_sync_retries_then_degrades(
    db_session: AsyncSession, organization: Organization
) -> None:
    settings = get_settings()
    fetcher = _StaticFetcher(KEV_SAMPLE, fail_times=1)  # first attempt fails, retry succeeds
    summary = await intel.sync_kev(
        db_session, fetcher, settings=settings, now=NOW, retries=3, sleep=_no_sleep
    )
    assert summary.status == FeedStatus.DEGRADED
    assert summary.attempts == 2
    assert fetcher.calls == 2

    fh = await db_session.get(FeedHealth, FeedSource.KEV)
    assert fh is not None and fh.status == FeedStatus.DEGRADED and fh.last_success_at is not None
