"""VulnaWatch synchronization and enrichment (build plan Section 14).

This service pulls CVE/KEV/EPSS intelligence, upserts it into the local tables,
records per-feed health, and layers the signals onto existing findings:

* NVD sync populates :class:`CveRecord`.
* KEV sync populates :class:`ThreatIntelEnrichment`, and a CVE newly added to KEV
  raises a ``cve_added_to_kev`` change event on every finding that references it.
* EPSS sync updates scores and raises ``epss_threshold_crossed`` when a score
  crosses the configured alert threshold.

The ``sync_*`` entry points fetch with bounded retries and always record feed
health (including on failure, so a broken feed is visible). The ``ingest_*``
helpers are pure DB operations, exercised directly by unit tests.

Enrichment currently scans findings that reference any CVE in Python; for the
self-hosted deployments Vulna targets this is inexpensive, and a targeted index
or a finding↔CVE join table can optimize it later.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.intelligence.epss import EpssData, parse_epss
from app.intelligence.fetchers import Fetcher, FetchError, fetch_with_retry
from app.intelligence.kev import KevCatalog, parse_kev
from app.intelligence.nvd import CveData, cvss_base_score, cvss_vector, parse_nvd
from app.models.change_event import ChangeEvent
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.enums import ChangeEventType, FeedSource, FeedStatus
from app.models.feed_health import FeedHealth
from app.models.finding import Finding
from app.services import risk

Sleep = Callable[[float], Awaitable[None]]
_Record = TypeVar("_Record", CveRecord, ThreatIntelEnrichment)
_Parsed = TypeVar("_Parsed")


@dataclass
class SyncSummary:
    """Outcome of one feed synchronization."""

    source: FeedSource
    status: FeedStatus
    attempts: int = 0
    records_processed: int = 0
    records_changed: int = 0
    change_events: int = 0
    error: str | None = None


@dataclass
class _EnrichResult:
    events: int = 0
    findings_enriched: int = 0
    affected_kev: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- #
# Feed health
# --------------------------------------------------------------------------- #
async def _record_feed_health(
    session: AsyncSession,
    source: FeedSource,
    *,
    status: FeedStatus,
    attempts: int,
    now: datetime,
    processed: int = 0,
    changed: int = 0,
    error: str | None = None,
    source_ts: str | None = None,
) -> None:
    fh = await session.get(FeedHealth, source)
    if fh is None:
        fh = FeedHealth(source=source)
        session.add(fh)
    fh.status = status
    fh.last_attempt_at = now
    fh.attempts = attempts
    if status in (FeedStatus.OK, FeedStatus.DEGRADED):
        fh.last_success_at = now
        fh.records_processed = processed
        fh.records_changed = changed
        fh.last_source_timestamp = source_ts
        fh.error = None
    else:
        fh.error = error


# --------------------------------------------------------------------------- #
# Enrichment of findings from CVE/enrichment data
# --------------------------------------------------------------------------- #
async def _findings_referencing(session: AsyncSession, cve_ids: set[str]) -> list[Finding]:
    """Return findings whose ``cve_ids_json`` intersects ``cve_ids``.

    Filtered in Python for portability across SQLite and PostgreSQL JSON.
    """
    result = await session.execute(select(Finding))
    return [f for f in result.scalars() if cve_ids.intersection(f.cve_ids_json or [])]


async def _load_by_ids(
    session: AsyncSession, model: type[_Record], ids: set[str]
) -> dict[str, _Record]:
    if not ids:
        return {}
    result = await session.execute(select(model).where(model.cve_id.in_(ids)))
    return {row.cve_id: row for row in result.scalars()}


def _emit_finding_event(
    session: AsyncSession,
    finding: Finding,
    event_type: ChangeEventType,
    summary: str,
    severity: str,
) -> None:
    session.add(
        ChangeEvent(
            organization_id=finding.organization_id,
            site_id=finding.site_id,
            asset_id=finding.asset_id,
            scan_job_id=None,
            event_type=event_type,
            severity=severity,
            summary=summary,
        )
    )


async def apply_enrichment(
    session: AsyncSession,
    affected_cve_ids: set[str],
    now: datetime,
    *,
    kev_added: set[str] | None = None,
    epss_crossed: set[str] | None = None,
) -> _EnrichResult:
    """Recompute enrichment for findings referencing any affected CVE and emit
    change events for KEV additions and EPSS threshold crossings."""
    res = _EnrichResult()
    kev_added = kev_added or set()
    epss_crossed = epss_crossed or set()
    if not affected_cve_ids:
        return res

    # Ensure the CVE/enrichment rows just upserted by the caller are queryable
    # (the request session may have autoflush disabled).
    await session.flush()
    findings = await _findings_referencing(session, affected_cve_ids)
    if not findings:
        return res

    referenced: set[str] = set()
    for f in findings:
        referenced.update(f.cve_ids_json or [])
    enr_map = await _load_by_ids(session, ThreatIntelEnrichment, referenced)
    cve_map = await _load_by_ids(session, CveRecord, referenced)

    for f in findings:
        ids = list(f.cve_ids_json or [])
        enrichments = [enr_map[i] for i in ids if i in enr_map]
        known = any(e.is_kev for e in enrichments)

        epss_pairs: list[tuple[float, float | None]] = [
            (e.epss_score, e.epss_percentile)
            for e in enrichments
            if e.epss_score is not None
        ]
        if epss_pairs:
            best_epss = max(epss_pairs, key=lambda t: t[0])
            f.epss_score, f.epss_percentile = best_epss

        if f.cvss_score is None:
            scores = [
                s
                for i in ids
                if i in cve_map
                for s in (cvss_base_score(cve_map[i].cvss_v3_json),)
                if s is not None
            ]
            if scores:
                f.cvss_score = max(scores)
                if f.cvss_vector is None:
                    for i in ids:
                        vec = cvss_vector(cve_map[i].cvss_v3_json) if i in cve_map else None
                        if vec:
                            f.cvss_vector = vec
                            break

        was_known = f.known_exploited
        f.known_exploited = known
        res.findings_enriched += 1

        if not was_known and known and any(i in kev_added for i in ids):
            kev_ids = [i for i in ids if i in kev_added]
            _emit_finding_event(
                session,
                f,
                ChangeEventType.CVE_ADDED_TO_KEV,
                f"{', '.join(kev_ids)} added to CISA KEV — {f.title}",
                "high",
            )
            res.events += 1

        if any(i in epss_crossed for i in ids):
            _emit_finding_event(
                session,
                f,
                ChangeEventType.EPSS_THRESHOLD_CROSSED,
                f"EPSS threshold crossed for {f.title}",
                f.severity.value,
            )
            res.events += 1

        await risk.score_finding(session, f, now=now)

    return res


# --------------------------------------------------------------------------- #
# Ingest (pure DB upserts)
# --------------------------------------------------------------------------- #
async def ingest_nvd(
    session: AsyncSession, cves: list[CveData], *, now: datetime
) -> tuple[int, int, int]:
    processed = changed = 0
    for c in cves:
        processed += 1
        rec = await session.get(CveRecord, c.cve_id)
        if rec is None:
            rec = CveRecord(cve_id=c.cve_id)
            session.add(rec)
            changed += 1
        elif rec.modified_at != c.modified_at:
            changed += 1
        rec.published_at = c.published_at
        rec.modified_at = c.modified_at
        rec.description = c.description
        rec.cvss_v2_json = c.cvss_v2
        rec.cvss_v3_json = c.cvss_v3
        rec.cvss_v4_json = c.cvss_v4
        rec.cwe_ids_json = c.cwe_ids
        rec.cpe_matches_json = c.cpe_matches
        rec.references_json = c.references
        rec.rejected = c.rejected
        rec.last_synced_at = now
    enrich = await apply_enrichment(session, {c.cve_id for c in cves}, now)
    return processed, changed, enrich.events


async def ingest_kev(
    session: AsyncSession, catalog: KevCatalog, *, now: datetime
) -> tuple[int, int, int]:
    processed = changed = 0
    newly_kev: set[str] = set()
    for e in catalog.entries:
        processed += 1
        enr = await session.get(ThreatIntelEnrichment, e.cve_id)
        if enr is None:
            enr = ThreatIntelEnrichment(cve_id=e.cve_id)
            session.add(enr)
        if not enr.is_kev:
            newly_kev.add(e.cve_id)
            changed += 1
        enr.is_kev = True
        enr.kev_date_added = e.date_added
        enr.kev_due_date = e.due_date
        enr.kev_required_action = e.required_action
        enr.known_ransomware_use = e.known_ransomware_use
        enr.last_enriched_at = now
    enrich = await apply_enrichment(
        session, {e.cve_id for e in catalog.entries}, now, kev_added=newly_kev
    )
    return processed, changed, enrich.events


# EPSS publishes a score for essentially every published CVE (~300k rows). Ingest
# must therefore be set-based: a per-row SELECT would mean ~300k sequential DB
# round-trips and the sync would never finish. We load existing rows in bounded
# chunks, update/insert, flush, and release each chunk from the identity map so
# a full feed stays memory-flat.
_EPSS_CHUNK = 5000


async def ingest_epss(
    session: AsyncSession, data: EpssData, *, now: datetime, threshold: float
) -> tuple[int, int, int]:
    epss_date = _parse_date(data.score_date)
    # Dedupe defensively (last score wins) so a CVE never appears twice in a chunk.
    latest = {e.cve_id: e for e in data.entries}
    items = list(latest.values())
    processed = changed = 0
    crossed: set[str] = set()

    for start in range(0, len(items), _EPSS_CHUNK):
        chunk = items[start : start + _EPSS_CHUNK]
        ids = [e.cve_id for e in chunk]
        existing = {
            enr.cve_id: enr
            for enr in (
                await session.execute(
                    select(ThreatIntelEnrichment).where(
                        ThreatIntelEnrichment.cve_id.in_(ids)
                    )
                )
            ).scalars()
        }
        touched: list[ThreatIntelEnrichment] = list(existing.values())
        for e in chunk:
            processed += 1
            enr = existing.get(e.cve_id)
            if enr is None:
                enr = ThreatIntelEnrichment(cve_id=e.cve_id)
                session.add(enr)
                touched.append(enr)
            prev = enr.epss_score
            if prev != e.epss:
                changed += 1
            enr.previous_epss_score = prev
            enr.epss_score = e.epss
            enr.epss_percentile = e.percentile
            enr.epss_date = epss_date
            enr.last_enriched_at = now
            if (prev is None or prev < threshold) and e.epss >= threshold:
                crossed.add(e.cve_id)
        await session.flush()
        # The rows are persisted for this transaction; drop them from the identity
        # map so the next chunk starts clean (findings enrichment below re-reads the
        # few CVEs it needs from the DB).
        for enr in touched:
            session.expunge(enr)

    enrich = await apply_enrichment(session, set(latest), now, epss_crossed=crossed)
    return processed, changed, enrich.events


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Sync orchestration (fetch + retry + ingest + health)
# --------------------------------------------------------------------------- #
async def sync_nvd(
    session: AsyncSession,
    fetcher: Fetcher,
    *,
    settings: Settings,
    now: datetime,
    retries: int = 3,
    sleep: Sleep = asyncio.sleep,
) -> SyncSummary:
    params = {"resultsPerPage": "2000"}
    if settings.nvd_api_key:
        params["apiKey"] = settings.nvd_api_key
    return await _sync(
        session,
        FeedSource.NVD,
        settings.nvd_api_url,
        fetcher,
        parse=lambda raw: parse_nvd(raw),
        ingest=lambda parsed: ingest_nvd(session, parsed, now=now),
        source_ts=lambda parsed: now.isoformat(),
        now=now,
        retries=retries,
        sleep=sleep,
        params=params,
    )


async def sync_kev(
    session: AsyncSession,
    fetcher: Fetcher,
    *,
    settings: Settings,
    now: datetime,
    retries: int = 3,
    sleep: Sleep = asyncio.sleep,
) -> SyncSummary:
    return await _sync(
        session,
        FeedSource.KEV,
        settings.kev_feed_url,
        fetcher,
        parse=lambda raw: parse_kev(raw),
        ingest=lambda parsed: ingest_kev(session, parsed, now=now),
        source_ts=lambda parsed: parsed.date_released,
        now=now,
        retries=retries,
        sleep=sleep,
    )


async def sync_epss(
    session: AsyncSession,
    fetcher: Fetcher,
    *,
    settings: Settings,
    now: datetime,
    retries: int = 3,
    sleep: Sleep = asyncio.sleep,
) -> SyncSummary:
    return await _sync(
        session,
        FeedSource.EPSS,
        settings.epss_feed_url,
        fetcher,
        parse=lambda raw: parse_epss(raw),
        ingest=lambda parsed: ingest_epss(
            session, parsed, now=now, threshold=settings.epss_alert_threshold
        ),
        source_ts=lambda parsed: parsed.score_date,
        now=now,
        retries=retries,
        sleep=sleep,
    )


async def _sync(
    session: AsyncSession,
    source: FeedSource,
    url: str,
    fetcher: Fetcher,
    *,
    parse: Callable[[bytes], _Parsed],
    ingest: Callable[[_Parsed], Awaitable[tuple[int, int, int]]],
    source_ts: Callable[[_Parsed], str | None],
    now: datetime,
    retries: int,
    sleep: Sleep,
    params: dict[str, str] | None = None,
) -> SyncSummary:
    try:
        raw, attempts = await fetch_with_retry(
            fetcher, url, params=params, retries=retries, sleep=sleep
        )
        parsed = parse(raw)
        processed, changed, events = await ingest(parsed)
    except (FetchError, ValueError) as exc:
        await _record_feed_health(
            session, source, status=FeedStatus.FAILED, attempts=retries + 1, now=now, error=str(exc)
        )
        # Persist so the feed-health row is visible and upserted (not duplicated)
        # if this session runs several syncs before committing.
        await session.flush()
        return SyncSummary(source=source, status=FeedStatus.FAILED, error=str(exc))
    status = FeedStatus.OK if attempts == 1 else FeedStatus.DEGRADED
    await _record_feed_health(
        session,
        source,
        status=status,
        attempts=attempts,
        now=now,
        processed=processed,
        changed=changed,
        source_ts=source_ts(parsed),
    )
    await session.flush()
    return SyncSummary(
        source=source,
        status=status,
        attempts=attempts,
        records_processed=processed,
        records_changed=changed,
        change_events=events,
    )
