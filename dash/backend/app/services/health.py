"""Component health for the single-host (and distributed) deployment.

Distinguishes application, database, local-Scout, scanner-capability, and
intelligence-feed health so an operator can tell *which* part needs attention
(Phase 17). Aggregate/status values only — no sensitive detail.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import FeedStatus, ProbeStatus
from app.models.feed_health import FeedHealth
from app.models.probe import Probe


@dataclass
class ComponentHealth:
    application: str
    database: str
    local_scout: str  # connected | offline | not_enrolled | disabled
    scanner_capabilities: str  # ok | unknown | degraded
    feeds: str  # ok | degraded | stale | failed | never_synced | no_feeds


async def component_health(
    session: AsyncSession, settings: Settings, now: datetime
) -> ComponentHealth:
    # Database: a trivial query proves connectivity.
    try:
        await session.execute(select(1))
        database = "ok"
    except Exception:  # pragma: no cover - defensive
        database = "error"

    # Local Scout: enrolled + recent heartbeat?
    scout = None
    if settings.bootstrap_local_scout:
        scout = await session.scalar(
            select(Probe).where(Probe.name == settings.local_scout_name).limit(1)
        )
        if scout is None or scout.status != ProbeStatus.ENROLLED:
            local_scout = "not_enrolled"
        elif (
            scout.last_seen_at is not None
            and (now.timestamp() - scout.last_seen_at.timestamp())
            <= settings.probe_offline_after_seconds
        ):
            local_scout = "connected"
        else:
            local_scout = "offline"
    else:
        local_scout = "disabled"

    # Scanner capabilities: derived from the local Scout's reported capabilities.
    if scout is not None and scout.capabilities_json:
        scanner_capabilities = "ok" if "nmap" in scout.capabilities_json else "degraded"
    else:
        scanner_capabilities = "unknown"

    # Feeds: worst status across configured intelligence feeds.
    feeds = "no_feeds"
    total = await session.scalar(select(func.count()).select_from(FeedHealth))
    if total:
        statuses = {
            fh.status for fh in (await session.execute(select(FeedHealth))).scalars()
        }
        for level in (
            FeedStatus.FAILED,
            FeedStatus.STALE,
            FeedStatus.NEVER_SYNCED,
            FeedStatus.DEGRADED,
            FeedStatus.OK,
        ):
            if level in statuses:
                feeds = level.value
                break

    return ComponentHealth(
        application="ok",
        database=database,
        local_scout=local_scout,
        scanner_capabilities=scanner_capabilities,
        feeds=feeds,
    )
