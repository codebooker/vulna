"""VulnaWatch feed endpoints: health dashboard and manual sync triggers.

Feed health is readable by any authenticated user so operators can see whether
CVE/KEV/EPSS intelligence is current. Triggering a sync fetches from upstream
and is therefore restricted to administrators.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.intelligence.fetchers import HttpFetcher
from app.models.enums import FeedSource, FeedStatus
from app.models.feed_health import FeedHealth
from app.models.user import User
from app.schemas.intelligence import FeedHealthRead, SyncResultRead
from app.services import intelligence as intel
from app.services.audit import record_audit

router = APIRouter(
    prefix="/feeds",
    tags=["feeds"],
    dependencies=[Depends(require_permission("feeds.read"))],
)

_SYNC_FUNCS = {
    FeedSource.NVD: intel.sync_nvd,
    FeedSource.KEV: intel.sync_kev,
    FeedSource.EPSS: intel.sync_epss,
}


def _with_derived_status(fh: FeedHealth, settings: Settings, now: datetime) -> FeedHealthRead:
    """Report a successful-but-old feed as ``stale`` at read time."""
    read = FeedHealthRead.model_validate(fh)
    if read.status in (FeedStatus.OK, FeedStatus.DEGRADED) and read.last_success_at is not None:
        last = read.last_success_at
        if last.tzinfo is None:  # SQLite returns naive datetimes; assume UTC
            last = last.replace(tzinfo=UTC)
        if now - last > timedelta(hours=settings.feed_stale_after_hours):
            read.status = FeedStatus.STALE
    return read


@router.get("/health", response_model=list[FeedHealthRead], summary="Feed health dashboard")
async def feed_health(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[FeedHealthRead]:
    """List every intelligence feed's sync health (build plan Section 14.7)."""
    result = await session.execute(select(FeedHealth))
    existing = {fh.source: fh for fh in result.scalars()}
    now = datetime.now(UTC)
    out: list[FeedHealthRead] = []
    for source in FeedSource:
        fh = existing.get(source)
        if fh is None:
            out.append(
                FeedHealthRead(
                    source=source,
                    status=FeedStatus.NEVER_SYNCED,
                    last_success_at=None,
                    last_attempt_at=None,
                    records_processed=0,
                    records_changed=0,
                    attempts=0,
                    error=None,
                    last_source_timestamp=None,
                    updated_at=now,
                )
            )
        else:
            out.append(_with_derived_status(fh, settings, now))
    return out


@router.post(
    "/{source}/sync", response_model=SyncResultRead, summary="Trigger a feed sync (admin)"
)
async def trigger_sync(
    source: FeedSource,
    admin: Annotated[User, Depends(require_permission("feeds.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SyncResultRead:
    """Fetch and ingest one intelligence feed now (Administrator only)."""
    now = datetime.now(UTC)
    summary = await _SYNC_FUNCS[source](
        session, HttpFetcher(), settings=settings, now=now
    )
    record_audit(
        session,
        action="feed.sync",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="feed",
        target_id=source.value,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"status": summary.status.value, "records_changed": summary.records_changed},
    )
    return SyncResultRead(
        source=summary.source,
        status=summary.status,
        attempts=summary.attempts,
        records_processed=summary.records_processed,
        records_changed=summary.records_changed,
        change_events=summary.change_events,
        error=summary.error,
    )
