"""Home-dashboard aggregation (Phase 22).

Builds the everyday summary a non-specialist needs on login: what needs attention
now (by plain-language priority), what changed recently, which systems were not
assessed, whether Vulna itself is healthy, and the single next recommended action.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.asset import Asset
from app.models.change_event import ChangeEvent
from app.models.enums import FindingStatus, JobStatus
from app.models.finding import Finding
from app.models.network_scope import NetworkScope
from app.models.scan_job import ScanJob
from app.services.health import ComponentHealth, component_health
from app.services.priority import (
    FIX_NOW,
    INFORMATIONAL,
    PLAN,
    PRIORITY_ORDER,
    WATCH,
    classify,
    confidence_label,
)
from app.services.risk import priority_from_score

CLOSED_STATUSES = {
    FindingStatus.RESOLVED,
    FindingStatus.RISK_ACCEPTED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.DUPLICATE,
    FindingStatus.SUPPRESSED,
}

CHANGE_WINDOW_DAYS = 7
STALE_ASSET_DAYS = 14


async def build_summary(
    session: AsyncSession,
    settings: Settings,
    org_id: uuid.UUID,
    now: datetime | None = None,
    *,
    site_ids: set[uuid.UUID] | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)

    finding_filters = [Finding.organization_id == org_id]
    change_filters = [ChangeEvent.organization_id == org_id]
    asset_filters = [Asset.organization_id == org_id]
    scope_filters = [NetworkScope.organization_id == org_id]
    scan_filters = [ScanJob.organization_id == org_id]
    if site_ids is not None:
        finding_filters.append(Finding.site_id.in_(site_ids))
        change_filters.append(ChangeEvent.site_id.in_(site_ids))
        asset_filters.append(Asset.site_id.in_(site_ids))
        scope_filters.append(NetworkScope.site_id.in_(site_ids))
        scan_filters.append(ScanJob.site_id.in_(site_ids))

    # --- Needs attention: classify unresolved findings by everyday priority ---
    unresolved = (
        await session.execute(
            select(Finding).where(
                *finding_filters,
                Finding.status.notin_(CLOSED_STATUSES),
            )
        )
    ).scalars().all()

    counts = {FIX_NOW: 0, PLAN: 0, WATCH: 0, INFORMATIONAL: 0}
    scored: list[tuple[str, str, Finding]] = []
    for f in unresolved:
        if f.risk_score is not None:
            priority, rationale = priority_from_score(f.risk_score)
        else:
            priority, rationale = classify(
                severity=f.severity,
                confidence=f.confidence,
                known_exploited=f.known_exploited,
                epss_score=f.epss_score,
                validation_status=f.validation_status,
            )
        counts[priority] += 1
        scored.append((priority, rationale, f))
    scored.sort(
        key=lambda item: (
            PRIORITY_ORDER[item[0]],
            -(
                item[2].risk_score
                if item[2].risk_score is not None
                else item[2].cvss_score or 0.0
            ),
        )
    )
    top = [
        {
            "id": str(f.id),
            "title": f.title,
            "priority": priority,
            "rationale": rationale,
            "severity": f.severity.value,
            "confidence_label": confidence_label(f.confidence),
            "risk_score": f.risk_score,
            "asset_id": str(f.asset_id) if f.asset_id else None,
        }
        for priority, rationale, f in scored[:5]
    ]

    # --- What changed recently ---
    window_start = now - timedelta(days=CHANGE_WINDOW_DAYS)
    changes = (
        await session.execute(
            select(ChangeEvent)
            .where(*change_filters, ChangeEvent.created_at >= window_start)
            .order_by(ChangeEvent.created_at.desc())
        )
    ).scalars().all()
    by_type = Counter(c.event_type.value for c in changes)
    recent_changes = [
        {
            "event_type": c.event_type.value,
            "summary": c.summary,
            "severity": c.severity,
            "created_at": c.created_at.isoformat(),
        }
        for c in changes[:8]
    ]

    # --- Systems not assessed recently ---
    stale_cutoff = now - timedelta(days=STALE_ASSET_DAYS)
    stale_assets = await session.scalar(
        select(func.count())
        .select_from(Asset)
        .where(
            *asset_filters,
            or_(Asset.last_seen_at.is_(None), Asset.last_seen_at < stale_cutoff),
        )
    )

    approved_scopes = await session.scalar(
        select(func.count())
        .select_from(NetworkScope)
        .where(*scope_filters, NetworkScope.approved_at.is_not(None))
    )
    completed_scans = await session.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(*scan_filters, ScanJob.status == JobStatus.COMPLETED)
    )

    health: ComponentHealth = await component_health(session, settings, now)

    next_action = _recommend(
        counts=counts,
        approved_scopes=int(approved_scopes or 0),
        completed_scans=int(completed_scans or 0),
        stale_assets=int(stale_assets or 0),
    )

    return {
        "health": {
            "application": health.application,
            "database": health.database,
            "local_scout": health.local_scout,
            "scanner_capabilities": health.scanner_capabilities,
            "feeds": health.feeds,
        },
        "needs_attention": {**counts, "top": top},
        "changed_recently": {
            "window_days": CHANGE_WINDOW_DAYS,
            "total": len(changes),
            "by_type": dict(by_type),
            "recent": recent_changes,
        },
        "unassessed": {
            "stale_assets": int(stale_assets or 0),
            "approved_scopes": int(approved_scopes or 0),
            "completed_scans": int(completed_scans or 0),
        },
        "next_action": next_action,
    }


def _recommend(
    *, counts: dict[str, int], approved_scopes: int, completed_scans: int, stale_assets: int
) -> dict[str, str]:
    if counts[FIX_NOW] > 0:
        n = counts[FIX_NOW]
        plural = "s" if n != 1 else ""
        return {
            "kind": "review_fix_now",
            "priority": FIX_NOW,
            "message": f"{n} issue{plural} need fixing now — review the top of the list.",
        }
    if approved_scopes == 0:
        return {
            "kind": "approve_scope",
            "priority": PLAN,
            "message": "Approve a network scope to run your first assessment.",
        }
    if completed_scans == 0:
        return {
            "kind": "run_scan",
            "priority": PLAN,
            "message": "Run your first assessment to see what's on your network.",
        }
    if counts[PLAN] > 0:
        n = counts[PLAN]
        return {
            "kind": "plan_fixes",
            "priority": PLAN,
            "message": f"Plan a fix for {n} issue{'s' if n != 1 else ''}.",
        }
    if stale_assets > 0:
        return {
            "kind": "reassess",
            "priority": WATCH,
            "message": f"{stale_assets} system{'s' if stale_assets != 1 else ''} "
            "haven't been assessed recently.",
        }
    return {
        "kind": "all_clear",
        "priority": INFORMATIONAL,
        "message": "You're all caught up. Nothing needs attention right now.",
    }
