"""Permission-scoped dashboard aggregates, durable cache, and comparisons."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.models.passive_inventory import (
    AnalyticsCacheEntry,
    AssetInventoryState,
    ConnectorRun,
    DailyFindingAggregate,
    InventoryLifecycleEvent,
    ReconciliationCandidate,
)

CLOSED_STATUSES = frozenset(
    {
        FindingStatus.RESOLVED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
        FindingStatus.SUPPRESSED,
    }
)
CACHE_TTL_SECONDS = 60


def _scope_filters(column: Any, site_ids: set[uuid.UUID] | None) -> list[Any]:
    return [column.in_(site_ids)] if site_ids is not None else []


async def _cached(
    session: AsyncSession,
    organization_id: uuid.UUID,
    cache_key: str,
    *,
    now: datetime,
) -> dict[str, Any] | None:
    entry = await session.scalar(
        select(AnalyticsCacheEntry).where(
            AnalyticsCacheEntry.organization_id == organization_id,
            AnalyticsCacheEntry.site_id.is_(None),
            AnalyticsCacheEntry.cache_key == cache_key,
            AnalyticsCacheEntry.expires_at > now,
        )
    )
    return dict(entry.payload_json) if entry else None


async def _store_cache(
    session: AsyncSession,
    organization_id: uuid.UUID,
    cache_key: str,
    payload: dict[str, Any],
    *,
    now: datetime,
) -> None:
    entry = await session.scalar(
        select(AnalyticsCacheEntry).where(
            AnalyticsCacheEntry.organization_id == organization_id,
            AnalyticsCacheEntry.site_id.is_(None),
            AnalyticsCacheEntry.cache_key == cache_key,
        )
    )
    if entry is None:
        entry = AnalyticsCacheEntry(
            organization_id=organization_id,
            site_id=None,
            cache_key=cache_key,
            payload_json=payload,
            expires_at=now + timedelta(seconds=CACHE_TTL_SECONDS),
        )
        try:
            async with session.begin_nested():
                session.add(entry)
                await session.flush()
        except IntegrityError:
            entry = await session.scalar(
                select(AnalyticsCacheEntry).where(
                    AnalyticsCacheEntry.organization_id == organization_id,
                    AnalyticsCacheEntry.cache_key == cache_key,
                )
            )
            if entry is None:
                raise
            entry.payload_json = payload
            entry.expires_at = now + timedelta(seconds=CACHE_TTL_SECONDS)
    else:
        entry.payload_json = payload
        entry.expires_at = now + timedelta(seconds=CACHE_TTL_SECONDS)


async def build_dashboard(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    site_ids: set[uuid.UUID] | None,
    now: datetime | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Build constant-query-count summary; no finding rows are loaded into Python."""

    now = now or datetime.now(UTC)
    scope_key = "all" if site_ids is None else ",".join(sorted(str(item) for item in site_ids))
    cache_key = f"dashboard:v1:{scope_key}"
    if use_cache and (cached := await _cached(session, organization_id, cache_key, now=now)):
        cached["cache"] = "hit"
        return cached

    finding_scope = _scope_filters(Finding.site_id, site_ids)
    status_rows = (
        await session.execute(
            select(Finding.status, func.count())
            .where(Finding.organization_id == organization_id, *finding_scope)
            .group_by(Finding.status)
        )
    ).all()
    severity_rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .where(Finding.organization_id == organization_id, *finding_scope)
            .group_by(Finding.severity)
        )
    ).all()
    inventory_scope = _scope_filters(AssetInventoryState.site_id, site_ids)
    inventory_rows = (
        await session.execute(
            select(AssetInventoryState.state, func.count())
            .where(AssetInventoryState.organization_id == organization_id, *inventory_scope)
            .group_by(AssetInventoryState.state)
        )
    ).all()
    run_scope = _scope_filters(ConnectorRun.site_id, site_ids)
    run_rows = (
        await session.execute(
            select(ConnectorRun.status, func.count())
            .where(ConnectorRun.organization_id == organization_id, *run_scope)
            .group_by(ConnectorRun.status)
        )
    ).all()
    reconciliation_scope = _scope_filters(ReconciliationCandidate.site_id, site_ids)
    pending = await session.scalar(
        select(func.count())
        .select_from(ReconciliationCandidate)
        .where(
            ReconciliationCandidate.organization_id == organization_id,
            ReconciliationCandidate.status == "pending",
            *reconciliation_scope,
        )
    )
    breached = await session.scalar(
        select(func.count())
        .select_from(Finding)
        .where(
            Finding.organization_id == organization_id,
            Finding.status.notin_(CLOSED_STATUSES),
            Finding.due_at.is_not(None),
            Finding.due_at < now,
            *finding_scope,
        )
    )
    statuses = {status.value: int(count) for status, count in status_rows}
    severities = {severity.value: int(count) for severity, count in severity_rows}
    inventory = {state.value: int(count) for state, count in inventory_rows}
    payload: dict[str, Any] = {
        "generated_at": now.isoformat(),
        "scope": {"site_ids": None if site_ids is None else sorted(str(item) for item in site_ids)},
        "findings": {
            "total": sum(statuses.values()),
            "open": sum(
                count
                for key, count in statuses.items()
                if FindingStatus(key) not in CLOSED_STATUSES
            ),
            "closed": sum(
                count for key, count in statuses.items() if FindingStatus(key) in CLOSED_STATUSES
            ),
            "breached": int(breached or 0),
            "by_status": statuses,
            "by_severity": severities,
        },
        "inventory": {
            "total": sum(inventory.values()),
            "by_state": inventory,
            "pending_reconciliation": int(pending or 0),
        },
        "connector_runs": {status.value: int(count) for status, count in run_rows},
        "cache": "miss",
    }
    await _store_cache(session, organization_id, cache_key, payload, now=now)
    return payload


async def refresh_daily_aggregates(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> int:
    """Upsert organization and per-site daily snapshots from current state."""

    now = now or datetime.now(UTC)
    site_ids = set(
        (
            await session.execute(
                select(Finding.site_id).where(Finding.organization_id == organization_id).distinct()
            )
        ).scalars()
    )
    inventory_site_ids = set(
        (
            await session.execute(
                select(AssetInventoryState.site_id)
                .where(AssetInventoryState.organization_id == organization_id)
                .distinct()
            )
        ).scalars()
    )
    scopes: list[uuid.UUID | None] = [None, *sorted(site_ids | inventory_site_ids, key=str)]
    changed = 0
    for site_id in scopes:
        dashboard = await build_dashboard(
            session,
            organization_id,
            site_ids={site_id} if site_id else None,
            now=now,
            use_cache=False,
        )
        row = await session.scalar(
            select(DailyFindingAggregate).where(
                DailyFindingAggregate.organization_id == organization_id,
                (
                    DailyFindingAggregate.site_id == site_id
                    if site_id
                    else DailyFindingAggregate.site_id.is_(None)
                ),
                DailyFindingAggregate.aggregate_date == now.date(),
            )
        )
        if row is None:
            row = DailyFindingAggregate(
                organization_id=organization_id,
                site_id=site_id,
                scope_key=str(site_id) if site_id else "all",
                aggregate_date=now.date(),
            )
            session.add(row)
        row.finding_total = dashboard["findings"]["total"]
        row.finding_open = dashboard["findings"]["open"]
        row.finding_resolved = dashboard["findings"]["closed"]
        row.finding_breached = dashboard["findings"]["breached"]
        row.severity_json = dashboard["findings"]["by_severity"]
        row.inventory_state_json = dashboard["inventory"]["by_state"]
        changed += 1
    return changed


async def history(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    site_ids: set[uuid.UUID] | None,
    days: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    start = now.date() - timedelta(days=days - 1)
    aggregate_filters: list[Any] = [
        DailyFindingAggregate.organization_id == organization_id,
        DailyFindingAggregate.aggregate_date >= start,
    ]
    if site_ids is None:
        aggregate_filters.append(DailyFindingAggregate.site_id.is_(None))
    else:
        aggregate_filters.append(DailyFindingAggregate.site_id.in_(site_ids))
    rows = (
        (
            await session.execute(
                select(DailyFindingAggregate)
                .where(*aggregate_filters)
                .order_by(DailyFindingAggregate.aggregate_date)
            )
        )
        .scalars()
        .all()
    )
    events = (
        (
            await session.execute(
                select(InventoryLifecycleEvent)
                .where(
                    InventoryLifecycleEvent.organization_id == organization_id,
                    InventoryLifecycleEvent.created_at
                    >= datetime.combine(start, datetime.min.time(), UTC),
                    *_scope_filters(InventoryLifecycleEvent.site_id, site_ids),
                )
                .order_by(InventoryLifecycleEvent.created_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return {
        "days": days,
        "daily": [
            {
                "date": row.aggregate_date.isoformat(),
                "site_id": str(row.site_id) if row.site_id else None,
                "finding_total": row.finding_total,
                "finding_open": row.finding_open,
                "finding_resolved": row.finding_resolved,
                "finding_breached": row.finding_breached,
                "severity": row.severity_json,
                "inventory_state": row.inventory_state_json,
            }
            for row in rows
        ],
        "events": [
            {
                "id": str(event.id),
                "asset_id": str(event.asset_id),
                "site_id": str(event.site_id),
                "previous_state": event.previous_state.value if event.previous_state else None,
                "new_state": event.new_state.value,
                "reason": event.reason,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ],
    }


async def compare_periods(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    site_ids: set[uuid.UUID] | None,
    first_start: date,
    first_end: date,
    second_start: date,
    second_end: date,
) -> dict[str, Any]:
    async def summarize(start: date, end: date) -> dict[str, Any]:
        filters: list[Any] = [
            DailyFindingAggregate.organization_id == organization_id,
            DailyFindingAggregate.aggregate_date >= start,
            DailyFindingAggregate.aggregate_date <= end,
        ]
        if site_ids is None:
            filters.append(DailyFindingAggregate.site_id.is_(None))
        else:
            filters.append(DailyFindingAggregate.site_id.in_(site_ids))
        rows = (
            (await session.execute(select(DailyFindingAggregate).where(*filters))).scalars().all()
        )
        severity: Counter[str] = Counter()
        inventory: Counter[str] = Counter()
        for row in rows:
            severity.update(row.severity_json)
            inventory.update(row.inventory_state_json)
        count = len(rows)
        return {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "snapshots": count,
            "average_open_findings": (
                round(sum(row.finding_open for row in rows) / count, 2) if count else 0
            ),
            "average_breached_findings": (
                round(sum(row.finding_breached for row in rows) / count, 2) if count else 0
            ),
            "severity_snapshot_totals": dict(severity),
            "inventory_snapshot_totals": dict(inventory),
        }

    first = await summarize(first_start, first_end)
    second = await summarize(second_start, second_end)
    return {
        "first": first,
        "second": second,
        "change": {
            "average_open_findings": round(
                second["average_open_findings"] - first["average_open_findings"], 2
            ),
            "average_breached_findings": round(
                second["average_breached_findings"] - first["average_breached_findings"], 2
            ),
        },
    }
