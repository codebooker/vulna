"""Unified maintenance center (Phase 28).

One place for a self-hoster to tell whether Vulna needs attention: updates,
Scouts, scanners/templates, feeds, backups, certificates, storage growth,
retention, failed schedules, stuck jobs, report failures, and plugin health.

This aggregates the Phase 26 diagnostics (so the two never disagree) and adds the
maintenance-specific signals — stuck jobs and reclaimable storage — mapping every
result to a green / warning / action-required state with a specific next step.
Read-only. It has no dependency on the optional monitoring stack, so it stays
usable when Prometheus/Grafana are not installed.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import JobStatus
from app.models.scan_job import ScanJob
from app.services import retention
from app.services.diagnostics import FAIL, OK, WARN, run_diagnostics

# Maintenance states.
GREEN = "ok"
WARNING = "warn"
ACTION = "action"

_DIAG_STATE = {OK: GREEN, WARN: WARNING, FAIL: ACTION}

# A RUNNING job older than this with no completion is treated as stuck.
STUCK_JOB_HOURS = 6


@dataclass
class MaintenanceItem:
    domain: str
    state: str  # ok | warn | action
    summary: str
    detail: str
    action: str
    doc: str


async def run_maintenance(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID, now: datetime | None = None
) -> list[MaintenanceItem]:
    now = now or datetime.now(UTC)
    items: list[MaintenanceItem] = []

    # Reuse the diagnostics picture (updates, scouts, scanners, feeds, certs,
    # storage, failed jobs/reports, backups) so the two surfaces never disagree.
    for d in await run_diagnostics(session, settings, org_id, now):
        items.append(
            MaintenanceItem(
                domain=d.component,
                state=_DIAG_STATE.get(d.status, WARNING),
                summary=d.summary,
                detail=d.impact,
                action=d.next_step,
                doc=d.doc,
            )
        )

    # Maintenance-specific signals.
    items.append(await _stuck_jobs_item(session, org_id, now))
    items.append(await _retention_item(session, org_id, now))
    return items


async def _stuck_jobs_item(
    session: AsyncSession, org_id: uuid.UUID, now: datetime
) -> MaintenanceItem:
    cutoff = now - timedelta(hours=STUCK_JOB_HOURS)
    n = await session.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.organization_id == org_id,
            ScanJob.status == JobStatus.RUNNING,
            ScanJob.started_at.is_not(None),
            ScanJob.started_at < cutoff,
        )
    )
    if n:
        return MaintenanceItem(
            "stuck_jobs", WARNING, f"{n} job(s) running longer than {STUCK_JOB_HOURS}h",
            "a job may be stuck on an unreachable target or an offline Scout",
            "cancel the stuck job(s) and check the Scout with `vulnascout doctor`",
            "docs/deployment.md",
        )
    return MaintenanceItem("stuck_jobs", GREEN, "no stuck jobs", "", "", "docs/deployment.md")


async def _retention_item(
    session: AsyncSession, org_id: uuid.UUID, now: datetime
) -> MaintenanceItem:
    plan = await retention.build_cleanup_plan(
        session, org_id, retention.RetentionPolicy(), now
    )
    if plan.reclaimable_bytes > 0:
        mb = plan.reclaimable_bytes / (1024 * 1024)
        return MaintenanceItem(
            "retention", WARNING,
            f"{len(plan.eligible)} old item(s) reclaimable (~{mb:.0f} MB)",
            "old raw output and reports can be cleaned up to reclaim space",
            "preview and run a safe cleanup from the Maintenance center",
            "docs/maintenance.md",
        )
    return MaintenanceItem(
        "retention", GREEN, "nothing past retention", "", "", "docs/maintenance.md"
    )


def overall_state(items: list[MaintenanceItem]) -> str:
    states = {i.state for i in items}
    if ACTION in states:
        return ACTION
    if WARNING in states:
        return WARNING
    return GREEN


def summarize(items: list[MaintenanceItem]) -> dict[str, int]:
    counts = {GREEN: 0, WARNING: 0, ACTION: 0}
    for i in items:
        counts[i.state] = counts.get(i.state, 0) + 1
    return counts


def as_dicts(items: list[MaintenanceItem]) -> list[dict[str, str]]:
    return [asdict(i) for i in items]


async def health_report(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID, now: datetime | None = None
) -> dict[str, object]:
    """A self-hosting health summary (the content of a monthly maintenance report).

    Delivery through notification channels arrives with Phase 29; this is the
    on-demand summary an operator (or a future scheduled job) reports on.
    """
    now = now or datetime.now(UTC)
    items = await run_maintenance(session, settings, org_id, now)
    by_domain = {i.domain: i for i in items}

    def state_of(domain: str) -> str:
        item = by_domain.get(domain)
        return item.state if item else GREEN

    action_items = [
        {"domain": i.domain, "action": i.action}
        for i in items
        if i.state in (WARNING, ACTION) and i.action
    ]
    return {
        "generated_at": now.isoformat(),
        "version": settings.version,
        "overall_state": overall_state(items),
        "summary": summarize(items),
        "domains": {
            "updates": state_of("updates"),
            "backups": state_of("backups"),
            "feeds": state_of("feeds"),
            "certificates_ca": state_of("certificate_ca"),
            "certificates_scouts": state_of("certificate_scouts"),
            "storage": state_of("storage"),
            "failed_scans": state_of("scan_jobs"),
            "retention": state_of("retention"),
        },
        "action_items": action_items,
    }
