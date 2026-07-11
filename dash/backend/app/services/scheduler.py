"""Scan scheduler: fire due scan schedules and advance them to the next slot.

A schedule fires a non-intrusive vulnerability-assessment job against its network
(via the network's bound scout and ranges). ``run_due_schedules`` is a pure sweep
— it finds schedules whose ``next_run_at`` has passed, fires each, and rolls the
next slot forward — so it is fully unit-testable; a background loop calls it on an
interval. A firing failure (no scout, no ranges, validation) is recorded on the
schedule and never stops the sweep.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import JobMode
from app.models.scan_job import ScanJob
from app.models.scan_schedule import ScanSchedule
from app.services import networks
from app.services.jobs import JobValidationError, create_scan_job


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _next_slot(after: datetime, interval_minutes: int, now: datetime) -> datetime:
    """Advance the run time by whole intervals until it is in the future, so a
    scheduler that was down for a while doesn't fire a burst of backlogged runs."""
    nxt = _aware(after) + timedelta(minutes=interval_minutes)
    while nxt <= now:
        nxt += timedelta(minutes=interval_minutes)
    return nxt


async def fire_schedule(
    session: AsyncSession, settings: Settings, schedule: ScanSchedule, now: datetime | None = None
) -> ScanJob | None:
    """Dispatch a scan job for a schedule's network. Records the outcome on the
    schedule and returns the job (or None on failure)."""
    now = now or datetime.now(UTC)
    schedule.last_run_at = now
    schedule.last_job_id = None
    schedule.last_error = None

    # One test per network at a time: skip if the network is already under test.
    if await networks.network_has_active_job(session, schedule.network_id):
        schedule.last_error = "skipped: the network is already under test"
        return None
    probe = await networks.select_network_scout(session, schedule.network_id)
    if probe is None:
        schedule.last_error = "No enrolled scout is bound to the network"
        return None
    targets = await networks.network_cidrs(session, schedule.network_id)
    if not targets:
        schedule.last_error = "The network has no ranges to scan"
        return None
    try:
        job = await create_scan_job(
            session, probe, settings,
            targets=targets,
            mode=JobMode.VULNERABILITY_ASSESSMENT,
            created_by=schedule.created_by,
            network_id=schedule.network_id,
        )
    except JobValidationError as exc:
        schedule.last_error = f"Could not dispatch scan: {exc}"
        return None
    await session.flush()
    schedule.last_job_id = job.id
    return job


async def run_due_schedules(
    session: AsyncSession,
    settings: Settings,
    *,
    organization_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    """Fire every enabled schedule that is due and roll its next run forward.
    Returns the number fired (attempted). Scoped to an org when given."""
    now = now or datetime.now(UTC)
    stmt = select(ScanSchedule).where(
        ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now
    )
    if organization_id is not None:
        stmt = stmt.where(ScanSchedule.organization_id == organization_id)

    fired = 0
    for schedule in (await session.execute(stmt)).scalars():
        await fire_schedule(session, settings, schedule, now)
        schedule.next_run_at = _next_slot(schedule.next_run_at, schedule.interval_minutes, now)
        fired += 1
    return fired
