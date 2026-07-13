"""Reap stale scan jobs so a dead or stalled scout doesn't leave work hanging.

A scout can accept a job and then die, lose its link, or hang mid-scan and never
report a terminal status. Without a reaper the job sits ``running`` forever and,
worse, a full-spectrum workflow waiting on it never advances. This sweep expires
any active job past its envelope ``expires_at`` and fails the linked workflow's
scanning stage so the run proceeds to its tail.

It runs opportunistically on probe heartbeats (org-scoped, a cheap indexed query)
and can be triggered directly by an administrator.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import JobMode, JobStatus
from app.models.scan_job import ScanJob
from app.services import pentest as pentest_service
from app.services import workflow_dispatch

# Non-terminal statuses a stalled job can be stuck in.
_ACTIVE = (JobStatus.QUEUED, JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def reap_stale_jobs(
    session: AsyncSession,
    settings: Settings,
    *,
    organization_id: uuid.UUID | None = None,
    site_ids: set[uuid.UUID] | None = None,
    now: datetime | None = None,
) -> int:
    """Expire active jobs past their deadline and fail any linked workflow stage.

    Scoped to ``organization_id`` when given. Returns the number reaped.
    """
    now = now or datetime.now(UTC)
    stmt = select(ScanJob).where(ScanJob.status.in_(_ACTIVE))
    if organization_id is not None:
        stmt = stmt.where(ScanJob.organization_id == organization_id)
    if site_ids is not None:
        stmt = stmt.where(ScanJob.site_id.in_(site_ids))

    reaped = 0
    for job in (await session.execute(stmt)).scalars():
        if _aware(job.expires_at) > now:
            continue
        job.status = JobStatus.EXPIRED
        job.finished_at = now
        job.error_code = job.error_code or "timeout"
        job.error_message = (
            job.error_message or "job expired before completion (scout stalled or offline)"
        )
        # Fail the scanning stage of any workflow waiting on this job.
        await workflow_dispatch.on_scan_job_terminal(session, settings, job, JobStatus.EXPIRED)
        # A pentest job whose scout went silent: close the session cleanup-pending
        # (teardown is uncertain until verified).
        if job.mode == JobMode.CONTROLLED_PENTEST:
            await pentest_service.complete_session_for_job(
                session, job=job, job_status=JobStatus.EXPIRED, evidence=None, now=now
            )
        reaped += 1
    return reaped
