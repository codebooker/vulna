"""Reap stale scan jobs so a dead or stalled scout doesn't leave work hanging.

A scout can accept a job and then die, lose its link, or hang mid-scan and never
report a terminal status. Without a reaper the job sits ``running`` forever and,
worse, a full-spectrum workflow waiting on it never advances. This sweep expires
any active job past its signed execution limit or envelope ``expires_at`` and
fails the linked workflow's scanning stage so the run proceeds to its tail.

It runs opportunistically on probe heartbeats (org-scoped, a cheap indexed query)
and can be triggered directly by an administrator.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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


def _effective_deadline(job: ScanJob) -> tuple[datetime, str, str]:
    """Return the earliest signed deadline and its safe terminal diagnostic."""
    deadline = _aware(job.expires_at)
    code = "timeout"
    message = "job expired before completion (scout stalled or offline)"

    # The Scout starts its max-duration clock immediately after acceptance. A
    # missing RUNNING update must not buy extra execution time, so accepted_at is
    # the fallback when started_at was never acknowledged by the orchestrator.
    started_at = job.started_at or job.accepted_at
    raw_seconds = (job.limits_json or {}).get("max_duration_seconds")
    if (
        started_at is not None
        and isinstance(raw_seconds, (int, float))
        and not isinstance(raw_seconds, bool)
        and raw_seconds > 0
    ):
        execution_deadline = _aware(started_at) + timedelta(seconds=raw_seconds)
        if execution_deadline < deadline:
            deadline = execution_deadline
            code = "max_duration_exceeded"
            message = (
                "job exceeded its signed maximum duration before the Scout "
                "reported completion"
            )
    return deadline, code, message


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
        deadline, error_code, error_message = _effective_deadline(job)
        if error_code == "max_duration_exceeded":
            # The Scout enforces the hard execution limit locally. Give it one
            # normal offline-detection window to stop descendants, persist any
            # final output, and report cancellation before the server publishes
            # an EXPIRED fallback. This avoids the heartbeat reaper winning the
            # ordinary deadline race while still clearing a lost terminal POST.
            deadline += timedelta(seconds=max(30, settings.probe_offline_after_seconds))
        if deadline > now:
            continue
        job.status = JobStatus.EXPIRED
        job.finished_at = now
        job.estimated_completion_at = None
        job.error_code = job.error_code or error_code
        job.error_message = job.error_message or error_message
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
