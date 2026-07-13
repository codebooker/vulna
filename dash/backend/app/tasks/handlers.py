"""Allowlisted task handlers; task payloads never select executable code."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.intelligence.fetchers import HttpFetcher
from app.models.background_task import BackgroundTask
from app.models.enums import FeedSource, ReportType
from app.models.scan_job import ScanJob
from app.services import intelligence, notify, pentest, reaper, risk, scheduler, sla, ticketing
from app.services.reports import generate_reports

TaskHandler = Callable[[AsyncSession, BackgroundTask, Settings], Awaitable[dict[str, Any]]]


async def system_sweep(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    if task.organization_id is None:
        raise ValueError("system sweep requires an organization")
    now = datetime.now(UTC)
    return {
        "schedules": await scheduler.run_due_schedules(
            session, settings, organization_id=task.organization_id, now=now
        ),
        "reaped_jobs": await reaper.reap_stale_jobs(
            session, settings, organization_id=task.organization_id, now=now
        ),
        "expired_pentest_sessions": await pentest.terminate_expired_sessions(
            session, now, organization_id=task.organization_id
        ),
        "purged_pentest_evidence": await pentest.purge_expired_evidence(
            session, now, organization_id=task.organization_id
        ),
        "expired_finding_decisions": await risk.expire_finding_decisions(
            session, now, organization_id=task.organization_id
        ),
        "sla": await sla.sweep_sla_status(
            session, now, organization_id=task.organization_id
        ),
    }


async def dispatch_notifications(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    if task.organization_id is None:
        raise ValueError("notification dispatch requires an organization")
    return await notify.dispatch_pending(
        session, task.organization_id, notify.RealSender(), settings, datetime.now(UTC)
    )


async def sync_feed(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    source = FeedSource(str(task.payload_json["source"]))
    functions = {
        FeedSource.NVD: intelligence.sync_nvd,
        FeedSource.KEV: intelligence.sync_kev,
        FeedSource.EPSS: intelligence.sync_epss,
    }
    summary = await functions[source](
        session, HttpFetcher(), settings=settings, now=datetime.now(UTC)
    )
    return {
        "source": source.value,
        "status": summary.status.value,
        "records_processed": summary.records_processed,
        "records_changed": summary.records_changed,
    }


async def generate_report_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    scan_job_id = uuid.UUID(str(task.payload_json["scan_job_id"]))
    scan_job = await session.scalar(
        select(ScanJob).where(
            ScanJob.id == scan_job_id,
            ScanJob.organization_id == task.organization_id,
        )
    )
    if scan_job is None:
        raise ValueError("scan job no longer exists")
    report_types = [ReportType(str(value)) for value in task.payload_json["report_types"]]
    raw_asset_filter_ids = task.payload_json.get("asset_filter_ids")
    asset_filter_ids = (
        {uuid.UUID(str(value)) for value in raw_asset_filter_ids}
        if raw_asset_filter_ids is not None
        else None
    )
    requested_by_raw = task.payload_json.get("requested_by")
    reports = await generate_reports(
        session,
        scan_job=scan_job,
        report_types=report_types,
        requested_by=(uuid.UUID(str(requested_by_raw)) if requested_by_raw else None),
        settings=settings,
        now=datetime.now(UTC),
        report_ids={
            report_type: uuid.uuid5(task.id, f"report:{report_type.value}")
            for report_type in report_types
        },
        asset_filter_ids=asset_filter_ids,
    )
    return {"report_ids": [str(report.id) for report in reports]}


async def sync_ticket_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    return await ticketing.execute_sync_task(session, task, settings)


HANDLERS: dict[str, TaskHandler] = {
    "system.sweep": system_sweep,
    "notifications.dispatch": dispatch_notifications,
    "feeds.sync": sync_feed,
    "reports.generate": generate_report_task,
    "tickets.sync": sync_ticket_task,
}


async def execute_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    handler = HANDLERS.get(task.task_type)
    if handler is None:
        raise ValueError(f"Unknown task type: {task.task_type}")
    return await handler(session, task, settings)
