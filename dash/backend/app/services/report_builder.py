"""Reusable report templates, worker scheduling, delivery, and comparisons."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.background_task import BackgroundTask
from app.models.enums import JobStatus, ReportStatus, ReportTemplateRunStatus, ReportType
from app.models.passive_inventory import (
    ReportTemplate,
    ReportTemplateRun,
    ReportTemplateSchedule,
)
from app.models.scan_job import ScanJob
from app.services import analytics, asset_context, background_tasks, notify
from app.services.notifications import EventType, NotificationEvent
from app.services.reports import generate_reports
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret

ALLOWED_REDACTIONS = frozenset({"network_identifiers", "asset_names", "ownership", "remediation"})
ALLOWED_SECTIONS = frozenset(
    {
        "summary",
        "assets",
        "services",
        "findings",
        "cve_exposure",
        "changes",
        "pentest_sessions",
    }
)


class ReportBuilderError(ValueError):
    """A report template or run request is invalid."""


def validate_definition(
    *,
    report_types: list[ReportType],
    sections: list[str],
    filters: dict[str, Any],
    redaction: dict[str, Any],
    branding: dict[str, Any],
) -> tuple[list[str], list[str], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not report_types or len(set(report_types)) != len(report_types):
        raise ReportBuilderError("report_types must contain unique values")
    unknown_sections = set(sections) - ALLOWED_SECTIONS
    if unknown_sections:
        raise ReportBuilderError("report template contains an unsupported section")
    allowed_filter_keys = {"asset_tag_ids", "asset_group_ids", "date_from", "date_to"}
    if set(filters) - allowed_filter_keys:
        raise ReportBuilderError("report template contains an unsupported filter")
    clean_filters: dict[str, Any] = {}
    for field in ("asset_tag_ids", "asset_group_ids"):
        raw = filters.get(field, [])
        if not isinstance(raw, list) or len(raw) > 50:
            raise ReportBuilderError(f"{field} must contain at most 50 UUIDs")
        try:
            clean_filters[field] = [str(uuid.UUID(str(item))) for item in raw]
        except ValueError as exc:
            raise ReportBuilderError(f"{field} contains an invalid UUID") from exc
    for field in ("date_from", "date_to"):
        if filters.get(field) is not None:
            try:
                clean_filters[field] = date.fromisoformat(str(filters[field])).isoformat()
            except ValueError as exc:
                raise ReportBuilderError(f"{field} must be an ISO date") from exc
    if (
        clean_filters.get("date_from")
        and clean_filters.get("date_to")
        and clean_filters["date_from"] > clean_filters["date_to"]
    ):
        raise ReportBuilderError("date_from must not be after date_to")
    fields = redaction.get("fields", [])
    if not isinstance(fields, list) or set(fields) - ALLOWED_REDACTIONS:
        raise ReportBuilderError("redaction fields are not supported")
    clean_redaction = {"fields": sorted({str(item) for item in fields})}
    if set(branding) - {"display_name", "primary_color"}:
        raise ReportBuilderError("branding contains an unsupported field")
    clean_branding: dict[str, Any] = {}
    if branding.get("display_name"):
        clean_branding["display_name"] = str(branding["display_name"]).strip()[:255]
    if branding.get("primary_color"):
        color = str(branding["primary_color"]).strip().lower()
        if len(color) != 7 or not color.startswith("#"):
            raise ReportBuilderError("primary_color must be a six-digit hex color")
        try:
            int(color[1:], 16)
        except ValueError as exc:
            raise ReportBuilderError("primary_color must be a six-digit hex color") from exc
        clean_branding["primary_color"] = color
    return (
        [item.value for item in report_types],
        list(dict.fromkeys(sections)),
        clean_filters,
        clean_redaction,
        clean_branding,
    )


def encrypt_export_password(settings: Settings, plaintext: str) -> str:
    if not plaintext or len(plaintext) > 255:
        raise ReportBuilderError("export password must contain 1-255 characters")
    if not settings.secret_key:
        raise ReportBuilderError("application secret key is required for report encryption")
    return encrypt_secret(settings.secret_key, SecretPurpose.REPORT_EXPORT_PASSWORD, plaintext)


def decrypt_export_password(settings: Settings, ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    if not settings.secret_key:
        raise ReportBuilderError("application secret key is required for report decryption")
    return decrypt_secret(settings.secret_key, SecretPurpose.REPORT_EXPORT_PASSWORD, ciphertext)


def validate_delivery(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) - {"notify"}:
        raise ReportBuilderError("delivery contains an unsupported field")
    return {"notify": bool(value.get("notify", True))}


async def enqueue_template_run(
    session: AsyncSession,
    template: ReportTemplate,
    *,
    created_by_user_id: uuid.UUID | None,
    schedule: ReportTemplateSchedule | None = None,
    client_idempotency_key: str | None = None,
) -> tuple[ReportTemplateRun, BackgroundTask, bool]:
    run = ReportTemplateRun(
        organization_id=template.organization_id,
        site_id=template.site_id,
        template_id=template.id,
        schedule_id=schedule.id if schedule else None,
        status=ReportTemplateRunStatus.QUEUED,
        template_version=template.version,
        parameters_json={
            "name": template.name,
            "report_types": template.report_types_json,
            "filters": template.filters_json,
            "redaction": template.redaction_json,
            "branding": template.branding_json,
            "sections": template.sections_json,
            "delivery": schedule.delivery_json if schedule else {"notify": False},
        },
        encrypted_export_password=template.encrypted_export_password,
    )
    session.add(run)
    await session.flush()
    key = (
        background_tasks.scoped_idempotency_key(
            f"report-template:{template.id}", client_idempotency_key
        )
        if client_idempotency_key
        else (
            f"report-template:{template.id}:schedule:{schedule.id}:{schedule.next_run_at.isoformat()}"
            if schedule
            else f"report-template:{template.id}:run:{run.id}"
        )
    )
    task, created = await background_tasks.enqueue_task(
        session,
        task_type="report_templates.generate",
        idempotency_key=key,
        payload={"run_id": str(run.id)},
        organization_id=template.organization_id,
        created_by_user_id=created_by_user_id,
        max_attempts=3,
    )
    if not created:
        await session.delete(run)
        existing_id = task.payload_json.get("run_id")
        existing = (
            await session.get(ReportTemplateRun, uuid.UUID(str(existing_id)))
            if existing_id
            else None
        )
        if existing is None:
            raise ReportBuilderError("idempotent template task has no run record")
        return existing, task, False
    run.background_task_id = task.id
    return run, task, True


async def schedule_due_templates(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: datetime,
) -> int:
    schedules = (
        (
            await session.execute(
                select(ReportTemplateSchedule).where(
                    ReportTemplateSchedule.organization_id == organization_id,
                    ReportTemplateSchedule.enabled.is_(True),
                    ReportTemplateSchedule.next_run_at <= now,
                )
            )
        )
        .scalars()
        .all()
    )
    created = 0
    for schedule in schedules:
        template = await session.get(ReportTemplate, schedule.template_id)
        if template is None or not template.enabled:
            schedule.enabled = False
            continue
        _, _, was_created = await enqueue_template_run(
            session, template, created_by_user_id=None, schedule=schedule
        )
        created += int(was_created)
        schedule.last_run_at = now
        while True:
            comparable = (
                schedule.next_run_at
                if schedule.next_run_at.tzinfo
                else schedule.next_run_at.replace(tzinfo=UTC)
            )
            if comparable > now:
                break
            schedule.next_run_at += timedelta(minutes=schedule.interval_minutes)
    return created


async def execute_template_task(
    session: AsyncSession, task: BackgroundTask, settings: Settings
) -> dict[str, Any]:
    run = await session.scalar(
        select(ReportTemplateRun).where(
            ReportTemplateRun.id == uuid.UUID(str(task.payload_json["run_id"])),
            ReportTemplateRun.organization_id == task.organization_id,
        )
    )
    if run is None:
        raise ReportBuilderError("report template run no longer exists")
    if run.status == ReportTemplateRunStatus.SUCCEEDED:
        return {"run_id": str(run.id), "report_ids": run.report_ids_json, "replayed": True}
    template = await session.get(ReportTemplate, run.template_id)
    if template is None or template.organization_id != task.organization_id:
        raise ReportBuilderError("report template ownership is invalid")
    now = datetime.now(UTC)
    run.status = ReportTemplateRunStatus.RUNNING
    run.started_at = now
    try:
        if not template.enabled:
            raise ReportBuilderError("report template is disabled")
        parameters = run.parameters_json
        filters = parameters.get("filters") or {}
        scan_filters: list[Any] = [
            ScanJob.organization_id == template.organization_id,
            ScanJob.status == JobStatus.COMPLETED,
        ]
        if template.site_id:
            scan_filters.append(ScanJob.site_id == template.site_id)
        if filters.get("date_from"):
            date_from = datetime.combine(
                date.fromisoformat(filters["date_from"]),
                datetime.min.time(),
                UTC,
            )
            scan_filters.append(ScanJob.finished_at >= date_from)
        if filters.get("date_to"):
            scan_filters.append(
                ScanJob.finished_at
                < datetime.combine(
                    date.fromisoformat(filters["date_to"]) + timedelta(days=1),
                    datetime.min.time(),
                    UTC,
                )
            )
        scan = await session.scalar(
            select(ScanJob)
            .where(*scan_filters)
            .order_by(ScanJob.finished_at.desc(), ScanJob.created_at.desc())
            .limit(1)
        )
        if scan is None:
            raise ReportBuilderError("no completed scan is available for this template")
        asset_ids = await asset_context.resolve_report_asset_ids(
            session,
            organization_id=template.organization_id,
            site_id=scan.site_id,
            tag_ids=[uuid.UUID(item) for item in filters.get("asset_tag_ids", [])],
            group_ids=[uuid.UUID(item) for item in filters.get("asset_group_ids", [])],
        )
        export_password = decrypt_export_password(settings, run.encrypted_export_password)
        report_types = [ReportType(item) for item in parameters.get("report_types", [])]
        if not report_types:
            raise ReportBuilderError("report run has no snapshotted report types")
        reports = await generate_reports(
            session,
            scan_job=scan,
            report_types=report_types,
            requested_by=task.created_by_user_id,
            settings=settings,
            now=now,
            report_ids={
                ReportType(item): uuid.uuid5(run.id, f"report:{item}")
                for item in parameters["report_types"]
            },
            asset_filter_ids=asset_ids,
            template_options={
                "name": parameters.get("name") or template.name,
                "version": run.template_version,
                "sections": parameters.get("sections") or [],
                "redaction": parameters.get("redaction") or {},
                "branding": parameters.get("branding") or {},
                "filters": filters,
            },
            export_password=export_password,
        )
        failed_reports = [report for report in reports if report.status != ReportStatus.COMPLETED]
        if failed_reports:
            raise ReportBuilderError(
                f"{len(failed_reports)} report artifact(s) failed to generate"
            )
        run.report_ids_json = [str(report.id) for report in reports]
        run.status = ReportTemplateRunStatus.SUCCEEDED
        run.finished_at = now
        run.encrypted_export_password = None
        delivery = parameters.get("delivery") or {}
        if delivery.get("notify"):
            await notify.emit_event(
                session,
                template.organization_id,
                NotificationEvent(
                    type=EventType.REPORT_READY,
                    title=f"Report ready: {parameters.get('name') or template.name}",
                    summary=f"{len(reports)} report artifact(s) were generated.",
                    site_id=str(scan.site_id),
                    object_type="report",
                    object_id=str(reports[0].id) if reports else str(run.id),
                    data={
                        "template": parameters.get("name") or template.name,
                        "artifact_count": len(reports),
                    },
                ),
                now,
            )
    except Exception as exc:  # noqa: BLE001 - durable run history
        run.status = ReportTemplateRunStatus.FAILED
        run.finished_at = now
        error = f"{type(exc).__name__}: {exc}"
        if password := locals().get("export_password"):
            error = error.replace(password, "[REDACTED]")
        run.error = error[:2048]
        await session.flush()
        raise background_tasks.PersistedTaskFailure(run.error) from exc
    return {"run_id": str(run.id), "report_ids": run.report_ids_json}


async def create_comparison_run(
    session: AsyncSession,
    template: ReportTemplate,
    *,
    site_ids: set[uuid.UUID] | None,
    first_start: date,
    first_end: date,
    second_start: date,
    second_end: date,
    created_by_user_id: uuid.UUID,
    now: datetime | None = None,
) -> ReportTemplateRun:
    now = now or datetime.now(UTC)
    comparison = await analytics.compare_periods(
        session,
        template.organization_id,
        site_ids=site_ids,
        first_start=first_start,
        first_end=first_end,
        second_start=second_start,
        second_end=second_end,
    )
    run = ReportTemplateRun(
        organization_id=template.organization_id,
        site_id=template.site_id,
        template_id=template.id,
        status=ReportTemplateRunStatus.SUCCEEDED,
        template_version=template.version,
        parameters_json={
            "kind": "comparison",
            "created_by_user_id": str(created_by_user_id),
            "site_ids": None if site_ids is None else sorted(str(item) for item in site_ids),
        },
        report_ids_json=[],
        comparison_json=comparison,
        started_at=now,
        finished_at=now,
    )
    session.add(run)
    await session.flush()
    return run
