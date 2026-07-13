"""Reusable report templates, schedules, runs, and comparison reports."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentUser,
    require_permission,
    require_step_up_permission,
)
from app.auth.site_scope import accessible_site_ids, optional_site_scope_clause, require_site_access
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import GrantScopeType, ReportType
from app.models.passive_inventory import (
    ReportTemplate,
    ReportTemplateRun,
    ReportTemplateSchedule,
)
from app.schemas.background_task import BackgroundTaskRead
from app.schemas.passive_inventory import (
    ComparisonRequest,
    ReportTemplateCreate,
    ReportTemplateRead,
    ReportTemplateRunRead,
    ReportTemplateScheduleCreate,
    ReportTemplateScheduleRead,
    ReportTemplateScheduleUpdate,
    ReportTemplateUpdate,
)
from app.services import authorization, report_builder
from app.services.audit import record_audit

router = APIRouter(prefix="/report-templates", tags=["report templates"])


async def _owned_template(
    session: AsyncSession,
    template_id: uuid.UUID,
    actor: CurrentUser,
    *,
    permission_key: str,
) -> ReportTemplate:
    template = await session.scalar(
        select(ReportTemplate).where(
            ReportTemplate.id == template_id,
            ReportTemplate.organization_id == actor.organization_id,
            optional_site_scope_clause(
                actor, ReportTemplate.site_id, permission_key=permission_key
            ),
        )
    )
    if template is None:
        raise HTTPException(status_code=404, detail="Report template not found")
    return template


async def _require_template_scope(
    session: AsyncSession,
    actor: CurrentUser,
    site_id: uuid.UUID | None,
    *,
    permission_key: str,
) -> None:
    if site_id is not None:
        await require_site_access(
            session,
            actor,
            site_id,
            not_found_detail="Site not found",
            permission_key=permission_key,
        )
        return
    if not await authorization.has_permission(
        session,
        actor,
        permission_key,
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=actor.organization_id,
    ):
        raise HTTPException(status_code=403, detail="Organization-wide permission is required")


@router.get(
    "",
    response_model=list[ReportTemplateRead],
    dependencies=[Depends(require_permission("report_templates.read"))],
)
async def list_templates(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[ReportTemplateRead]:
    rows = (
        (
            await session.execute(
                select(ReportTemplate)
                .where(
                    ReportTemplate.organization_id == actor.organization_id,
                    optional_site_scope_clause(
                        actor,
                        ReportTemplate.site_id,
                        permission_key="report_templates.read",
                    ),
                )
                .order_by(ReportTemplate.name)
            )
        )
        .scalars()
        .all()
    )
    return [ReportTemplateRead.from_model(row) for row in rows]


@router.post("", response_model=ReportTemplateRead, status_code=status.HTTP_201_CREATED)
async def create_template(
    payload: ReportTemplateCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReportTemplateRead:
    actor = identity.user
    await _require_template_scope(
        session, actor, payload.site_id, permission_key="report_templates.manage"
    )
    duplicate = await session.scalar(
        select(ReportTemplate.id).where(
            ReportTemplate.organization_id == actor.organization_id,
            ReportTemplate.name == payload.name.strip(),
        )
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Report template name already exists")
    try:
        report_types, sections, filters, redaction, branding = report_builder.validate_definition(
            report_types=payload.report_types,
            sections=payload.sections,
            filters=payload.filters,
            redaction=payload.redaction,
            branding=payload.branding,
        )
        encrypted = (
            report_builder.encrypt_export_password(settings, payload.export_password)
            if payload.export_password
            else None
        )
    except report_builder.ReportBuilderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    template = ReportTemplate(
        organization_id=actor.organization_id,
        site_id=payload.site_id,
        name=payload.name.strip(),
        description=payload.description,
        version=1,
        report_types_json=report_types,
        sections_json=sections,
        filters_json=filters,
        redaction_json=redaction,
        branding_json=branding,
        encrypted_export_password=encrypted,
        enabled=True,
        created_by_user_id=actor.id,
    )
    session.add(template)
    await session.flush()
    record_audit(
        session,
        action="report_template.created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template",
        target_id=template.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "site_id": str(template.site_id) if template.site_id else None,
            "report_types": report_types,
            "has_export_password": bool(encrypted),
        },
    )
    return ReportTemplateRead.from_model(template)


@router.patch("/{template_id}", response_model=ReportTemplateRead)
async def update_template(
    template_id: uuid.UUID,
    payload: ReportTemplateUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReportTemplateRead:
    actor = identity.user
    template = await _owned_template(
        session, template_id, actor, permission_key="report_templates.manage"
    )
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        name = str(changes["name"]).strip()
        duplicate = await session.scalar(
            select(ReportTemplate.id).where(
                ReportTemplate.organization_id == actor.organization_id,
                ReportTemplate.name == name,
                ReportTemplate.id != template.id,
            )
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="Report template name already exists")
        template.name = name
    for field in ("description", "enabled"):
        if field in changes:
            setattr(template, field, changes[field])
    try:
        report_types, sections, filters, redaction, branding = report_builder.validate_definition(
            report_types=(
                changes["report_types"]
                if "report_types" in changes
                else [ReportType(item) for item in template.report_types_json]
            ),
            sections=changes.get("sections", template.sections_json),
            filters=changes.get("filters", template.filters_json),
            redaction=changes.get("redaction", template.redaction_json),
            branding=changes.get("branding", template.branding_json),
        )
        if "export_password" in changes:
            template.encrypted_export_password = report_builder.encrypt_export_password(
                settings, str(changes["export_password"])
            )
        elif changes.get("clear_export_password"):
            template.encrypted_export_password = None
    except report_builder.ReportBuilderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    template.report_types_json = report_types
    template.sections_json = sections
    template.filters_json = filters
    template.redaction_json = redaction
    template.branding_json = branding
    template.version += 1
    record_audit(
        session,
        action="report_template.updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template",
        target_id=template.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "changed_fields": sorted(payload.model_fields_set),
            "version": template.version,
            "has_export_password": bool(template.encrypted_export_password),
        },
    )
    return ReportTemplateRead.from_model(template)


@router.post(
    "/{template_id}/runs",
    response_model=BackgroundTaskRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def queue_template_run(
    template_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", min_length=1, max_length=255)
    ] = None,
) -> BackgroundTaskRead:
    actor = identity.user
    template = await _owned_template(
        session, template_id, actor, permission_key="report_templates.manage"
    )
    run, task, created = await report_builder.enqueue_template_run(
        session,
        template,
        created_by_user_id=actor.id,
        client_idempotency_key=idempotency_key,
    )
    record_audit(
        session,
        action="report_template.run_queued",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"template_id": str(template.id), "idempotent_replay": not created},
    )
    return BackgroundTaskRead.model_validate(task)


@router.post(
    "/{template_id}/schedules",
    response_model=ReportTemplateScheduleRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_schedule(
    template_id: uuid.UUID,
    payload: ReportTemplateScheduleCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReportTemplateScheduleRead:
    actor = identity.user
    template = await _owned_template(
        session, template_id, actor, permission_key="report_templates.manage"
    )
    try:
        delivery = report_builder.validate_delivery(payload.delivery)
    except report_builder.ReportBuilderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    schedule = ReportTemplateSchedule(
        organization_id=template.organization_id,
        site_id=template.site_id,
        template_id=template.id,
        interval_minutes=payload.interval_minutes,
        next_run_at=payload.next_run_at,
        delivery_json=delivery,
        enabled=True,
    )
    session.add(schedule)
    await session.flush()
    record_audit(
        session,
        action="report_template.schedule_created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template_schedule",
        target_id=schedule.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"template_id": str(template.id), "interval_minutes": schedule.interval_minutes},
    )
    return ReportTemplateScheduleRead.model_validate(schedule)


@router.get(
    "/runs",
    response_model=list[ReportTemplateRunRead],
    dependencies=[Depends(require_permission("report_templates.read"))],
)
async def list_template_runs(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[ReportTemplateRunRead]:
    rows = (
        (
            await session.execute(
                select(ReportTemplateRun)
                .where(
                    ReportTemplateRun.organization_id == actor.organization_id,
                    optional_site_scope_clause(
                        actor,
                        ReportTemplateRun.site_id,
                        permission_key="report_templates.read",
                    ),
                )
                .order_by(ReportTemplateRun.created_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return [ReportTemplateRunRead.model_validate(row) for row in rows]


@router.get(
    "/schedules",
    response_model=list[ReportTemplateScheduleRead],
    dependencies=[Depends(require_permission("report_templates.read"))],
)
async def list_template_schedules(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[ReportTemplateScheduleRead]:
    rows = (
        (
            await session.execute(
                select(ReportTemplateSchedule)
                .where(
                    ReportTemplateSchedule.organization_id == actor.organization_id,
                    optional_site_scope_clause(
                        actor,
                        ReportTemplateSchedule.site_id,
                        permission_key="report_templates.read",
                    ),
                )
                .order_by(ReportTemplateSchedule.next_run_at)
            )
        )
        .scalars()
        .all()
    )
    return [ReportTemplateScheduleRead.model_validate(row) for row in rows]


@router.patch("/schedules/{schedule_id}", response_model=ReportTemplateScheduleRead)
async def update_template_schedule(
    schedule_id: uuid.UUID,
    payload: ReportTemplateScheduleUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReportTemplateScheduleRead:
    actor = identity.user
    schedule = await session.scalar(
        select(ReportTemplateSchedule).where(
            ReportTemplateSchedule.id == schedule_id,
            ReportTemplateSchedule.organization_id == actor.organization_id,
            optional_site_scope_clause(
                actor,
                ReportTemplateSchedule.site_id,
                permission_key="report_templates.manage",
            ),
        )
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="Report schedule not found")
    changes = payload.model_dump(exclude_unset=True)
    try:
        if "delivery" in changes:
            schedule.delivery_json = report_builder.validate_delivery(changes["delivery"])
    except report_builder.ReportBuilderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for field in ("interval_minutes", "next_run_at", "enabled"):
        if field in changes:
            setattr(schedule, field, changes[field])
    record_audit(
        session,
        action="report_template.schedule_updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template_schedule",
        target_id=schedule.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(payload.model_fields_set)},
    )
    return ReportTemplateScheduleRead.model_validate(schedule)


@router.post("/{template_id}/comparison", response_model=ReportTemplateRunRead)
async def create_comparison(
    template_id: uuid.UUID,
    payload: ComparisonRequest,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("report_templates.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReportTemplateRunRead:
    actor = identity.user
    template = await _owned_template(
        session, template_id, actor, permission_key="report_templates.manage"
    )
    scope = (
        {template.site_id}
        if template.site_id
        else await accessible_site_ids(session, actor, permission_key="analytics.read")
    )
    run = await report_builder.create_comparison_run(
        session,
        template,
        site_ids=scope,
        first_start=payload.first_start,
        first_end=payload.first_end,
        second_start=payload.second_start,
        second_end=payload.second_end,
        created_by_user_id=actor.id,
        now=datetime.now(UTC),
    )
    record_audit(
        session,
        action="report_template.comparison_created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="report_template_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"template_id": str(template.id)},
    )
    return ReportTemplateRunRead.model_validate(run)
