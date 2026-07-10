"""Full-spectrum workflow endpoints: create a run and drive its stages.

The engine owns stage ordering, conditional skipping, the approval pause, safe
continuation after a denial or failure, and the guarantee that cleanup (when a
validation ran), verification, and reporting always run. Each transition is
audited; ``stages_json`` is the per-stage trail.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_roles
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.site import Site
from app.models.user import User
from app.models.workflow_run import WorkflowRun
from app.schemas.common import Page
from app.schemas.workflow import (
    WorkflowAdvance,
    WorkflowApproval,
    WorkflowRunCreate,
    WorkflowRunRead,
)
from app.services import workflow as engine
from app.services.audit import record_audit

router = APIRouter(prefix="/workflows", tags=["workflows"])

_require_operator = require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)
_require_approver = require_roles(UserRole.ADMINISTRATOR, UserRole.PENTEST_APPROVER)


async def _owned_run(session: AsyncSession, run_id: uuid.UUID, org_id: uuid.UUID) -> WorkflowRun:
    run = await session.get(WorkflowRun, run_id)
    if run is None or run.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow run not found")
    return run


@router.post(
    "",
    response_model=WorkflowRunRead,
    status_code=status.HTTP_201_CREATED,
    summary="Start a full-spectrum workflow run",
)
async def create_run(
    payload: WorkflowRunCreate,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> WorkflowRunRead:
    site = await session.get(Site, payload.site_id)
    if site is None or site.organization_id != operator.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    now = datetime.now(UTC)
    run = WorkflowRun(
        organization_id=operator.organization_id,
        site_id=payload.site_id,
        include_web=payload.include_web,
        include_intrusive=payload.include_intrusive,
        stages_json=engine.create_run(
            include_web=payload.include_web, include_intrusive=payload.include_intrusive
        ),
        created_by=operator.id,
    )
    engine.start(run, now)
    session.add(run)
    await session.flush()
    record_audit(
        session,
        action="workflow.started",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="workflow_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"web": payload.include_web, "intrusive": payload.include_intrusive},
    )
    return WorkflowRunRead.model_validate(run)


@router.get("", response_model=Page[WorkflowRunRead], summary="List workflow runs")
async def list_runs(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[WorkflowRunRead]:
    filters = [WorkflowRun.organization_id == current_user.organization_id]
    total = await session.scalar(select(func.count()).select_from(WorkflowRun).where(*filters))
    result = await session.execute(
        select(WorkflowRun)
        .where(*filters)
        .order_by(WorkflowRun.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return Page[WorkflowRunRead](
        items=[WorkflowRunRead.model_validate(r) for r in result.scalars().all()],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{run_id}", response_model=WorkflowRunRead, summary="Get a workflow run")
async def get_run(
    run_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> WorkflowRunRead:
    run = await _owned_run(session, run_id, current_user.organization_id)
    return WorkflowRunRead.model_validate(run)


@router.post(
    "/{run_id}/advance",
    response_model=WorkflowRunRead,
    summary="Complete or fail the current stage",
)
async def advance_run(
    run_id: uuid.UUID,
    payload: WorkflowAdvance,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> WorkflowRunRead:
    run = await _owned_run(session, run_id, operator.organization_id)
    stage_name = engine.current_stage_name(run)
    try:
        engine.advance(run, outcome=payload.outcome, detail=payload.detail, now=datetime.now(UTC))
    except engine.WorkflowError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    flag_modified(run, "stages_json")  # in-place JSON mutation is otherwise not persisted
    record_audit(
        session,
        action="workflow.stage_advanced",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="workflow_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"stage": stage_name, "outcome": payload.outcome.value},
    )
    return WorkflowRunRead.model_validate(run)


@router.post(
    "/{run_id}/approval",
    response_model=WorkflowRunRead,
    summary="Approve or deny the intrusive stage",
)
async def decide_run(
    run_id: uuid.UUID,
    payload: WorkflowApproval,
    approver: Annotated[User, Depends(_require_approver)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> WorkflowRunRead:
    """Decide the workflow's approval pause. Denial continues the workflow safely
    (validation is skipped; verification and reporting still run)."""
    run = await _owned_run(session, run_id, approver.organization_id)
    try:
        engine.decide_intrusive(run, approve=payload.approve, now=datetime.now(UTC))
    except engine.WorkflowError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    flag_modified(run, "stages_json")  # in-place JSON mutation is otherwise not persisted
    record_audit(
        session,
        action="workflow.intrusive_approved" if payload.approve else "workflow.intrusive_denied",
        actor=approver,
        organization_id=approver.organization_id,
        target_type="workflow_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"approved": payload.approve},
    )
    return WorkflowRunRead.model_validate(run)
