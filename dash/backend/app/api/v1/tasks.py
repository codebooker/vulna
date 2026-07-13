"""Administrator task health, history, cancellation, and retry APIs."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import StepUpIdentity, require_permission
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.background_task import BackgroundTask, WorkerHeartbeat
from app.models.enums import BackgroundTaskStatus
from app.models.user import User
from app.schemas.background_task import BackgroundTaskRead, TaskHealthRead, WorkerHeartbeatRead
from app.schemas.common import Page
from app.services import background_tasks
from app.services.audit import record_audit

router = APIRouter(prefix="/tasks", tags=["tasks"])


def _visible(actor: User) -> ColumnElement[bool]:
    return BackgroundTask.organization_id == actor.organization_id


async def _owned_task(
    session: AsyncSession,
    actor: User,
    task_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> BackgroundTask:
    statement = select(BackgroundTask).where(BackgroundTask.id == task_id, _visible(actor))
    if for_update:
        statement = statement.with_for_update()
    task = await session.scalar(statement)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.get("", response_model=Page[BackgroundTaskRead])
async def list_tasks(
    actor: Annotated[User, Depends(require_permission("tasks.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    task_status: Annotated[BackgroundTaskStatus | None, Query(alias="status")] = None,
    task_type: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[BackgroundTaskRead]:
    filters = [_visible(actor)]
    if task_status is not None:
        filters.append(BackgroundTask.status == task_status)
    if task_type is not None:
        filters.append(BackgroundTask.task_type == task_type)
    total = int(
        await session.scalar(select(func.count()).select_from(BackgroundTask).where(*filters)) or 0
    )
    rows = list(
        (
            await session.execute(
                select(BackgroundTask)
                .where(*filters)
                .order_by(BackgroundTask.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[BackgroundTaskRead](
        items=[BackgroundTaskRead.model_validate(task) for task in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/health", response_model=TaskHealthRead)
async def task_health(
    actor: Annotated[User, Depends(require_permission("tasks.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TaskHealthRead:
    rows = list(
        (
            await session.execute(
                select(BackgroundTask.status, func.count())
                .where(_visible(actor))
                .group_by(BackgroundTask.status)
            )
        ).all()
    )
    workers = list(
        (
            await session.execute(
                select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc())
            )
        ).scalars()
    )
    return TaskHealthRead(
        counts={task_status.value: int(count) for task_status, count in rows},
        workers=[
            WorkerHeartbeatRead.model_validate(worker).model_copy(
                update={"current_task_id": None, "metadata_json": {}}
            )
            for worker in workers
        ],
        stale_after_seconds=max(60, settings.background_task_lease_seconds * 2),
    )


@router.get("/{task_id}", response_model=BackgroundTaskRead)
async def get_task(
    task_id: uuid.UUID,
    actor: Annotated[User, Depends(require_permission("tasks.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> BackgroundTaskRead:
    return BackgroundTaskRead.model_validate(await _owned_task(session, actor, task_id))


@router.post("/{task_id}/cancel", response_model=BackgroundTaskRead)
async def cancel_task(
    task_id: uuid.UUID,
    actor: Annotated[User, Depends(require_permission("tasks.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> BackgroundTaskRead:
    task = await _owned_task(session, actor, task_id, for_update=True)
    if task.status in background_tasks.TERMINAL:
        raise HTTPException(status_code=409, detail="Terminal tasks cannot be cancelled")
    await background_tasks.request_cancellation(session, task)
    record_audit(
        session,
        action="background_task.cancel_requested",
        actor=actor,
        target_type="background_task",
        target_id=task.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"task_type": task.task_type},
    )
    await session.flush()
    return BackgroundTaskRead.model_validate(task)


@router.post("/{task_id}/retry", response_model=BackgroundTaskRead)
async def retry_task(
    task_id: uuid.UUID,
    actor: Annotated[User, Depends(require_permission("tasks.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> BackgroundTaskRead:
    task = await _owned_task(session, actor, task_id, for_update=True)
    try:
        await background_tasks.retry_task(session, task)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit(
        session,
        action="background_task.retried",
        actor=actor,
        target_type="background_task",
        target_id=task.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"task_type": task.task_type, "attempts": task.attempts},
    )
    await session.flush()
    return BackgroundTaskRead.model_validate(task)
