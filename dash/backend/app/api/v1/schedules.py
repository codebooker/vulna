"""Scheduled-scan endpoints.

A schedule fires a recurring non-intrusive vulnerability assessment against a
network. Mutations require an operator/administrator; the background scheduler
fires due schedules, and ``/{id}/run`` fires one immediately.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_roles
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import JobMode, UserRole
from app.models.network import Network
from app.models.scan_schedule import ScanSchedule
from app.models.user import User
from app.schemas.schedule import ScanScheduleCreate, ScanScheduleRead, ScanScheduleUpdate
from app.services import scheduler
from app.services.audit import record_audit

router = APIRouter(prefix="/schedules", tags=["schedules"])

_require_operator = require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)


async def _owned(session: AsyncSession, schedule_id: uuid.UUID, org_id: uuid.UUID) -> ScanSchedule:
    sched = await session.get(ScanSchedule, schedule_id)
    if sched is None or sched.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return sched


@router.post("", response_model=ScanScheduleRead, status_code=status.HTTP_201_CREATED,
             summary="Create a scan schedule")
async def create_schedule(
    payload: ScanScheduleCreate,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ScanScheduleRead:
    net = await session.get(Network, payload.network_id)
    if net is None or net.organization_id != operator.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")
    now = datetime.now(UTC)
    first = payload.first_run_at or (now + timedelta(minutes=payload.interval_minutes))
    sched = ScanSchedule(
        organization_id=operator.organization_id,
        network_id=payload.network_id,
        name=payload.name,
        mode=JobMode.VULNERABILITY_ASSESSMENT,
        interval_minutes=payload.interval_minutes,
        enabled=payload.enabled,
        next_run_at=first,
        created_by=operator.id,
    )
    session.add(sched)
    record_audit(
        session, action="schedule.created", actor=operator,
        organization_id=operator.organization_id, target_type="scan_schedule", target_id=sched.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={
            "network_id": str(payload.network_id),
            "interval_minutes": payload.interval_minutes,
        },
    )
    await session.flush()
    return ScanScheduleRead.model_validate(sched)


@router.get("", response_model=list[ScanScheduleRead], summary="List scan schedules")
async def list_schedules(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ScanScheduleRead]:
    rows = (
        await session.execute(
            select(ScanSchedule)
            .where(ScanSchedule.organization_id == current_user.organization_id)
            .order_by(ScanSchedule.next_run_at)
        )
    ).scalars().all()
    return [ScanScheduleRead.model_validate(r) for r in rows]


@router.patch("/{schedule_id}", response_model=ScanScheduleRead, summary="Update a scan schedule")
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScanScheduleUpdate,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScanScheduleRead:
    sched = await _owned(session, schedule_id, operator.organization_id)
    if payload.name is not None:
        sched.name = payload.name
    if payload.interval_minutes is not None:
        sched.interval_minutes = payload.interval_minutes
    if payload.enabled is not None:
        sched.enabled = payload.enabled
    if payload.next_run_at is not None:
        sched.next_run_at = payload.next_run_at
    return ScanScheduleRead.model_validate(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a scan schedule")
async def delete_schedule(
    schedule_id: uuid.UUID,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    sched = await _owned(session, schedule_id, operator.organization_id)
    await session.delete(sched)


@router.post("/{schedule_id}/run", response_model=ScanScheduleRead, summary="Run a schedule now")
async def run_now(
    schedule_id: uuid.UUID,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScanScheduleRead:
    sched = await _owned(session, schedule_id, operator.organization_id)
    job = await scheduler.fire_schedule(session, settings, sched)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=sched.last_error or "Could not dispatch the scan",
        )
    return ScanScheduleRead.model_validate(sched)
