"""Change-event (delta) read endpoints.

Change events are append-only records of inventory changes. Any authenticated
user in the organization can read them, filtered by site, asset, scan, or type.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser, require_permission
from app.auth.site_scope import site_scope_clause
from app.db.session import get_session
from app.models.change_event import ChangeEvent
from app.models.enums import ChangeEventType
from app.schemas.change_event import ChangeEventRead
from app.schemas.common import Page

router = APIRouter(
    prefix="/changes",
    tags=["changes"],
    dependencies=[Depends(require_permission("assets.read"))],
)


@router.get("", response_model=Page[ChangeEventRead], summary="List change events")
async def list_changes(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    asset_id: Annotated[uuid.UUID | None, Query(description="Filter by asset")] = None,
    scan_job_id: Annotated[uuid.UUID | None, Query(description="Filter by scan job")] = None,
    event_type: Annotated[ChangeEventType | None, Query(description="Filter by event type")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ChangeEventRead]:
    """List change events for the caller's organization, newest first."""
    filters = [
        ChangeEvent.organization_id == current_user.organization_id,
        site_scope_clause(current_user, ChangeEvent.site_id, permission_key="assets.read"),
    ]
    if site_id is not None:
        filters.append(ChangeEvent.site_id == site_id)
    if asset_id is not None:
        filters.append(ChangeEvent.asset_id == asset_id)
    if scan_job_id is not None:
        filters.append(ChangeEvent.scan_job_id == scan_job_id)
    if event_type is not None:
        filters.append(ChangeEvent.event_type == event_type)

    total = await session.scalar(select(func.count()).select_from(ChangeEvent).where(*filters))
    result = await session.execute(
        select(ChangeEvent)
        .where(*filters)
        .order_by(ChangeEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    events = result.scalars().all()
    return Page[ChangeEventRead](
        items=[ChangeEventRead.model_validate(e) for e in events],
        total=total or 0,
        limit=limit,
        offset=offset,
    )
