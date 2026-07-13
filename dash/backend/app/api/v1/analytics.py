"""Permission-aware analytics and event-derived inventory history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser, require_permission
from app.auth.site_scope import accessible_site_ids, require_site_access
from app.db.session import get_session
from app.services import analytics

router = APIRouter(
    prefix="/analytics",
    tags=["analytics"],
    dependencies=[Depends(require_permission("analytics.read"))],
)


async def _requested_scope(
    session: AsyncSession, actor: CurrentUser, site_id: uuid.UUID | None
) -> set[uuid.UUID] | None:
    if site_id is not None:
        await require_site_access(
            session,
            actor,
            site_id,
            not_found_detail="Site not found",
            permission_key="analytics.read",
        )
        return {site_id}
    return await accessible_site_ids(session, actor, permission_key="analytics.read")


@router.get("/dashboard", response_model=dict[str, Any])
async def dashboard(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    response: Response,
    site_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    scope = await _requested_scope(session, actor, site_id)
    result = await analytics.build_dashboard(
        session, actor.organization_id, site_ids=scope, now=datetime.now(UTC)
    )
    response.headers["Cache-Control"] = "private, max-age=60"
    response.headers["Vary"] = "Authorization"
    return result


@router.get("/history", response_model=dict[str, Any])
async def dashboard_history(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    response: Response,
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict[str, Any]:
    scope = await _requested_scope(session, actor, site_id)
    result = await analytics.history(
        session,
        actor.organization_id,
        site_ids=scope,
        days=days,
        now=datetime.now(UTC),
    )
    response.headers["Cache-Control"] = "private, max-age=60"
    response.headers["Vary"] = "Authorization"
    return result
