"""Safe demo mode endpoints (Phase 30).

Demo mode seeds sample assets and findings so the interface can be evaluated
without scanning. While it is on, real scan jobs are refused (see the guard in the
jobs API), so the demo can never contact a real target. Enabling/disabling is an
administrator action and is audited.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.db.session import get_session
from app.models.organization import Organization
from app.models.user import User
from app.services import demo
from app.services.audit import record_audit

router = APIRouter(
    prefix="/demo",
    tags=["demo"],
    dependencies=[Depends(require_permission("demo.read"))],
)


@router.get("/status", summary="Demo mode status")
async def demo_status(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = await _org(session, current_user.organization_id)
    return await demo.status(session, org)


@router.post("/enable", summary="Enable demo mode and seed sample data (admin)")
async def enable(
    admin: Annotated[User, Depends(require_permission("demo.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    org = await _org(session, admin.organization_id)
    result = await demo.enable_demo(session, org)
    record_audit(
        session, action="demo.enabled", actor=admin, organization_id=admin.organization_id,
        target_type="demo", source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.commit()
    return result


@router.post("/disable", summary="Disable demo mode and remove sample data (admin)")
async def disable(
    admin: Annotated[User, Depends(require_permission("demo.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    org = await _org(session, admin.organization_id)
    result = await demo.disable_demo(session, org)
    record_audit(
        session, action="demo.disabled", actor=admin, organization_id=admin.organization_id,
        target_type="demo", source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.commit()
    return result


async def _org(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="organization not found")
    return org
