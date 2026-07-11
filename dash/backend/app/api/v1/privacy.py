"""Privacy and data-ownership endpoints (Phase 31).

Show exactly what can leave the deployment, what secrets are configured (never
their values), and what an opt-in telemetry payload would contain. Toggles for
telemetry, update checks, feeds, and local analytics are explicit and default to
the privacy-preserving choice; changing them is admin-only and audited.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.organization import Organization
from app.models.user import User
from app.services import privacy
from app.services.audit import record_audit

router = APIRouter(prefix="/privacy", tags=["privacy"])


class PrivacySettingsUpdate(BaseModel):
    telemetry_enabled: bool | None = None
    update_check_enabled: bool | None = None
    intelligence_feeds_enabled: bool | None = None
    local_analytics_enabled: bool | None = None


async def _org(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="organization not found")
    return org


@router.get("/outbound", summary="Outbound connections (what can leave the deployment)")
async def outbound(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    org = await _org(session, current_user.organization_id)
    return {"connections": await privacy.outbound_connections(session, settings, org)}


@router.get("/secrets", summary="Secret inventory (status only, never values)")
async def secrets(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    org = await _org(session, admin.organization_id)
    return {"secrets": await privacy.secret_inventory(session, settings, org)}


@router.get("/settings", summary="Privacy toggles")
async def get_settings_(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = await _org(session, current_user.organization_id)
    return {"settings": privacy.get_privacy_settings(org), "defaults": privacy.PRIVACY_DEFAULTS}


@router.post("/settings", summary="Update privacy toggles (admin)")
async def update_settings(
    payload: PrivacySettingsUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    org = await _org(session, admin.organization_id)
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    result = privacy.set_privacy_settings(org, updates)
    record_audit(
        session, action="privacy.settings_updated", actor=admin,
        organization_id=admin.organization_id, target_type="privacy",
        source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id, metadata={"changed": updates},
    )
    await session.commit()
    return {"settings": result}


@router.get("/telemetry/preview", summary="Preview the anonymous telemetry payload")
async def telemetry_preview(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Show the exact aggregate, anonymous payload telemetry would send, so opt-in
    is an informed choice. Telemetry is off unless explicitly enabled."""
    return await privacy.telemetry_preview(session, settings, current_user.organization_id)


@router.get("/analytics", summary="Local usage analytics (never transmitted)")
async def analytics(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    return await privacy.local_analytics(session, current_user.organization_id)
