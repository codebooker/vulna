"""Notification channels, delivery history, test, and dispatch (Phase 29).

Configure and test email or webhook notifications from the UI without editing
environment files. Configuration requires an administrator and is audited;
credentials are stored encrypted and never returned. Webhook destinations are
SSRF-validated at configuration, test, and send time.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.notification import NotificationChannel, NotificationDelivery
from app.models.user import User
from app.services import notifications as core
from app.services import notify
from app.services.audit import record_audit

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    channel_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str | None = Field(default=None, max_length=1024)
    events: list[str] = Field(default_factory=list)
    policy: str = "immediate"
    quiet_start_hour: int | None = Field(default=None, ge=0, le=23)
    quiet_end_hour: int | None = Field(default=None, ge=0, le=23)


class ChannelUpdate(BaseModel):
    events: list[str] | None = None
    policy: str | None = None
    enabled: bool | None = None
    quiet_start_hour: int | None = Field(default=None, ge=0, le=23)
    quiet_end_hour: int | None = Field(default=None, ge=0, le=23)


class SecretRotate(BaseModel):
    secret: str = Field(min_length=1, max_length=1024)


@router.get("/events", summary="Notification event catalogue")
async def event_catalog(current_user: CurrentUser) -> dict[str, Any]:
    return {"events": [{"type": k, "label": v} for k, v in core.EVENT_CATALOG.items()],
            "policies": [p.value for p in core.Policy]}


@router.get("/channels", summary="List notification channels")
async def list_channels(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    rows = (
        await session.execute(
            select(NotificationChannel).where(
                NotificationChannel.organization_id == current_user.organization_id
            )
        )
    ).scalars().all()
    return {"channels": [notify.redact_channel(c) for c in rows]}


@router.post("/channels", summary="Create a notification channel (admin)", status_code=201)
async def create_channel(
    payload: ChannelCreate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    try:
        channel = notify.build_channel(
            settings, admin.organization_id, admin.id,
            name=payload.name, channel_type=payload.channel_type, config=payload.config,
            secret=payload.secret, events=payload.events, policy=payload.policy,
            quiet_start_hour=payload.quiet_start_hour, quiet_end_hour=payload.quiet_end_hour,
        )
    except (notify.ChannelError, core.NotificationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    session.add(channel)
    record_audit(
        session, action="notification.channel_created", actor=admin,
        organization_id=admin.organization_id, target_type="notification_channel",
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"channel_type": payload.channel_type},
    )
    await session.commit()
    return notify.redact_channel(channel)


@router.patch("/channels/{channel_id}", summary="Update a channel (admin)")
async def update_channel(
    channel_id: uuid.UUID,
    payload: ChannelUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    channel = await _get_channel(session, channel_id, admin.organization_id)
    if payload.events is not None:
        try:
            notify._validate_events(payload.events)
        except notify.ChannelError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        channel.events_json = payload.events
    if payload.policy is not None:
        if payload.policy not in {p.value for p in core.Policy}:
            raise HTTPException(status_code=422, detail=f"Unknown policy '{payload.policy}'.")
        channel.policy = payload.policy
    if payload.enabled is not None:
        channel.enabled = payload.enabled
    if payload.quiet_start_hour is not None:
        channel.quiet_start_hour = payload.quiet_start_hour
    if payload.quiet_end_hour is not None:
        channel.quiet_end_hour = payload.quiet_end_hour
    await session.commit()
    return notify.redact_channel(channel)


@router.post("/channels/{channel_id}/rotate-secret", summary="Rotate a channel secret (admin)")
async def rotate_secret(
    channel_id: uuid.UUID,
    payload: SecretRotate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    channel = await _get_channel(session, channel_id, admin.organization_id)
    notify.rotate_secret(settings, channel, payload.secret)
    record_audit(
        session, action="notification.secret_rotated", actor=admin,
        organization_id=admin.organization_id, target_type="notification_channel",
        target_id=channel.id, source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.commit()
    return {"rotated": True}


@router.delete("/channels/{channel_id}", summary="Delete a channel (admin)")
async def delete_channel(
    channel_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    channel = await _get_channel(session, channel_id, admin.organization_id)
    await session.delete(channel)
    await session.commit()
    return {"deleted": True}


@router.post("/channels/{channel_id}/test", summary="Send a test notification (admin)")
async def test_channel(
    channel_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Send a test through the same validation and audit path as real delivery."""
    channel = await _get_channel(session, channel_id, admin.organization_id)
    event = core.NotificationEvent(
        type=core.EventType.SCAN_COMPLETED,
        title="Vulna test notification",
        summary="This is a test from the Vulna notification settings.",
        severity="info",
    )
    secret = (
        core.decrypt_secret(settings.require_secret_key(), channel.encrypted_secret)
        if channel.encrypted_secret
        else None
    )
    ok, error = True, None
    try:
        notify.RealSender().send(channel, secret, [event], settings.public_base_url or "")
    except Exception as exc:  # noqa: BLE001 - report the failure to the operator
        ok, error = False, str(exc)
    record_audit(
        session, action="notification.tested", actor=admin,
        organization_id=admin.organization_id, target_type="notification_channel",
        target_id=channel.id, source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id, metadata={"ok": ok},
    )
    await session.commit()
    if not ok:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Test failed: {error}")
    return {"ok": True}


@router.get("/deliveries", summary="Delivery history")
async def deliveries(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
) -> dict[str, Any]:
    rows = (
        await session.execute(
            select(NotificationDelivery)
            .where(NotificationDelivery.organization_id == current_user.organization_id)
            .order_by(desc(NotificationDelivery.created_at))
            .limit(min(limit, 200))
        )
    ).scalars().all()
    return {
        "deliveries": [
            {
                "id": str(d.id),
                "channel_id": str(d.channel_id),
                "event_type": d.event_type,
                "status": d.status,
                "attempts": d.attempts,
                "last_error": d.last_error,
                "title": d.title,
                "created_at": d.created_at.isoformat(),
                "sent_at": d.sent_at.isoformat() if d.sent_at else None,
            }
            for d in rows
        ]
    }


@router.post("/dispatch", summary="Send pending notifications (admin)")
async def dispatch(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, int]:
    result = await notify.dispatch_pending(
        session, admin.organization_id, notify.RealSender(), settings, datetime.now(UTC)
    )
    await session.commit()
    return result


async def _get_channel(
    session: AsyncSession, channel_id: uuid.UUID, org_id: uuid.UUID
) -> NotificationChannel:
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None or channel.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="channel not found")
    return channel
