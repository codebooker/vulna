"""One-way ticket connector configuration and worker-backed synchronization."""

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
from app.auth.site_scope import site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.finding import Finding
from app.models.ticketing import TicketConnector, TicketSync, TicketSyncEvent
from app.schemas.background_task import BackgroundTaskRead
from app.schemas.ticketing import (
    TicketConnectorCreate,
    TicketConnectorRead,
    TicketConnectorTestRead,
    TicketConnectorUpdate,
    TicketSyncEventRead,
    TicketSyncRead,
    TicketSyncRequest,
)
from app.services import ticketing
from app.services.audit import record_audit
from app.services.notifications import NotificationError, validate_destination

router = APIRouter(prefix="/ticketing", tags=["ticketing"])


async def _owned_connector(
    session: AsyncSession, connector_id: uuid.UUID, organization_id: uuid.UUID
) -> TicketConnector:
    connector = await session.scalar(
        select(TicketConnector).where(
            TicketConnector.id == connector_id,
            TicketConnector.organization_id == organization_id,
        )
    )
    if connector is None:
        raise HTTPException(status_code=404, detail="Ticket connector not found")
    return connector


@router.get(
    "/connectors",
    response_model=list[TicketConnectorRead],
    dependencies=[Depends(require_permission("ticketing.read"))],
)
async def list_connectors(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[TicketConnectorRead]:
    rows = (
        await session.execute(
            select(TicketConnector)
            .where(TicketConnector.organization_id == actor.organization_id)
            .order_by(TicketConnector.name)
        )
    ).scalars()
    return [TicketConnectorRead.from_model(row) for row in rows]


@router.post(
    "/connectors",
    response_model=TicketConnectorRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    payload: TicketConnectorCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("ticketing.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TicketConnectorRead:
    actor = identity.user
    if await session.scalar(
        select(TicketConnector.id).where(
            TicketConnector.organization_id == actor.organization_id,
            TicketConnector.name == payload.name.strip(),
        )
    ):
        raise HTTPException(status_code=409, detail="Ticket connector name already exists")
    try:
        base_url = ticketing.validate_connector_url(str(payload.base_url))
        config = ticketing.validate_public_config(payload.config)
        encrypted = ticketing.encrypt_connector_secret(settings, payload.secret)
    except ticketing.TicketingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    connector = TicketConnector(
        organization_id=actor.organization_id,
        name=payload.name.strip(),
        connector_type=payload.connector_type,
        base_url=base_url,
        project_key=payload.project_key.strip(),
        config_json=config,
        encrypted_secret=encrypted,
        enabled=False,
        close_after_verification=payload.close_after_verification,
        timeout_seconds=payload.timeout_seconds,
        created_by_user_id=actor.id,
    )
    session.add(connector)
    await session.flush()
    record_audit(
        session,
        action="ticket_connector.created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="ticket_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"connector_type": connector.connector_type.value, "has_secret": True},
    )
    return TicketConnectorRead.from_model(connector)


@router.patch("/connectors/{connector_id}", response_model=TicketConnectorRead)
async def update_connector(
    connector_id: uuid.UUID,
    payload: TicketConnectorUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("ticketing.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TicketConnectorRead:
    actor = identity.user
    connector = await _owned_connector(session, connector_id, actor.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("enabled") is True and connector.successful_test_at is None:
        raise HTTPException(
            status_code=409,
            detail="Test the connector successfully before enabling it",
        )
    if "name" in changes:
        name = str(changes["name"]).strip()
        conflict = await session.scalar(
            select(TicketConnector.id).where(
                TicketConnector.organization_id == actor.organization_id,
                TicketConnector.name == name,
                TicketConnector.id != connector.id,
            )
        )
        if conflict:
            raise HTTPException(status_code=409, detail="Ticket connector name already exists")
        connector.name = name
    try:
        if "base_url" in changes:
            connector.base_url = ticketing.validate_connector_url(str(changes["base_url"]))
            connector.successful_test_at = None
            connector.enabled = False
        if "config" in changes:
            connector.config_json = ticketing.validate_public_config(changes["config"])
            connector.successful_test_at = None
            connector.enabled = False
        if "secret" in changes:
            connector.encrypted_secret = ticketing.encrypt_connector_secret(
                settings, str(changes["secret"])
            )
            connector.successful_test_at = None
            connector.enabled = False
    except ticketing.TicketingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for field in ("project_key", "enabled", "close_after_verification", "timeout_seconds"):
        if field in changes:
            setattr(connector, field, changes[field])
    record_audit(
        session,
        action="ticket_connector.updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="ticket_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(payload.model_fields_set), "has_secret": True},
    )
    return TicketConnectorRead.from_model(connector)


@router.post("/connectors/{connector_id}/test", response_model=TicketConnectorTestRead)
async def test_connector(
    connector_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("ticketing.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TicketConnectorTestRead:
    actor = identity.user
    connector = await _owned_connector(session, connector_id, actor.organization_id)
    tested_at = datetime.now(UTC)
    try:
        validate_destination(
            connector.base_url,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )
        metadata = await ticketing.test_connector(connector, settings)
    except (NotificationError, ticketing.TicketingError, OSError, ValueError) as exc:
        connector.successful_test_at = None
        connector.enabled = False
        connector.last_test_error = f"{type(exc).__name__}: {exc}"[:1024]
        result = TicketConnectorTestRead(
            succeeded=False, tested_at=tested_at, error=connector.last_test_error
        )
    else:
        connector.successful_test_at = tested_at
        connector.last_test_error = None
        result = TicketConnectorTestRead(
            succeeded=True, tested_at=tested_at, metadata=metadata
        )
    record_audit(
        session,
        action="ticket_connector.tested",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="ticket_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"succeeded": result.succeeded},
    )
    return result


@router.get(
    "/syncs",
    response_model=list[TicketSyncRead],
    dependencies=[Depends(require_permission("ticketing.read"))],
)
async def list_syncs(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[TicketSyncRead]:
    rows = (
        await session.execute(
            select(TicketSync)
            .where(
                TicketSync.organization_id == actor.organization_id,
                site_scope_clause(actor, TicketSync.site_id, permission_key="ticketing.read"),
            )
            .order_by(TicketSync.updated_at.desc())
        )
    ).scalars()
    return [TicketSyncRead.model_validate(row) for row in rows]


@router.get(
    "/syncs/{sync_id}/events",
    response_model=list[TicketSyncEventRead],
    dependencies=[Depends(require_permission("ticketing.read"))],
)
async def list_sync_events(
    sync_id: uuid.UUID,
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[TicketSyncEventRead]:
    sync = await session.scalar(
        select(TicketSync).where(
            TicketSync.id == sync_id,
            TicketSync.organization_id == actor.organization_id,
            site_scope_clause(actor, TicketSync.site_id, permission_key="ticketing.read"),
        )
    )
    if sync is None:
        raise HTTPException(status_code=404, detail="Ticket sync not found")
    rows = (
        await session.execute(
            select(TicketSyncEvent)
            .where(TicketSyncEvent.sync_id == sync.id)
            .order_by(TicketSyncEvent.created_at.desc())
        )
    ).scalars()
    return [TicketSyncEventRead.model_validate(row) for row in rows]


@router.post(
    "/findings/{finding_id}/sync",
    response_model=BackgroundTaskRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def queue_finding_sync(
    finding_id: uuid.UUID,
    payload: TicketSyncRequest,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("ticketing.sync"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", min_length=1, max_length=255)
    ] = None,
) -> BackgroundTaskRead:
    actor = identity.user
    finding = await session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == actor.organization_id,
            site_scope_clause(actor, Finding.site_id, permission_key="ticketing.sync"),
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    connector = await _owned_connector(session, payload.connector_id, actor.organization_id)
    task, created = await ticketing.enqueue_sync(
        session,
        connector,
        finding,
        action=payload.action,
        created_by_user_id=actor.id,
        client_idempotency_key=idempotency_key,
        explicit_close_reason=payload.explicit_close_reason,
    )
    record_audit(
        session,
        action="ticket_sync.queued",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="background_task",
        target_id=task.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "finding_id": str(finding.id),
            "connector_id": str(connector.id),
            "sync_action": payload.action.value,
            "explicit_close": bool(payload.explicit_close_reason),
            "idempotent_replay": not created,
        },
    )
    return BackgroundTaskRead.model_validate(task)
