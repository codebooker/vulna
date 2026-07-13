"""Permission-aware software inventory, history, and EOL override APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, StepUpIdentity, require_permission
from app.auth.site_scope import site_scope_clause
from app.db.session import get_session
from app.models.software import EolOverride, SoftwareInventoryHistory, SoftwareInventoryItem
from app.models.user import User
from app.schemas.common import Page
from app.schemas.software import (
    EolEvaluation,
    EolOverrideCreate,
    EolOverrideRead,
    SoftwareHistoryRead,
    SoftwareRead,
)
from app.services import authorization
from app.services.audit import record_audit
from app.services.software_inventory import evaluate_eol

router = APIRouter(
    prefix="/software",
    tags=["software"],
    dependencies=[Depends(require_permission("software.read"))],
)


async def _owned_item(
    session: AsyncSession, item_id: uuid.UUID, user: User, permission_key: str
) -> SoftwareInventoryItem:
    item = await session.scalar(
        select(SoftwareInventoryItem).where(
            SoftwareInventoryItem.id == item_id,
            SoftwareInventoryItem.organization_id == user.organization_id,
            site_scope_clause(user, SoftwareInventoryItem.site_id, permission_key=permission_key),
        )
    )
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Software item not found")
    return item


async def _serialize(session: AsyncSession, item: SoftwareInventoryItem) -> SoftwareRead:
    eol = await evaluate_eol(session, item)
    return SoftwareRead(
        id=item.id,
        organization_id=item.organization_id,
        site_id=item.site_id,
        asset_id=item.asset_id,
        source=item.source,
        name=item.name,
        package_key=item.package_key,
        version=item.version,
        architecture=item.architecture,
        publisher=item.publisher,
        product_key=item.product_key,
        install_date=item.install_date,
        first_seen_at=item.first_seen_at,
        last_seen_at=item.last_seen_at,
        removed_at=item.removed_at,
        metadata=dict(item.metadata_json or {}),
        eol=EolEvaluation(
            status=eol.status,
            eol_date=eol.eol_date,
            source=eol.source,
            source_url=eol.source_url,
            overridden=eol.overridden,
        ),
    )


@router.get("", response_model=Page[SoftwareRead])
async def list_software(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    include_removed: bool = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[SoftwareRead]:
    filters = [
        SoftwareInventoryItem.organization_id == current_user.organization_id,
        site_scope_clause(
            current_user, SoftwareInventoryItem.site_id, permission_key="software.read"
        ),
    ]
    if asset_id is not None:
        filters.append(SoftwareInventoryItem.asset_id == asset_id)
    if not include_removed:
        filters.append(SoftwareInventoryItem.removed_at.is_(None))
    total = await session.scalar(
        select(func.count()).select_from(SoftwareInventoryItem).where(*filters)
    )
    rows = list(
        (
            await session.execute(
                select(SoftwareInventoryItem)
                .where(*filters)
                .order_by(SoftwareInventoryItem.name, SoftwareInventoryItem.version)
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[SoftwareRead](
        items=[await _serialize(session, row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/history", response_model=Page[SoftwareHistoryRead])
async def list_software_history(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    software_item_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[SoftwareHistoryRead]:
    filters = [
        SoftwareInventoryHistory.organization_id == current_user.organization_id,
        site_scope_clause(
            current_user, SoftwareInventoryHistory.site_id, permission_key="software.read"
        ),
    ]
    if asset_id is not None:
        filters.append(SoftwareInventoryHistory.asset_id == asset_id)
    if software_item_id is not None:
        filters.append(SoftwareInventoryHistory.software_item_id == software_item_id)
    total = await session.scalar(
        select(func.count()).select_from(SoftwareInventoryHistory).where(*filters)
    )
    rows = list(
        (
            await session.execute(
                select(SoftwareInventoryHistory)
                .where(*filters)
                .order_by(SoftwareInventoryHistory.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[SoftwareHistoryRead](
        items=[
            SoftwareHistoryRead(
                id=row.id,
                asset_id=row.asset_id,
                software_item_id=row.software_item_id,
                scan_job_id=row.scan_job_id,
                change_type=row.change_type,
                previous_version=row.previous_version,
                observed_version=row.observed_version,
                observation=dict(row.observation_json or {}),
                created_at=row.created_at,
            )
            for row in rows
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{item_id}", response_model=SoftwareRead)
async def get_software_item(
    item_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SoftwareRead:
    return await _serialize(
        session, await _owned_item(session, item_id, current_user, "software.read")
    )


@router.post(
    "/{item_id}/eol-overrides",
    response_model=EolOverrideRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_eol_override(
    item_id: uuid.UUID,
    payload: EolOverrideCreate,
    manager: Annotated[User, Depends(require_permission("software.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> EolOverrideRead:
    item = await _owned_item(session, item_id, manager, "software.manage")
    now = datetime.now(UTC)
    if payload.expires_at is not None:
        expires = (
            payload.expires_at
            if payload.expires_at.tzinfo
            else payload.expires_at.replace(tzinfo=UTC)
        )
        if expires <= now:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Override expiry must be in the future",
            )
    existing = list(
        (
            await session.execute(
                select(EolOverride).where(
                    EolOverride.organization_id == manager.organization_id,
                    EolOverride.software_item_id == item.id,
                    EolOverride.active.is_(True),
                )
            )
        ).scalars()
    )
    for prior in existing:
        prior.active = False
    override = EolOverride(
        organization_id=manager.organization_id,
        software_item_id=item.id,
        status=payload.status,
        eol_date=payload.eol_date,
        reason=payload.reason,
        expires_at=payload.expires_at,
        active=True,
        created_by_user_id=authorization.user_actor_id(manager),
    )
    session.add(override)
    await session.flush()
    record_audit(
        session,
        action="software.eol_override_created",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="eol_override",
        target_id=override.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={
            "software_item_id": str(item.id),
            "status": override.status.value,
            "expires_at": override.expires_at.isoformat() if override.expires_at else None,
        },
    )
    return EolOverrideRead(
        id=override.id,
        software_item_id=override.software_item_id,
        status=override.status,
        eol_date=override.eol_date,
        reason=override.reason,
        expires_at=override.expires_at,
        active=override.active,
        created_at=override.created_at,
        updated_at=override.updated_at,
    )
