"""Asset and service read endpoints (any authenticated role, organization-scoped)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.auth.site_scope import site_scope_clause
from app.db.session import get_session
from app.models.asset import Asset
from app.models.service import Service
from app.schemas.asset import AssetDetail, AssetIdentifierRead, AssetRead, ServiceRead
from app.schemas.common import Page

router = APIRouter(prefix="/assets", tags=["assets"])


async def _get_owned_asset(
    session: AsyncSession, asset_id: uuid.UUID, current_user: CurrentUser
) -> Asset:
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == current_user.organization_id,
            site_scope_clause(current_user, Asset.site_id),
        )
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.get("", response_model=Page[AssetRead], summary="List assets")
async def list_assets(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetRead]:
    filters = [
        Asset.organization_id == current_user.organization_id,
        site_scope_clause(current_user, Asset.site_id),
    ]
    if site_id is not None:
        filters.append(Asset.site_id == site_id)
    total = await session.scalar(select(func.count()).select_from(Asset).where(*filters))
    result = await session.execute(
        select(Asset).where(*filters).order_by(Asset.last_seen_at.desc()).limit(limit).offset(offset)
    )
    assets = result.scalars().all()
    return Page[AssetRead](
        items=[AssetRead.model_validate(a) for a in assets],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{asset_id}", response_model=AssetDetail, summary="Get an asset with services")
async def get_asset(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AssetDetail:
    asset = await _get_owned_asset(session, asset_id, current_user)
    services = (
        await session.execute(
            select(Service).where(Service.asset_id == asset.id).order_by(Service.port.asc())
        )
    ).scalars().all()
    return AssetDetail(
        **AssetRead.model_validate(asset).model_dump(),
        identifiers=[AssetIdentifierRead.model_validate(i) for i in asset.identifiers],
        services=[ServiceRead.model_validate(s) for s in services],
    )


@router.get(
    "/{asset_id}/services",
    response_model=Page[ServiceRead],
    summary="List an asset's services",
)
async def list_asset_services(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ServiceRead]:
    await _get_owned_asset(session, asset_id, current_user)
    total = await session.scalar(
        select(func.count()).select_from(Service).where(Service.asset_id == asset_id)
    )
    result = await session.execute(
        select(Service)
        .where(Service.asset_id == asset_id)
        .order_by(Service.port.asc())
        .limit(limit)
        .offset(offset)
    )
    services = result.scalars().all()
    return Page[ServiceRead](
        items=[ServiceRead.model_validate(s) for s in services],
        total=total or 0,
        limit=limit,
        offset=offset,
    )
