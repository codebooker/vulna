"""Asset and service read endpoints (any authenticated role, organization-scoped)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser, require_permission
from app.auth.site_scope import site_scope_clause
from app.db.session import get_session
from app.models.asset import Asset
from app.models.asset_context import AssetGroup, AssetGroupMembership, AssetTag, AssetTagAssignment
from app.models.enums import AssetCriticality, AssetEnvironment, DataClassification
from app.models.service import Service
from app.schemas.asset import (
    AssetDetail,
    AssetIdentifierRead,
    AssetRead,
    AssetTagRead,
    ServiceRead,
)
from app.schemas.common import Page
from app.services import asset_context

router = APIRouter(
    prefix="/assets",
    tags=["assets"],
    dependencies=[Depends(require_permission("assets.read"))],
)


async def _get_owned_asset(
    session: AsyncSession, asset_id: uuid.UUID, current_user: CurrentUser
) -> Asset:
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == current_user.organization_id,
            site_scope_clause(current_user, Asset.site_id, permission_key="assets.read"),
        )
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


async def _asset_reads(session: AsyncSession, assets: list[Asset]) -> list[AssetRead]:
    """Enrich asset rows with normalized tags and materialized group ids."""
    asset_ids = [asset.id for asset in assets]
    tags_by_asset: dict[uuid.UUID, list[AssetTagRead]] = {value: [] for value in asset_ids}
    groups_by_asset: dict[uuid.UUID, list[uuid.UUID]] = {value: [] for value in asset_ids}
    if asset_ids:
        tag_rows = (
            await session.execute(
                select(AssetTagAssignment.asset_id, AssetTag)
                .join(AssetTag, AssetTag.id == AssetTagAssignment.tag_id)
                .where(AssetTagAssignment.asset_id.in_(asset_ids))
                .order_by(AssetTag.normalized_name)
            )
        ).all()
        for asset_id, tag in tag_rows:
            tags_by_asset[asset_id].append(AssetTagRead.model_validate(tag))
        group_rows = (
            await session.execute(
                select(AssetGroupMembership.asset_id, AssetGroupMembership.group_id)
                .join(AssetGroup, AssetGroup.id == AssetGroupMembership.group_id)
                .where(AssetGroupMembership.asset_id.in_(asset_ids))
                .where(AssetGroup.enabled.is_(True))
                .order_by(AssetGroupMembership.group_id)
            )
        ).all()
        for asset_id, group_id in group_rows:
            groups_by_asset[asset_id].append(group_id)
    return [
        AssetRead.model_validate(asset).model_copy(
            update={
                "tags": tags_by_asset[asset.id],
                "group_ids": groups_by_asset[asset.id],
            }
        )
        for asset in assets
    ]


@router.get("", response_model=Page[AssetRead], summary="List assets")
async def list_assets(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    tag_id: Annotated[uuid.UUID | None, Query()] = None,
    tag: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    group_id: Annotated[uuid.UUID | None, Query()] = None,
    department: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    environment: Annotated[AssetEnvironment | None, Query()] = None,
    criticality: Annotated[AssetCriticality | None, Query()] = None,
    data_classification: Annotated[DataClassification | None, Query()] = None,
    owner_user_id: Annotated[uuid.UUID | None, Query()] = None,
    internet_exposed: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetRead]:
    filters = [
        Asset.organization_id == current_user.organization_id,
        site_scope_clause(current_user, Asset.site_id, permission_key="assets.read"),
    ]
    if site_id is not None:
        filters.append(Asset.site_id == site_id)
    if q is not None:
        escaped = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        filters.append(
            or_(
                Asset.canonical_name.ilike(pattern, escape="\\"),
                Asset.operating_system.ilike(pattern, escape="\\"),
                Asset.manufacturer.ilike(pattern, escape="\\"),
                Asset.department.ilike(pattern, escape="\\"),
                Asset.business_function.ilike(pattern, escape="\\"),
            )
        )
    if tag_id is not None:
        filters.append(
            Asset.id.in_(
                select(AssetTagAssignment.asset_id).where(
                    AssetTagAssignment.organization_id == current_user.organization_id,
                    AssetTagAssignment.tag_id == tag_id,
                )
            )
        )
    if tag is not None:
        filters.append(
            Asset.id.in_(
                select(AssetTagAssignment.asset_id)
                .join(AssetTag, AssetTag.id == AssetTagAssignment.tag_id)
                .where(
                    AssetTagAssignment.organization_id == current_user.organization_id,
                    AssetTag.normalized_name == asset_context.normalize_name(tag),
                )
            )
        )
    if group_id is not None:
        filters.append(
            Asset.id.in_(
                select(AssetGroupMembership.asset_id)
                .join(AssetGroup, AssetGroup.id == AssetGroupMembership.group_id)
                .where(
                    AssetGroupMembership.organization_id == current_user.organization_id,
                    AssetGroupMembership.group_id == group_id,
                    AssetGroup.enabled.is_(True),
                )
            )
        )
    if department is not None:
        filters.append(func.lower(Asset.department) == department.strip().casefold())
    if environment is not None:
        filters.append(Asset.environment == environment)
    if criticality is not None:
        filters.append(Asset.criticality == criticality)
    if data_classification is not None:
        filters.append(Asset.data_classification == data_classification)
    if owner_user_id is not None:
        filters.append(Asset.owner_user_id == owner_user_id)
    if internet_exposed is not None:
        filters.append(Asset.internet_exposed.is_(internet_exposed))
    total = await session.scalar(select(func.count()).select_from(Asset).where(*filters))
    result = await session.execute(
        select(Asset)
        .where(*filters)
        .order_by(Asset.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    assets = list(result.scalars().all())
    return Page[AssetRead](
        items=await _asset_reads(session, assets),
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
        (
            await session.execute(
                select(Service).where(Service.asset_id == asset.id).order_by(Service.port.asc())
            )
        )
        .scalars()
        .all()
    )
    asset_read = (await _asset_reads(session, [asset]))[0]
    return AssetDetail(
        **asset_read.model_dump(),
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
