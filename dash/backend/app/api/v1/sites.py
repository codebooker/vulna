"""Site management endpoints.

Read access is available to any authenticated user within the organization.
Create, update, and delete require the Administrator role. Every mutation is
recorded in the audit log.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.auth.site_scope import get_accessible_site, site_scope_clause
from app.db.session import get_session
from app.models.asset import Asset
from app.models.site import Site
from app.models.user import User
from app.schemas.common import Page
from app.schemas.site import SiteCreate, SiteRead, SiteUpdate
from app.services import asset_context
from app.services.asset_context import AssetContextError, validate_owner
from app.services.audit import record_audit

router = APIRouter(
    prefix="/sites",
    tags=["sites"],
    dependencies=[Depends(require_permission("sites.read"))],
)


async def _get_owned_site(session: AsyncSession, site_id: uuid.UUID, org_id: uuid.UUID) -> Site:
    """Load a site by id, scoped to the caller's organization, or raise 404."""
    site = await session.get(Site, site_id)
    if site is None or site.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    return site


@router.get("", response_model=Page[SiteRead], summary="List sites")
async def list_sites(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[SiteRead]:
    """List sites in the caller's organization (any authenticated role)."""
    org_id = current_user.organization_id
    filters = [
        Site.organization_id == org_id,
        site_scope_clause(current_user, Site.id, permission_key="sites.read"),
    ]
    total = await session.scalar(select(func.count()).select_from(Site).where(*filters))
    result = await session.execute(
        select(Site).where(*filters).order_by(Site.created_at.asc()).limit(limit).offset(offset)
    )
    sites = result.scalars().all()
    return Page[SiteRead](
        items=[SiteRead.model_validate(s) for s in sites],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{site_id}", response_model=SiteRead, summary="Get a site")
async def get_site(
    site_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SiteRead:
    site = await get_accessible_site(session, current_user, site_id, permission_key="sites.read")
    return SiteRead.model_validate(site)


@router.post(
    "",
    response_model=SiteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a site",
)
async def create_site(
    payload: SiteCreate,
    admin: Annotated[User, Depends(require_permission("sites.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SiteRead:
    """Create a site (Administrator only)."""
    try:
        await validate_owner(session, admin.organization_id, payload.owner_user_id)
    except AssetContextError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    site = Site(
        organization_id=admin.organization_id,
        name=payload.name,
        code=payload.code,
        description=payload.description,
        address=payload.address,
        timezone=payload.timezone,
        business_owner=payload.business_owner,
        technical_owner=payload.technical_owner,
        owner_user_id=payload.owner_user_id,
        tags=payload.tags,
    )
    session.add(site)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A site with code '{payload.code}' already exists",
        ) from exc

    record_audit(
        session,
        action="site.created",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="site",
        target_id=site.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"name": site.name, "code": site.code},
    )
    return SiteRead.model_validate(site)


@router.patch("/{site_id}", response_model=SiteRead, summary="Update a site")
async def update_site(
    site_id: uuid.UUID,
    payload: SiteUpdate,
    admin: Annotated[User, Depends(require_permission("sites.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SiteRead:
    """Update a site (Administrator only)."""
    site = await _get_owned_site(session, site_id, admin.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    if "owner_user_id" in changes:
        try:
            await validate_owner(session, admin.organization_id, changes["owner_user_id"])
        except AssetContextError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    for field, value in changes.items():
        setattr(site, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A site with that code already exists",
        ) from exc

    if "owner_user_id" in changes:
        assets = list(
            (await session.execute(select(Asset).where(Asset.site_id == site.id))).scalars()
        )
        for asset in assets:
            ownership = await asset_context.resolve_ownership(session, asset)
            await asset_context.record_ownership_snapshot(session, ownership)

    record_audit(
        session,
        action="site.updated",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="site",
        target_id=site.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(changes.keys())},
    )
    return SiteRead.model_validate(site)


@router.delete(
    "/{site_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a site",
)
async def delete_site(
    site_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("sites.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    """Delete a site and its scopes (Administrator only)."""
    site = await _get_owned_site(session, site_id, admin.organization_id)
    record_audit(
        session,
        action="site.deleted",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="site",
        target_id=site.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"name": site.name, "code": site.code},
    )
    await session.delete(site)
