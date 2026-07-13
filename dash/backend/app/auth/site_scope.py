"""Shared Phase 34 site-scope enforcement.

All authorization remains server-side. Administrators and users explicitly in
``all`` mode retain organization-wide access; users in ``assigned`` mode are
limited through a correlated assignment subquery. Phase 39 migrates this exact
boundary to generalized scoped grants.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, false, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import SiteAccessMode, UserRole
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment


def has_all_site_access(user: User) -> bool:
    """Administrators must be able to manage assignments for every site."""
    return user.role == UserRole.ADMINISTRATOR or user.site_access_mode == SiteAccessMode.ALL


def site_scope_clause(user: User, site_column: Any) -> ColumnElement[bool]:
    """SQL predicate limiting a site-id column to the caller's assignments."""
    if has_all_site_access(user):
        return true()
    if user.site_access_mode != SiteAccessMode.ASSIGNED:
        return false()
    return cast(
        ColumnElement[bool],
        site_column.in_(
            select(UserSiteAssignment.site_id).where(
                UserSiteAssignment.organization_id == user.organization_id,
                UserSiteAssignment.user_id == user.id,
            )
        )
    )


def optional_site_scope_clause(user: User, site_column: Any) -> ColumnElement[bool]:
    """Allow organization-wide rows while filtering rows bound to a site."""
    if has_all_site_access(user):
        return true()
    return or_(site_column.is_(None), site_scope_clause(user, site_column))


async def can_access_site(
    session: AsyncSession, user: User, site_id: uuid.UUID
) -> bool:
    if has_all_site_access(user):
        return bool(
            await session.scalar(
                select(Site.id).where(
                    Site.id == site_id, Site.organization_id == user.organization_id
                )
            )
        )
    return bool(
        await session.scalar(
            select(UserSiteAssignment.id)
            .join(Site, Site.id == UserSiteAssignment.site_id)
            .where(
                UserSiteAssignment.organization_id == user.organization_id,
                UserSiteAssignment.user_id == user.id,
                UserSiteAssignment.site_id == site_id,
                Site.organization_id == user.organization_id,
            )
        )
    )


async def accessible_site_ids(
    session: AsyncSession, user: User
) -> set[uuid.UUID] | None:
    """Return ``None`` for all-sites access, otherwise the assigned id set."""
    if has_all_site_access(user):
        return None
    return set(
        (
            await session.execute(
                select(UserSiteAssignment.site_id).where(
                    UserSiteAssignment.organization_id == user.organization_id,
                    UserSiteAssignment.user_id == user.id,
                )
            )
        ).scalars()
    )


async def require_site_access(
    session: AsyncSession,
    user: User,
    site_id: uuid.UUID,
    *,
    not_found_detail: str = "Resource not found",
) -> None:
    """Raise a non-disclosing 404 when a site is foreign or inaccessible."""
    if not await can_access_site(session, user, site_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found_detail)


async def get_accessible_site(
    session: AsyncSession, user: User, site_id: uuid.UUID
) -> Site:
    await require_site_access(session, user, site_id, not_found_detail="Site not found")
    site = await session.get(Site, site_id)
    if site is None:  # defensive: access check and load share the transaction
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    return site
