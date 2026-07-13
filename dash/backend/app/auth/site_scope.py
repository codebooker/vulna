"""Shared Phase 34 site-scope enforcement.

All authorization remains server-side. Administrators and users explicitly in
``all`` mode retain organization-wide access; users in ``assigned`` mode are
limited through a correlated assignment subquery. Phase 39 migrates this exact
boundary to generalized scoped grants.
"""

from __future__ import annotations

import uuid
from typing import Any, TypeGuard, cast

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, exists, false, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.permission_catalog import BUILTIN_ROLE_PERMISSIONS, PERMISSION_BY_KEY, SITE_SCOPE
from app.models.authorization import RolePermission, ScopedGrant
from app.models.enums import GrantScopeType, SiteAccessMode, UserRole
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment
from app.services.authorization import Principal, principal_filter


def _uses_legacy_scope(principal: Principal) -> TypeGuard[User]:
    return isinstance(principal, User) and principal.authorization_migrated_at is None


def has_all_site_access(user: Principal) -> bool:
    """Compatibility-only check for a user not yet materialized as grants."""
    return _uses_legacy_scope(user) and (
        user.role == UserRole.ADMINISTRATOR or user.site_access_mode == SiteAccessMode.ALL
    )


def site_scope_clause(
    user: Principal,
    site_column: Any,
    *,
    permission_key: str | None = None,
) -> ColumnElement[bool]:
    """SQL predicate limiting a site-id column to the caller's assignments."""
    if _uses_legacy_scope(user):
        if (
            permission_key is not None
            and permission_key not in BUILTIN_ROLE_PERMISSIONS[user.role]
        ):
            return false()
        if user.role == UserRole.ADMINISTRATOR or user.site_access_mode == SiteAccessMode.ALL:
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
            ),
        )
    organization_grant_stmt = select(ScopedGrant.id).where(
        ScopedGrant.organization_id == user.organization_id,
        principal_filter(user),
        ScopedGrant.scope_type == GrantScopeType.ORGANIZATION,
        ScopedGrant.scope_id == user.organization_id,
    )
    site_grant_stmt = select(ScopedGrant.id).where(
        ScopedGrant.organization_id == user.organization_id,
        principal_filter(user),
        ScopedGrant.scope_type == GrantScopeType.SITE,
        ScopedGrant.scope_id == site_column,
    )
    if permission_key is not None:
        definition = PERMISSION_BY_KEY.get(permission_key)
        if definition is None:
            raise ValueError(f"Unknown permission key: {permission_key}")
        organization_grant_stmt = organization_grant_stmt.join(
            RolePermission, RolePermission.role_id == ScopedGrant.role_id
        ).where(
            RolePermission.organization_id == user.organization_id,
            RolePermission.permission_key == permission_key,
        )
        if SITE_SCOPE not in definition.scopes:
            return exists(organization_grant_stmt)
        site_grant_stmt = site_grant_stmt.join(
            RolePermission, RolePermission.role_id == ScopedGrant.role_id
        ).where(
            RolePermission.organization_id == user.organization_id,
            RolePermission.permission_key == permission_key,
        )
    organization_grant = exists(organization_grant_stmt)
    site_grant = exists(site_grant_stmt)
    return or_(organization_grant, site_grant)


def optional_site_scope_clause(
    user: Principal,
    site_column: Any,
    *,
    permission_key: str | None = None,
) -> ColumnElement[bool]:
    """Allow organization-wide rows while filtering rows bound to a site."""
    if permission_key is not None:
        return site_scope_clause(user, site_column, permission_key=permission_key)
    if _uses_legacy_scope(user) and has_all_site_access(user):
        return true()
    return or_(
        site_column.is_(None),
        site_scope_clause(user, site_column, permission_key=permission_key),
    )


async def can_access_site(
    session: AsyncSession,
    user: Principal,
    site_id: uuid.UUID,
    *,
    permission_key: str | None = None,
) -> bool:
    if _uses_legacy_scope(user):
        if (
            permission_key is not None
            and permission_key not in BUILTIN_ROLE_PERMISSIONS[user.role]
        ):
            return False
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
    return bool(
        await session.scalar(
            select(Site.id).where(
                Site.id == site_id,
                Site.organization_id == user.organization_id,
                site_scope_clause(user, Site.id, permission_key=permission_key),
            )
        )
    )


async def accessible_site_ids(
    session: AsyncSession,
    user: Principal,
    *,
    permission_key: str | None = None,
) -> set[uuid.UUID] | None:
    """Return ``None`` for all-sites access, otherwise the assigned id set."""
    if _uses_legacy_scope(user):
        if (
            permission_key is not None
            and permission_key not in BUILTIN_ROLE_PERMISSIONS[user.role]
        ):
            return set()
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
    organization_stmt = select(ScopedGrant.id).where(
        ScopedGrant.organization_id == user.organization_id,
        principal_filter(user),
        ScopedGrant.scope_type == GrantScopeType.ORGANIZATION,
        ScopedGrant.scope_id == user.organization_id,
    )
    sites_stmt = select(ScopedGrant.scope_id).join(
        Site, Site.id == ScopedGrant.scope_id
    ).where(
        ScopedGrant.organization_id == user.organization_id,
        principal_filter(user),
        ScopedGrant.scope_type == GrantScopeType.SITE,
        Site.organization_id == user.organization_id,
    )
    if permission_key is not None:
        definition = PERMISSION_BY_KEY.get(permission_key)
        if definition is None:
            raise ValueError(f"Unknown permission key: {permission_key}")
        organization_stmt = organization_stmt.join(
            RolePermission, RolePermission.role_id == ScopedGrant.role_id
        ).where(
            RolePermission.organization_id == user.organization_id,
            RolePermission.permission_key == permission_key,
        )
        if SITE_SCOPE not in definition.scopes:
            sites_stmt = sites_stmt.where(false())
        else:
            sites_stmt = sites_stmt.join(
                RolePermission, RolePermission.role_id == ScopedGrant.role_id
            ).where(
                RolePermission.organization_id == user.organization_id,
                RolePermission.permission_key == permission_key,
            )
    organization_wide = await session.scalar(organization_stmt)
    if organization_wide is not None:
        return None
    return set(
        (
            await session.execute(sites_stmt)
        ).scalars()
    )


async def require_site_access(
    session: AsyncSession,
    user: Principal,
    site_id: uuid.UUID,
    *,
    not_found_detail: str = "Resource not found",
    permission_key: str | None = None,
) -> None:
    """Raise a non-disclosing 404 when a site is foreign or inaccessible."""
    if not await can_access_site(
        session, user, site_id, permission_key=permission_key
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found_detail)


async def get_accessible_site(
    session: AsyncSession,
    user: Principal,
    site_id: uuid.UUID,
    *,
    permission_key: str | None = None,
) -> Site:
    await require_site_access(
        session,
        user,
        site_id,
        not_found_detail="Site not found",
        permission_key=permission_key,
    )
    site = await session.get(Site, site_id)
    if site is None:  # defensive: access check and load share the transaction
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    return site
