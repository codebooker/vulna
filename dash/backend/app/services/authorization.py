"""Permission evaluation, compatibility synchronization, and API-token auth."""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import ColumnElement, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.permission_catalog import (
    BUILTIN_ROLE_PERMISSIONS,
    PERMISSION_BY_KEY,
    ROLE_PRIORITY,
    validate_permission_keys,
)
from app.models.authorization import (
    ApiToken,
    AuthorizationRole,
    RolePermission,
    ScopedGrant,
    ServiceAccount,
)
from app.models.enums import (
    AccountStatus,
    GrantScopeType,
    PrincipalType,
    ServiceAccountStatus,
    SiteAccessMode,
    UserRole,
)
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment

type Principal = User | ServiceAccount

_TOKEN_PREFIX = "vapi"  # noqa: S105 - public token type prefix, not a secret


class ApiTokenError(ValueError):
    """A token is absent, expired, revoked, stale, or outside its IP policy."""


@dataclass(frozen=True)
class GeneratedApiToken:
    secret: str
    token_hash: str
    token_prefix: str


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def principal_type(principal: Principal) -> PrincipalType:
    return PrincipalType.USER if isinstance(principal, User) else PrincipalType.SERVICE_ACCOUNT


def user_actor_id(principal: Principal) -> uuid.UUID | None:
    """Return an id only for legacy columns that still reference users."""
    return principal.id if isinstance(principal, User) else None


def principal_filter(principal: Principal) -> ColumnElement[bool]:
    if isinstance(principal, User):
        return ScopedGrant.user_id == principal.id
    return ScopedGrant.service_account_id == principal.id


def hash_api_token(secret: str) -> str:
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()


def generate_api_token() -> GeneratedApiToken:
    secret = f"{_TOKEN_PREFIX}_{secrets.token_urlsafe(48)}"
    return GeneratedApiToken(
        secret=secret,
        token_hash=hash_api_token(secret),
        token_prefix=secret[:18],
    )


async def ensure_builtin_roles(
    session: AsyncSession, organization_id: uuid.UUID
) -> dict[UserRole, AuthorizationRole]:
    """Idempotently materialize code-defined compatibility roles for an org."""
    rows = list(
        (
            await session.execute(
                select(AuthorizationRole).where(
                    AuthorizationRole.organization_id == organization_id,
                    AuthorizationRole.compatibility_role.is_not(None),
                )
            )
        ).scalars()
    )
    by_compatibility = {
        row.compatibility_role: row for row in rows if row.compatibility_role is not None
    }
    for compatibility_role in UserRole:
        role = by_compatibility.get(compatibility_role)
        if role is None:
            role = AuthorizationRole(
                organization_id=organization_id,
                key=compatibility_role.value,
                name=compatibility_role.value.replace("_", " ").title(),
                description=f"Built-in compatibility role: {compatibility_role.value}",
                is_system=True,
                compatibility_role=compatibility_role,
            )
            session.add(role)
            await session.flush()
            by_compatibility[compatibility_role] = role

        expected = BUILTIN_ROLE_PERMISSIONS[compatibility_role]
        current_rows = list(
            (
                await session.execute(
                    select(RolePermission).where(RolePermission.role_id == role.id)
                )
            ).scalars()
        )
        current = {value.permission_key: value for value in current_rows}
        session.add_all(
            [
                RolePermission(
                    organization_id=organization_id,
                    role_id=role.id,
                    permission_key=permission_key,
                )
                for permission_key in sorted(expected - current.keys())
            ]
        )
        for permission_key, value in current.items():
            if permission_key not in expected:
                await session.delete(value)
    await session.flush()
    return by_compatibility


async def effective_permissions(
    session: AsyncSession,
    principal: Principal,
    *,
    scope_type: GrantScopeType | None = None,
    scope_id: uuid.UUID | None = None,
) -> set[str]:
    """Return code-defined permissions granted to a principal at a scope."""
    stmt = (
        select(RolePermission.permission_key, ScopedGrant.scope_type, ScopedGrant.scope_id)
        .join(AuthorizationRole, AuthorizationRole.id == RolePermission.role_id)
        .join(ScopedGrant, ScopedGrant.role_id == AuthorizationRole.id)
        .where(
            ScopedGrant.organization_id == principal.organization_id,
            AuthorizationRole.organization_id == principal.organization_id,
            RolePermission.organization_id == principal.organization_id,
            principal_filter(principal),
        )
    )
    rows = list((await session.execute(stmt)).all())
    if not rows and isinstance(principal, User) and principal.authorization_migrated_at is None:
        # Transitional compatibility for tests/integrations that insert a User
        # directly. Runtime-created and migrated users always have this marker.
        return set(BUILTIN_ROLE_PERMISSIONS[principal.role])

    result: set[str] = set()
    for permission_key, grant_scope, grant_scope_id in rows:
        definition = PERMISSION_BY_KEY.get(permission_key)
        if definition is None or grant_scope.value not in definition.scopes:
            continue
        if (
            scope_type is None
            or grant_scope == GrantScopeType.ORGANIZATION
            or (grant_scope == scope_type and grant_scope_id == scope_id)
        ):
            result.add(permission_key)
    return result


async def has_permission(
    session: AsyncSession,
    principal: Principal,
    permission_key: str,
    *,
    scope_type: GrantScopeType | None = None,
    scope_id: uuid.UUID | None = None,
) -> bool:
    validate_permission_keys({permission_key})
    return permission_key in await effective_permissions(
        session, principal, scope_type=scope_type, scope_id=scope_id
    )


async def sync_user_compatibility_grants(
    session: AsyncSession,
    user: User,
    *,
    created_by_user_id: uuid.UUID | None = None,
) -> None:
    """Make built-in grants follow the retained legacy role/site fields."""
    roles = await ensure_builtin_roles(session, user.organization_id)
    compatibility_role_ids = [role.id for role in roles.values()]
    await session.execute(
        delete(ScopedGrant).where(
            ScopedGrant.user_id == user.id,
            ScopedGrant.role_id.in_(compatibility_role_ids),
        )
    )
    # Assignment helpers run with autoflush disabled; materialize pending rows
    # before deriving site-scoped grants from them.
    await session.flush()
    if user.role == UserRole.ADMINISTRATOR or user.site_access_mode == SiteAccessMode.ALL:
        scopes = [(GrantScopeType.ORGANIZATION, user.organization_id)]
    else:
        site_ids = list(
            (
                await session.execute(
                    select(UserSiteAssignment.site_id).where(
                        UserSiteAssignment.organization_id == user.organization_id,
                        UserSiteAssignment.user_id == user.id,
                    )
                )
            ).scalars()
        )
        scopes = [(GrantScopeType.SITE, site_id) for site_id in site_ids]
    session.add_all(
        [
            ScopedGrant(
                organization_id=user.organization_id,
                principal_type=PrincipalType.USER,
                user_id=user.id,
                role_id=roles[user.role].id,
                scope_type=scope_type,
                scope_id=scope_id,
                created_by_user_id=created_by_user_id,
            )
            for scope_type, scope_id in scopes
        ]
    )
    user.authorization_migrated_at = utcnow()
    await session.flush()


async def sync_user_compatibility_fields(session: AsyncSession, user: User) -> None:
    """Derive legacy primary role and site fields from the user's grants."""
    rows = list(
        (
            await session.execute(
                select(
                    AuthorizationRole.compatibility_role,
                    ScopedGrant.scope_type,
                    ScopedGrant.scope_id,
                )
                .join(ScopedGrant, ScopedGrant.role_id == AuthorizationRole.id)
                .where(
                    ScopedGrant.organization_id == user.organization_id,
                    ScopedGrant.user_id == user.id,
                )
            )
        ).all()
    )
    compatibility_rows = [row for row in rows if row[0] is not None]
    compatibility_roles = [value for value, _, _ in compatibility_rows]
    user.role = (
        max(compatibility_roles, key=lambda role: ROLE_PRIORITY[role])
        if compatibility_roles
        else UserRole.VIEWER
    )
    # Legacy site fields are a projection of the retained compatibility grant,
    # not of unrelated custom roles. Otherwise an org-wide custom permission
    # (for example audit.read) could turn an assigned Viewer into an org-wide
    # Viewer the next time a lifecycle update re-synchronizes compatibility.
    organization_wide = any(
        scope_type == GrantScopeType.ORGANIZATION for _, scope_type, _ in compatibility_rows
    )
    user.site_access_mode = SiteAccessMode.ALL if organization_wide else SiteAccessMode.ASSIGNED
    await session.execute(delete(UserSiteAssignment).where(UserSiteAssignment.user_id == user.id))
    if not organization_wide:
        site_ids = {
            scope_id
            for _, scope_type, scope_id in compatibility_rows
            if scope_type == GrantScopeType.SITE
        }
        if site_ids:
            valid_site_ids = set(
                (
                    await session.execute(
                        select(Site.id).where(
                            Site.organization_id == user.organization_id,
                            Site.id.in_(site_ids),
                        )
                    )
                ).scalars()
            )
            session.add_all(
                [
                    UserSiteAssignment(
                        organization_id=user.organization_id,
                        user_id=user.id,
                        site_id=site_id,
                        assigned_by_user_id=None,
                    )
                    for site_id in sorted(valid_site_ids, key=str)
                ]
            )
    user.authorization_migrated_at = utcnow()
    await session.flush()


async def sync_service_account_primary_role(
    session: AsyncSession, service_account: ServiceAccount
) -> None:
    roles = [
        role
        for role in (
            (
                await session.execute(
                    select(AuthorizationRole.compatibility_role)
                    .join(ScopedGrant, ScopedGrant.role_id == AuthorizationRole.id)
                    .where(
                        ScopedGrant.organization_id == service_account.organization_id,
                        ScopedGrant.service_account_id == service_account.id,
                        AuthorizationRole.compatibility_role.is_not(None),
                    )
                )
            ).scalars()
        )
        if role is not None
    ]
    service_account.primary_role = (
        max(roles, key=lambda role: ROLE_PRIORITY[role]) if roles else UserRole.VIEWER
    )


def ip_is_allowed(source_ip: str | None, restrictions: list[str]) -> bool:
    if not restrictions:
        return True
    if not source_ip:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
        return any(address in ipaddress.ip_network(value, strict=False) for value in restrictions)
    except ValueError:
        return False


def validate_ip_restrictions(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        try:
            normalized.append(str(ipaddress.ip_network(value.strip(), strict=False)))
        except ValueError as exc:
            raise ValueError(f"Invalid IP restriction: {value}") from exc
    return sorted(set(normalized))


async def authenticate_api_token(
    session: AsyncSession, secret: str, source_ip: str | None
) -> tuple[Principal, ApiToken]:
    token = await session.scalar(
        select(ApiToken).where(ApiToken.token_hash == hash_api_token(secret))
    )
    now = utcnow()
    if (
        token is None
        or token.revoked_at is not None
        or aware(token.expires_at) <= now
        or not ip_is_allowed(source_ip, list(token.ip_restrictions_json or []))
    ):
        raise ApiTokenError("Could not validate credentials")

    principal: Principal | None
    if token.principal_type == PrincipalType.USER:
        principal = await session.get(User, token.user_id)
        if (
            principal is None
            or principal.organization_id != token.organization_id
            or not principal.is_active
            or principal.account_status != AccountStatus.ACTIVE
            or principal.auth_version != token.issued_auth_version
        ):
            raise ApiTokenError("Could not validate credentials")
    else:
        principal = await session.get(ServiceAccount, token.service_account_id)
        if (
            principal is None
            or principal.organization_id != token.organization_id
            or principal.status != ServiceAccountStatus.ACTIVE
            or principal.auth_version != token.issued_auth_version
        ):
            raise ApiTokenError("Could not validate credentials")
        principal.last_used_at = now
    token.last_used_at = now
    token.last_used_ip = source_ip
    return principal, token
