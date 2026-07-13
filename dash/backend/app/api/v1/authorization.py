"""Granular roles, grants, service accounts, and API-token management."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentIdentity,
    CurrentUser,
    require_permission,
    require_step_up_permission,
)
from app.auth.permission_catalog import PERMISSIONS, validate_permission_keys
from app.db.session import get_session
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
    UserRole,
)
from app.models.site import Site
from app.models.user import User
from app.schemas.authorization import (
    ApiTokenCreate,
    ApiTokenIssued,
    ApiTokenRead,
    ApiTokenRotate,
    AuthorizationRoleCreate,
    AuthorizationRoleRead,
    AuthorizationRoleUpdate,
    PermissionRead,
    ScopedGrantCreate,
    ScopedGrantRead,
    ServiceAccountCreate,
    ServiceAccountRead,
    ServiceAccountUpdate,
)
from app.services import authorization
from app.services.audit import record_audit
from app.services.sessions import revoke_user_sessions
from app.services.user_lifecycle import active_admin_count

router = APIRouter(tags=["authorization"])


async def _owned_role(
    session: AsyncSession, organization_id: uuid.UUID, role_id: uuid.UUID
) -> AuthorizationRole:
    role = await session.scalar(
        select(AuthorizationRole).where(
            AuthorizationRole.id == role_id,
            AuthorizationRole.organization_id == organization_id,
        )
    )
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


async def _role_read(session: AsyncSession, role: AuthorizationRole) -> AuthorizationRoleRead:
    permissions = list(
        (
            await session.execute(
                select(RolePermission.permission_key)
                .where(RolePermission.role_id == role.id)
                .order_by(RolePermission.permission_key.asc())
            )
        ).scalars()
    )
    return AuthorizationRoleRead(
        id=role.id,
        key=role.key,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        compatibility_role=role.compatibility_role,
        permission_keys=permissions,
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


async def _replace_permissions(
    session: AsyncSession, role: AuthorizationRole, permission_keys: set[str]
) -> None:
    validate_permission_keys(permission_keys)
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
    session.add_all(
        [
            RolePermission(
                organization_id=role.organization_id,
                role_id=role.id,
                permission_key=key,
            )
            for key in sorted(permission_keys)
        ]
    )


async def _invalidate_role_principals(session: AsyncSession, role_id: uuid.UUID) -> None:
    grants = list(
        (await session.execute(select(ScopedGrant).where(ScopedGrant.role_id == role_id))).scalars()
    )
    user_ids = {grant.user_id for grant in grants if grant.user_id is not None}
    service_ids = {
        grant.service_account_id for grant in grants if grant.service_account_id is not None
    }
    if user_ids:
        users = list((await session.execute(select(User).where(User.id.in_(user_ids)))).scalars())
        for user in users:
            user.auth_version += 1
            await revoke_user_sessions(session, user.id, reason="authorization role changed")
    if service_ids:
        services = list(
            (
                await session.execute(
                    select(ServiceAccount).where(ServiceAccount.id.in_(service_ids))
                )
            ).scalars()
        )
        for service in services:
            service.auth_version += 1


async def _principal(
    session: AsyncSession,
    organization_id: uuid.UUID,
    kind: PrincipalType,
    principal_id: uuid.UUID,
) -> authorization.Principal:
    if kind == PrincipalType.USER:
        principal = await session.scalar(
            select(User).where(User.id == principal_id, User.organization_id == organization_id)
        )
    else:
        principal = await session.scalar(
            select(ServiceAccount).where(
                ServiceAccount.id == principal_id,
                ServiceAccount.organization_id == organization_id,
            )
        )
    if principal is None:
        raise HTTPException(status_code=404, detail="Principal not found")
    return principal


def _grant_read(grant: ScopedGrant, role: AuthorizationRole) -> ScopedGrantRead:
    principal_id = grant.user_id or grant.service_account_id
    if principal_id is None:  # protected by a database check constraint
        raise RuntimeError("grant has no principal")
    return ScopedGrantRead(
        id=grant.id,
        organization_id=grant.organization_id,
        principal_type=grant.principal_type,
        principal_id=principal_id,
        role_id=grant.role_id,
        role_key=role.key,
        role_name=role.name,
        scope_type=grant.scope_type,
        scope_id=grant.scope_id,
        created_at=grant.created_at,
    )


async def _after_grant_change(session: AsyncSession, principal: authorization.Principal) -> None:
    if isinstance(principal, User):
        await authorization.sync_user_compatibility_fields(session, principal)
        principal.auth_version += 1
        await revoke_user_sessions(session, principal.id, reason="authorization grants changed")
    else:
        await authorization.sync_service_account_primary_role(session, principal)
        principal.auth_version += 1


@router.get("/permissions", response_model=list[PermissionRead])
async def permission_catalogue(current_user: CurrentUser) -> list[PermissionRead]:
    return [
        PermissionRead(
            key=value.key,
            label=value.label,
            description=value.description,
            scopes=list(value.scopes),
            high_risk=value.high_risk,
        )
        for value in PERMISSIONS
    ]


@router.get("/authorization/effective", response_model=list[str])
async def my_effective_permissions(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[str]:
    return sorted(await authorization.effective_permissions(session, current_user))


@router.get("/roles", response_model=list[AuthorizationRoleRead])
async def list_roles(
    actor: Annotated[User, Depends(require_permission("roles.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[AuthorizationRoleRead]:
    rows = list(
        (
            await session.execute(
                select(AuthorizationRole)
                .where(AuthorizationRole.organization_id == actor.organization_id)
                .order_by(AuthorizationRole.is_system.desc(), AuthorizationRole.name.asc())
            )
        ).scalars()
    )
    return [await _role_read(session, role) for role in rows]


@router.post("/roles", response_model=AuthorizationRoleRead, status_code=201)
async def create_role(
    payload: AuthorizationRoleCreate,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("roles.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AuthorizationRoleRead:
    actor = identity.user
    duplicate = await session.scalar(
        select(AuthorizationRole.id).where(
            AuthorizationRole.organization_id == actor.organization_id,
            (AuthorizationRole.key == payload.key)
            | (AuthorizationRole.name == payload.name.strip()),
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="A role with that key or name already exists")
    role = AuthorizationRole(
        organization_id=actor.organization_id,
        key=payload.key,
        name=payload.name.strip(),
        description=payload.description,
        is_system=False,
        compatibility_role=None,
    )
    session.add(role)
    await session.flush()
    try:
        await _replace_permissions(session, role, set(payload.permission_keys))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit(
        session,
        action="authorization.role_created",
        actor=actor,
        target_type="authorization_role",
        target_id=role.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"key": role.key, "permissions": sorted(set(payload.permission_keys))},
    )
    await session.flush()
    return await _role_read(session, role)


@router.patch("/roles/{role_id}", response_model=AuthorizationRoleRead)
async def update_role(
    role_id: uuid.UUID,
    payload: AuthorizationRoleUpdate,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("roles.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AuthorizationRoleRead:
    actor = identity.user
    role = await _owned_role(session, actor.organization_id, role_id)
    if role.is_system:
        raise HTTPException(status_code=409, detail="Built-in roles are code-defined and immutable")
    changed: list[str] = []
    if payload.name is not None:
        new_name = payload.name.strip()
        duplicate = await session.scalar(
            select(AuthorizationRole.id).where(
                AuthorizationRole.organization_id == actor.organization_id,
                AuthorizationRole.name == new_name,
                AuthorizationRole.id != role.id,
            )
        )
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="A role with that name already exists")
        role.name = new_name
        changed.append("name")
    if "description" in payload.model_fields_set:
        role.description = payload.description
        changed.append("description")
    if payload.permission_keys is not None:
        try:
            await _replace_permissions(session, role, set(payload.permission_keys))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        await _invalidate_role_principals(session, role.id)
        changed.append("permissions")
    record_audit(
        session,
        action="authorization.role_updated",
        actor=actor,
        target_type="authorization_role",
        target_id=role.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": changed},
    )
    await session.flush()
    return await _role_read(session, role)


@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(
    role_id: uuid.UUID,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("roles.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    actor = identity.user
    role = await _owned_role(session, actor.organization_id, role_id)
    if role.is_system:
        raise HTTPException(status_code=409, detail="Built-in roles cannot be deleted")
    affected = list(
        (await session.execute(select(ScopedGrant).where(ScopedGrant.role_id == role.id))).scalars()
    )
    user_ids = {value.user_id for value in affected if value.user_id is not None}
    service_ids = {
        value.service_account_id for value in affected if value.service_account_id is not None
    }
    await session.execute(delete(ScopedGrant).where(ScopedGrant.role_id == role.id))
    await session.flush()
    await session.delete(role)
    await session.flush()
    for user in list((await session.execute(select(User).where(User.id.in_(user_ids)))).scalars()):
        await _after_grant_change(session, user)
    for service in list(
        (
            await session.execute(select(ServiceAccount).where(ServiceAccount.id.in_(service_ids)))
        ).scalars()
    ):
        await _after_grant_change(session, service)
    record_audit(
        session,
        action="authorization.role_deleted",
        actor=actor,
        target_type="authorization_role",
        target_id=role_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"key": role.key},
    )
    return Response(status_code=204)


@router.get("/grants", response_model=list[ScopedGrantRead])
async def list_grants(
    actor: Annotated[User, Depends(require_permission("roles.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ScopedGrantRead]:
    rows = list(
        (
            await session.execute(
                select(ScopedGrant, AuthorizationRole)
                .join(AuthorizationRole, AuthorizationRole.id == ScopedGrant.role_id)
                .where(ScopedGrant.organization_id == actor.organization_id)
                .order_by(ScopedGrant.created_at.asc())
            )
        ).all()
    )
    return [_grant_read(grant, role) for grant, role in rows]


@router.post("/grants", response_model=ScopedGrantRead, status_code=201)
async def create_grant(
    payload: ScopedGrantCreate,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("roles.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ScopedGrantRead:
    actor = identity.user
    role = await _owned_role(session, actor.organization_id, payload.role_id)
    principal = await _principal(
        session, actor.organization_id, payload.principal_type, payload.principal_id
    )
    if payload.scope_type == GrantScopeType.ORGANIZATION:
        if payload.scope_id != actor.organization_id:
            raise HTTPException(status_code=422, detail="Organization scope id must match")
    else:
        site = await session.scalar(
            select(Site.id).where(
                Site.id == payload.scope_id, Site.organization_id == actor.organization_id
            )
        )
        if site is None:
            raise HTTPException(status_code=422, detail="Site does not belong to this organization")
    owner_column = (
        ScopedGrant.user_id
        if payload.principal_type == PrincipalType.USER
        else ScopedGrant.service_account_id
    )
    duplicate = await session.scalar(
        select(ScopedGrant.id).where(
            ScopedGrant.organization_id == actor.organization_id,
            owner_column == payload.principal_id,
            ScopedGrant.role_id == role.id,
            ScopedGrant.scope_type == payload.scope_type,
            ScopedGrant.scope_id == payload.scope_id,
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="That scoped grant already exists")
    grant = ScopedGrant(
        organization_id=actor.organization_id,
        principal_type=payload.principal_type,
        user_id=(payload.principal_id if payload.principal_type == PrincipalType.USER else None),
        service_account_id=(
            payload.principal_id
            if payload.principal_type == PrincipalType.SERVICE_ACCOUNT
            else None
        ),
        role_id=role.id,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        created_by_user_id=authorization.user_actor_id(actor),
    )
    session.add(grant)
    await session.flush()
    await _after_grant_change(session, principal)
    record_audit(
        session,
        action="authorization.grant_created",
        actor=actor,
        target_type="scoped_grant",
        target_id=grant.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "principal_type": payload.principal_type.value,
            "principal_id": str(payload.principal_id),
            "role_key": role.key,
            "scope_type": payload.scope_type.value,
            "scope_id": str(payload.scope_id),
        },
    )
    return _grant_read(grant, role)


@router.delete("/grants/{grant_id}", status_code=204)
async def delete_grant(
    grant_id: uuid.UUID,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("roles.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    actor = identity.user
    row = (
        await session.execute(
            select(ScopedGrant, AuthorizationRole)
            .join(AuthorizationRole, AuthorizationRole.id == ScopedGrant.role_id)
            .where(
                ScopedGrant.id == grant_id,
                ScopedGrant.organization_id == actor.organization_id,
            )
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Grant not found")
    grant, role = row
    principal_id = grant.user_id or grant.service_account_id
    if principal_id is None:
        raise HTTPException(status_code=409, detail="Grant has no principal")
    principal = await _principal(session, actor.organization_id, grant.principal_type, principal_id)
    if (
        isinstance(principal, User)
        and role.compatibility_role == UserRole.ADMINISTRATOR
        and principal.account_status == AccountStatus.ACTIVE
    ):
        other_admin_grants = int(
            await session.scalar(
                select(func.count())
                .select_from(ScopedGrant)
                .join(AuthorizationRole, AuthorizationRole.id == ScopedGrant.role_id)
                .where(
                    ScopedGrant.user_id == principal.id,
                    ScopedGrant.id != grant.id,
                    AuthorizationRole.compatibility_role == UserRole.ADMINISTRATOR,
                )
            )
            or 0
        )
        if (
            other_admin_grants == 0
            and await active_admin_count(
                session, principal.organization_id, exclude_user_id=principal.id
            )
            == 0
        ):
            raise HTTPException(
                status_code=409, detail="The last active administrator cannot lose access"
            )
    await session.delete(grant)
    await session.flush()
    await _after_grant_change(session, principal)
    record_audit(
        session,
        action="authorization.grant_deleted",
        actor=actor,
        target_type="scoped_grant",
        target_id=grant_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"principal_id": str(principal_id), "role_key": role.key},
    )
    return Response(status_code=204)


@router.get("/service-accounts", response_model=list[ServiceAccountRead])
async def list_service_accounts(
    actor: Annotated[User, Depends(require_permission("service_accounts.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ServiceAccount]:
    return list(
        (
            await session.execute(
                select(ServiceAccount)
                .where(ServiceAccount.organization_id == actor.organization_id)
                .order_by(ServiceAccount.name.asc())
            )
        ).scalars()
    )


@router.post("/service-accounts", response_model=ServiceAccountRead, status_code=201)
async def create_service_account(
    payload: ServiceAccountCreate,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ServiceAccount:
    actor = identity.user
    exists = await session.scalar(
        select(ServiceAccount.id).where(
            ServiceAccount.organization_id == actor.organization_id,
            ServiceAccount.name == payload.name.strip(),
        )
    )
    if exists is not None:
        raise HTTPException(status_code=409, detail="A service account with that name exists")
    account = ServiceAccount(
        organization_id=actor.organization_id,
        name=payload.name.strip(),
        description=payload.description,
        status=ServiceAccountStatus.ACTIVE,
        created_by_user_id=authorization.user_actor_id(actor),
    )
    session.add(account)
    await session.flush()
    record_audit(
        session,
        action="service_account.created",
        actor=actor,
        target_type="service_account",
        target_id=account.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"name": account.name},
    )
    return account


async def _owned_service(
    session: AsyncSession, organization_id: uuid.UUID, account_id: uuid.UUID
) -> ServiceAccount:
    account = await session.scalar(
        select(ServiceAccount).where(
            ServiceAccount.id == account_id,
            ServiceAccount.organization_id == organization_id,
        )
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    return account


@router.patch("/service-accounts/{account_id}", response_model=ServiceAccountRead)
async def update_service_account(
    account_id: uuid.UUID,
    payload: ServiceAccountUpdate,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ServiceAccount:
    actor = identity.user
    account = await _owned_service(session, actor.organization_id, account_id)
    changes = payload.model_dump(exclude_unset=True)
    if payload.name is not None and payload.name.strip() != account.name:
        duplicate = await session.scalar(
            select(ServiceAccount.id).where(
                ServiceAccount.organization_id == actor.organization_id,
                ServiceAccount.name == payload.name.strip(),
                ServiceAccount.id != account.id,
            )
        )
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="A service account with that name exists")
    for field, value in changes.items():
        setattr(account, field, value.strip() if field == "name" and value else value)
    if "status" in changes:
        account.auth_version += 1
        if account.status == ServiceAccountStatus.SUSPENDED:
            now = authorization.utcnow()
            for token in list(
                (
                    await session.execute(
                        select(ApiToken).where(
                            ApiToken.service_account_id == account.id,
                            ApiToken.revoked_at.is_(None),
                        )
                    )
                ).scalars()
            ):
                token.revoked_at = now
    record_audit(
        session,
        action="service_account.updated",
        actor=actor,
        target_type="service_account",
        target_id=account.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(changes)},
    )
    return account


@router.delete("/service-accounts/{account_id}", status_code=204)
async def suspend_service_account(
    account_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    """Suspend a service principal and immediately revoke all of its tokens."""
    actor = identity.user
    account = await _owned_service(session, actor.organization_id, account_id)
    account.status = ServiceAccountStatus.SUSPENDED
    account.auth_version += 1
    now = authorization.utcnow()
    for token in list(
        (
            await session.execute(
                select(ApiToken).where(
                    ApiToken.service_account_id == account.id,
                    ApiToken.revoked_at.is_(None),
                )
            )
        ).scalars()
    ):
        token.revoked_at = now
    record_audit(
        session,
        action="service_account.suspended",
        actor=actor,
        target_type="service_account",
        target_id=account.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    return Response(status_code=204)


def _token_read(token: ApiToken) -> ApiTokenRead:
    principal_id = token.user_id or token.service_account_id
    if principal_id is None:
        raise RuntimeError("token has no principal")
    return ApiTokenRead(
        id=token.id,
        principal_type=token.principal_type,
        principal_id=principal_id,
        name=token.name,
        token_prefix=token.token_prefix,
        has_secret=True,
        expires_at=token.expires_at,
        revoked_at=token.revoked_at,
        ip_restrictions=list(token.ip_restrictions_json or []),
        last_used_at=token.last_used_at,
        last_used_ip=token.last_used_ip,
        created_at=token.created_at,
    )


async def _issue_token(
    session: AsyncSession,
    principal: authorization.Principal,
    payload: ApiTokenCreate,
    *,
    rotated_from: ApiToken | None = None,
) -> tuple[ApiToken, str]:
    try:
        restrictions = authorization.validate_ip_restrictions(payload.ip_restrictions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    generated = authorization.generate_api_token()
    kind = authorization.principal_type(principal)
    token = ApiToken(
        organization_id=principal.organization_id,
        principal_type=kind,
        user_id=principal.id if kind == PrincipalType.USER else None,
        service_account_id=(principal.id if kind == PrincipalType.SERVICE_ACCOUNT else None),
        name=payload.name.strip(),
        token_hash=generated.token_hash,
        token_prefix=generated.token_prefix,
        issued_auth_version=principal.auth_version,
        expires_at=authorization.utcnow() + timedelta(days=payload.expires_in_days),
        rotated_from_id=rotated_from.id if rotated_from else None,
        ip_restrictions_json=restrictions,
    )
    session.add(token)
    await session.flush()
    return token, generated.secret


def _issued(token: ApiToken, secret: str) -> ApiTokenIssued:
    return ApiTokenIssued(**_token_read(token).model_dump(), token=secret)


async def _owned_token(
    session: AsyncSession,
    organization_id: uuid.UUID,
    token_id: uuid.UUID,
    *,
    user_id: uuid.UUID | None = None,
    service_account_id: uuid.UUID | None = None,
) -> ApiToken:
    stmt = select(ApiToken).where(
        ApiToken.id == token_id, ApiToken.organization_id == organization_id
    )
    if user_id is not None:
        stmt = stmt.where(ApiToken.user_id == user_id)
    if service_account_id is not None:
        stmt = stmt.where(ApiToken.service_account_id == service_account_id)
    token = await session.scalar(stmt)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found")
    return token


@router.get("/tokens", response_model=list[ApiTokenRead])
async def list_personal_tokens(
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ApiTokenRead]:
    if not isinstance(identity.user, User):
        raise HTTPException(status_code=403, detail="Service accounts do not own personal tokens")
    if not await authorization.has_permission(session, identity.user, "tokens.self"):
        raise HTTPException(
            status_code=403, detail="You do not have permission to perform this action"
        )
    rows = list(
        (
            await session.execute(
                select(ApiToken)
                .where(ApiToken.user_id == identity.user.id)
                .order_by(ApiToken.created_at.desc())
            )
        ).scalars()
    )
    return [_token_read(value) for value in rows]


@router.post("/tokens", response_model=ApiTokenIssued, status_code=201)
async def create_personal_token(
    payload: ApiTokenCreate,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("tokens.self"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ApiTokenIssued:
    if not isinstance(identity.user, User):
        raise HTTPException(
            status_code=403, detail="Service accounts cannot create personal tokens"
        )
    token, secret = await _issue_token(session, identity.user, payload)
    record_audit(
        session,
        action="api_token.created",
        actor=identity.user,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"name": token.name, "expires_at": token.expires_at.isoformat()},
    )
    return _issued(token, secret)


@router.get("/service-accounts/{account_id}/tokens", response_model=list[ApiTokenRead])
async def list_service_tokens(
    account_id: uuid.UUID,
    actor: Annotated[User, Depends(require_permission("service_accounts.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ApiTokenRead]:
    await _owned_service(session, actor.organization_id, account_id)
    rows = list(
        (
            await session.execute(
                select(ApiToken)
                .where(ApiToken.service_account_id == account_id)
                .order_by(ApiToken.created_at.desc())
            )
        ).scalars()
    )
    return [_token_read(value) for value in rows]


@router.post(
    "/service-accounts/{account_id}/tokens",
    response_model=ApiTokenIssued,
    status_code=201,
)
async def create_service_token(
    account_id: uuid.UUID,
    payload: ApiTokenCreate,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ApiTokenIssued:
    actor = identity.user
    account = await _owned_service(session, actor.organization_id, account_id)
    if account.status != ServiceAccountStatus.ACTIVE:
        raise HTTPException(
            status_code=409, detail="Suspended service accounts cannot receive tokens"
        )
    token, secret = await _issue_token(session, account, payload)
    record_audit(
        session,
        action="service_account.token_created",
        actor=actor,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "service_account_id": str(account.id),
            "expires_at": token.expires_at.isoformat(),
        },
    )
    return _issued(token, secret)


async def _rotate_token(
    session: AsyncSession,
    token: ApiToken,
    principal: authorization.Principal,
    payload: ApiTokenRotate,
) -> tuple[ApiToken, str]:
    if token.revoked_at is not None:
        raise HTTPException(status_code=409, detail="A revoked token cannot be rotated")
    token.revoked_at = authorization.utcnow()
    restrictions = (
        list(token.ip_restrictions_json or [])
        if payload.ip_restrictions is None
        else payload.ip_restrictions
    )
    return await _issue_token(
        session,
        principal,
        ApiTokenCreate(
            name=token.name,
            expires_in_days=payload.expires_in_days,
            ip_restrictions=restrictions,
        ),
        rotated_from=token,
    )


@router.post("/tokens/{token_id}/rotate", response_model=ApiTokenIssued)
async def rotate_personal_token(
    token_id: uuid.UUID,
    payload: ApiTokenRotate,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("tokens.self"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ApiTokenIssued:
    if not isinstance(identity.user, User):
        raise HTTPException(status_code=403, detail="Service accounts do not own personal tokens")
    old = await _owned_token(
        session, identity.user.organization_id, token_id, user_id=identity.user.id
    )
    token, secret = await _rotate_token(session, old, identity.user, payload)
    record_audit(
        session,
        action="api_token.rotated",
        actor=identity.user,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"rotated_from_id": str(old.id)},
    )
    return _issued(token, secret)


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_personal_token(
    token_id: uuid.UUID,
    identity: Annotated[AuthenticatedIdentity, Depends(require_step_up_permission("tokens.self"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    if not isinstance(identity.user, User):
        raise HTTPException(status_code=403, detail="Service accounts do not own personal tokens")
    token = await _owned_token(
        session, identity.user.organization_id, token_id, user_id=identity.user.id
    )
    token.revoked_at = token.revoked_at or authorization.utcnow()
    record_audit(
        session,
        action="api_token.revoked",
        actor=identity.user,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    return Response(status_code=204)


@router.post(
    "/service-accounts/{account_id}/tokens/{token_id}/rotate",
    response_model=ApiTokenIssued,
)
async def rotate_service_token(
    account_id: uuid.UUID,
    token_id: uuid.UUID,
    payload: ApiTokenRotate,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ApiTokenIssued:
    account = await _owned_service(session, identity.user.organization_id, account_id)
    old = await _owned_token(
        session,
        identity.user.organization_id,
        token_id,
        service_account_id=account.id,
    )
    token, secret = await _rotate_token(session, old, account, payload)
    record_audit(
        session,
        action="service_account.token_rotated",
        actor=identity.user,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "service_account_id": str(account.id),
            "rotated_from_id": str(old.id),
        },
    )
    return _issued(token, secret)


@router.delete("/service-accounts/{account_id}/tokens/{token_id}", status_code=204)
async def revoke_service_token(
    account_id: uuid.UUID,
    token_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity,
        Depends(require_step_up_permission("service_accounts.manage")),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    await _owned_service(session, identity.user.organization_id, account_id)
    token = await _owned_token(
        session,
        identity.user.organization_id,
        token_id,
        service_account_id=account_id,
    )
    token.revoked_at = token.revoked_at or authorization.utcnow()
    record_audit(
        session,
        action="service_account.token_revoked",
        actor=identity.user,
        target_type="api_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"service_account_id": str(account_id)},
    )
    return Response(status_code=204)
