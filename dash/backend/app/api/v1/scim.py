"""Administrator SCIM token, mapping, preview, and provisioning-log APIs."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import StepUpIdentity, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.scim import (
    ScimGroup,
    ScimGroupMember,
    ScimGroupSiteMapping,
    ScimProvisioningLog,
    ScimToken,
)
from app.models.user import User
from app.schemas.scim import (
    ScimGroupMappingRead,
    ScimGroupMappingUpdate,
    ScimLogPage,
    ScimMappingPreview,
    ScimProvisioningLogRead,
    ScimTokenCreate,
    ScimTokenIssued,
    ScimTokenRead,
)
from app.services import scim
from app.services.audit import record_audit
from app.services.user_lifecycle import validate_site_ids

router = APIRouter(prefix="/scim", tags=["scim-administration"])

_ROLE_PRIORITY = {
    UserRole.ADMINISTRATOR: 60,
    UserRole.SECURITY_OPERATOR: 50,
    UserRole.PENTEST_APPROVER: 40,
    UserRole.REMEDIATION_OWNER: 30,
    UserRole.AUDITOR: 20,
    UserRole.VIEWER: 10,
}


def _require_admin(identity: StepUpIdentity) -> User:
    if identity.user.role != UserRole.ADMINISTRATOR:
        raise HTTPException(status_code=403, detail="Administrator access is required")
    return identity.user


async def _owned_token(
    session: AsyncSession, token_id: uuid.UUID, organization_id: uuid.UUID
) -> ScimToken:
    token = await session.scalar(
        select(ScimToken).where(
            ScimToken.id == token_id,
            ScimToken.organization_id == organization_id,
        )
    )
    if token is None:
        raise HTTPException(status_code=404, detail="SCIM token not found")
    return token


async def _owned_group(
    session: AsyncSession, group_id: uuid.UUID, organization_id: uuid.UUID
) -> ScimGroup:
    group = await session.scalar(
        select(ScimGroup).where(
            ScimGroup.id == group_id,
            ScimGroup.organization_id == organization_id,
        )
    )
    if group is None:
        raise HTTPException(status_code=404, detail="SCIM group not found")
    return group


def _token_read(value: ScimToken) -> ScimTokenRead:
    return ScimTokenRead(
        id=value.id,
        name=value.name,
        token_prefix=value.token_prefix,
        has_secret=True,
        created_at=value.created_at,
        expires_at=value.expires_at,
        revoked_at=value.revoked_at,
        last_used_at=value.last_used_at,
        last_used_ip=value.last_used_ip,
    )


def _token_issued(value: ScimToken, secret: str) -> ScimTokenIssued:
    return ScimTokenIssued(**_token_read(value).model_dump(), token=secret)


@router.get("/tokens", response_model=list[ScimTokenRead])
async def list_tokens(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ScimTokenRead]:
    rows = list(
        (
            await session.execute(
                select(ScimToken)
                .where(ScimToken.organization_id == admin.organization_id)
                .order_by(ScimToken.created_at.desc())
            )
        ).scalars()
    )
    return [_token_read(value) for value in rows]


@router.post("/tokens", response_model=ScimTokenIssued, status_code=201)
async def create_token(
    payload: ScimTokenCreate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ScimTokenIssued:
    admin = _require_admin(identity)
    generated = scim.generate_token()
    token = ScimToken(
        organization_id=admin.organization_id,
        name=payload.name.strip(),
        token_hash=generated.token_hash,
        token_prefix=generated.token_prefix,
        created_by_user_id=admin.id,
        expires_at=scim.utcnow()
        + timedelta(days=payload.expires_in_days or settings.scim_token_ttl_days),
    )
    session.add(token)
    await session.flush()
    record_audit(
        session,
        action="scim.token_created",
        actor=admin,
        target_type="scim_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"name": token.name, "expires_at": token.expires_at.isoformat()},
    )
    return _token_issued(token, generated.secret)


@router.post("/tokens/{token_id}/rotate", response_model=ScimTokenIssued)
async def rotate_token(
    token_id: uuid.UUID,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ScimTokenIssued:
    admin = _require_admin(identity)
    previous = await _owned_token(session, token_id, admin.organization_id)
    now = scim.utcnow()
    if previous.revoked_at is not None:
        raise HTTPException(status_code=409, detail="A revoked SCIM token cannot be rotated")
    previous.revoked_at = now
    generated = scim.generate_token()
    token = ScimToken(
        organization_id=admin.organization_id,
        name=previous.name,
        token_hash=generated.token_hash,
        token_prefix=generated.token_prefix,
        created_by_user_id=admin.id,
        rotated_from_id=previous.id,
        expires_at=now + timedelta(days=settings.scim_token_ttl_days),
    )
    session.add(token)
    await session.flush()
    record_audit(
        session,
        action="scim.token_rotated",
        actor=admin,
        target_type="scim_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"rotated_from_id": str(previous.id)},
    )
    return _token_issued(token, generated.secret)


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: uuid.UUID,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    admin = _require_admin(identity)
    token = await _owned_token(session, token_id, admin.organization_id)
    token.revoked_at = token.revoked_at or scim.utcnow()
    record_audit(
        session,
        action="scim.token_revoked",
        actor=admin,
        target_type="scim_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )


async def _mapping_read(session: AsyncSession, group: ScimGroup) -> ScimGroupMappingRead:
    member_count = int(
        await session.scalar(
            select(func.count())
            .select_from(ScimGroupMember)
            .where(ScimGroupMember.group_id == group.id)
        )
        or 0
    )
    site_ids = list(
        (
            await session.execute(
                select(ScimGroupSiteMapping.site_id)
                .where(ScimGroupSiteMapping.group_id == group.id)
                .order_by(ScimGroupSiteMapping.created_at.asc())
            )
        ).scalars()
    )
    return ScimGroupMappingRead(
        id=group.id,
        external_id=group.external_id,
        display_name=group.display_name,
        member_count=member_count,
        role=group.mapped_role,
        grants_all_sites=group.grants_all_sites,
        site_ids=site_ids,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


@router.get("/groups", response_model=list[ScimGroupMappingRead])
async def list_group_mappings(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ScimGroupMappingRead]:
    groups = list(
        (
            await session.execute(
                select(ScimGroup)
                .where(ScimGroup.organization_id == admin.organization_id)
                .order_by(ScimGroup.display_name.asc())
            )
        ).scalars()
    )
    return [await _mapping_read(session, group) for group in groups]


async def _mapping_preview(
    session: AsyncSession,
    group: ScimGroup,
    payload: ScimGroupMappingUpdate,
) -> ScimMappingPreview:
    users = list(
        (
            await session.execute(
                select(User)
                .join(ScimGroupMember, ScimGroupMember.user_id == User.id)
                .where(ScimGroupMember.group_id == group.id)
                .order_by(User.email.asc())
            )
        ).scalars()
    )
    preview_users: list[dict[str, object]] = []
    for user in users[:200]:
        memberships = list(
            (
                await session.execute(
                    select(ScimGroup)
                    .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
                    .where(ScimGroupMember.user_id == user.id)
                )
            ).scalars()
        )
        roles = [
            (payload.role if value.id == group.id else value.mapped_role) for value in memberships
        ]
        concrete_roles = [value for value in roles if value is not None]
        role = (
            max(concrete_roles, key=lambda value: _ROLE_PRIORITY[value])
            if concrete_roles
            else UserRole.VIEWER
        )
        all_sites = any(
            payload.grants_all_sites if value.id == group.id else value.grants_all_sites
            for value in memberships
        )
        preview_users.append(
            {
                "id": str(user.id),
                "email": user.email,
                "role": role.value,
                "site_access_mode": "all" if all_sites else "assigned",
            }
        )
    return ScimMappingPreview(
        group_id=group.id,
        affected_users=len(users),
        role=payload.role,
        grants_all_sites=payload.grants_all_sites,
        site_ids=payload.site_ids,
        users=preview_users,
    )


@router.post("/groups/{group_id}/mapping/preview", response_model=ScimMappingPreview)
async def preview_group_mapping(
    group_id: uuid.UUID,
    payload: ScimGroupMappingUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScimMappingPreview:
    group = await _owned_group(session, group_id, admin.organization_id)
    await validate_site_ids(session, admin.organization_id, set(payload.site_ids))
    return await _mapping_preview(session, group, payload)


@router.put("/groups/{group_id}/mapping", response_model=ScimGroupMappingRead)
async def update_group_mapping(
    group_id: uuid.UUID,
    payload: ScimGroupMappingUpdate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ScimGroupMappingRead:
    admin = _require_admin(identity)
    group = await _owned_group(session, group_id, admin.organization_id)
    await validate_site_ids(session, admin.organization_id, set(payload.site_ids))
    preview = await _mapping_preview(session, group, payload)
    previous = {
        "role": group.mapped_role.value if group.mapped_role else None,
        "grants_all_sites": group.grants_all_sites,
    }
    group.mapped_role = payload.role
    group.grants_all_sites = payload.grants_all_sites
    group.updated_at = scim.utcnow()
    await session.execute(
        delete(ScimGroupSiteMapping).where(ScimGroupSiteMapping.group_id == group.id)
    )
    session.add_all(
        [
            ScimGroupSiteMapping(
                organization_id=admin.organization_id,
                group_id=group.id,
                site_id=site_id,
            )
            for site_id in payload.site_ids
        ]
    )
    member_ids = set(
        (
            await session.execute(
                select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == group.id)
            )
        ).scalars()
    )
    await session.flush()
    await scim.recompute_users(session, admin.organization_id, member_ids, actor=admin)
    record_audit(
        session,
        action="scim.group_mapping_updated",
        actor=admin,
        target_type="scim_group",
        target_id=group.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "previous": previous,
            "role": payload.role.value if payload.role else None,
            "grants_all_sites": payload.grants_all_sites,
            "site_ids": [str(value) for value in payload.site_ids],
            "affected_users": preview.affected_users,
        },
    )
    return await _mapping_read(session, group)


@router.get("/logs", response_model=ScimLogPage)
async def provisioning_logs(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    succeeded: bool | None = None,
) -> ScimLogPage:
    conditions = [ScimProvisioningLog.organization_id == admin.organization_id]
    if succeeded is not None:
        conditions.append(ScimProvisioningLog.succeeded.is_(succeeded))
    total = int(
        await session.scalar(
            select(func.count()).select_from(ScimProvisioningLog).where(*conditions)
        )
        or 0
    )
    rows = list(
        (
            await session.execute(
                select(ScimProvisioningLog)
                .where(*conditions)
                .order_by(ScimProvisioningLog.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return ScimLogPage(
        items=[
            ScimProvisioningLogRead(
                id=value.id,
                operation=value.operation,
                resource_type=value.resource_type,
                resource_id=value.resource_id,
                external_id=value.external_id,
                status_code=value.status_code,
                succeeded=value.succeeded,
                detail=value.detail,
                request_id=value.request_id,
                source_ip=value.source_ip,
                changes=value.changes_json,
                created_at=value.created_at,
            )
            for value in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )
