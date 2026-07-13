"""Organization-isolated SCIM 2.0 Users, Groups, and discovery resources."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import AccountStatus, AuthenticationSource, SiteAccessMode, UserRole
from app.models.scim import ScimGroup, ScimGroupMember, ScimGroupSiteMapping
from app.models.user import User
from app.services import scim
from app.services.sessions import revoke_user_sessions
from app.services.user_lifecycle import (
    active_admin_count,
    lifecycle_event,
    revoke_pending_credentials,
)

router = APIRouter(prefix="/scim/v2", tags=["scim"])


def _json(
    body: object,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        body,
        status_code=status_code,
        media_type=scim.SCIM_MEDIA_TYPE,
        headers=headers,
    )


def _etag_headers(resource: dict[str, object]) -> dict[str, str]:
    meta = resource.get("meta")
    if not isinstance(meta, dict):
        return {}
    result: dict[str, str] = {}
    if isinstance(meta.get("version"), str):
        result["ETag"] = meta["version"]
    if isinstance(meta.get("location"), str):
        result["Location"] = meta["location"]
    return result


async def _owned_user(
    session: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID
) -> User:
    user = await session.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == organization_id,
            User.authentication_source == AuthenticationSource.SCIM,
        )
    )
    if user is None:
        raise scim.ScimError(404, "User resource not found")
    return user


async def _owned_group(
    session: AsyncSession, organization_id: uuid.UUID, group_id: uuid.UUID
) -> ScimGroup:
    group = await session.scalar(
        select(ScimGroup).where(
            ScimGroup.id == group_id,
            ScimGroup.organization_id == organization_id,
        )
    )
    if group is None:
        raise scim.ScimError(404, "Group resource not found")
    return group


def _uuid(value: str, resource_type: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise scim.ScimError(404, f"{resource_type} resource not found") from exc


def _active(payload: dict[str, object], *, default: bool) -> bool:
    value = payload.get("active", default)
    if not isinstance(value, bool):
        raise scim.ScimError(400, "active must be a boolean", "invalidValue")
    return value


async def _set_user_values(
    session: AsyncSession,
    user: User,
    payload: dict[str, object],
    *,
    replace: bool,
) -> dict[str, object]:
    email = scim.normalized_email(payload)
    external = (
        scim.external_id(payload) if (replace or "externalId" in payload) else user.scim_external_id
    )
    await scim.ensure_user_unique(
        session,
        organization_id=user.organization_id,
        email=email,
        external=external,
        exclude_user_id=user.id,
    )
    desired_active = _active(payload, default=(True if replace else user.is_active))
    previous_status = user.account_status
    if (
        not desired_active
        and user.role == UserRole.ADMINISTRATOR
        and user.account_status == AccountStatus.ACTIVE
        and await active_admin_count(session, user.organization_id, exclude_user_id=user.id) == 0
    ):
        raise scim.ScimError(
            409, "The last active administrator cannot be deactivated", "mutability"
        )
    previous = {
        "userName": user.email,
        "displayName": user.full_name,
        "externalId": user.scim_external_id,
        "active": user.account_status == AccountStatus.ACTIVE and user.is_active,
    }
    user.email = email
    if replace or "displayName" in payload or "name" in payload:
        user.full_name = scim.display_name(payload)
    user.scim_external_id = external
    desired_status = AccountStatus.ACTIVE if desired_active else AccountStatus.DEACTIVATED
    if user.account_status != desired_status or user.is_active != desired_active:
        user.set_account_status(desired_status, now=scim.utcnow())
        if not desired_active:
            await revoke_pending_credentials(session, user)
        else:
            user.auth_version += 1
            await revoke_user_sessions(session, user.id, reason="SCIM account reactivated")
        lifecycle_event(
            session,
            user=user,
            event_type="scim_status_changed",
            actor=None,
            previous_status=previous_status,
            new_status=desired_status,
            reason="SCIM provisioning request",
        )
    return {
        "previous": previous,
        "userName": user.email,
        "displayName": user.full_name,
        "externalId": user.scim_external_id,
        "active": desired_active,
    }


def _merge_user_patch(user: User, payload: dict[str, object]) -> dict[str, object]:
    schemas = payload.get("schemas")
    if not isinstance(schemas, list) or scim.SCIM_PATCH_SCHEMA not in schemas:
        raise scim.ScimError(400, "PatchOp schema is required", "invalidSyntax")
    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise scim.ScimError(400, "Patch Operations are required", "invalidSyntax")
    merged: dict[str, object] = {
        "userName": user.email,
        "displayName": user.full_name or "",
        "externalId": user.scim_external_id,
        "active": user.account_status == AccountStatus.ACTIVE and user.is_active,
    }
    aliases = {
        "username": "userName",
        "emails": "emails",
        "emails.value": "userName",
        'emails[type eq "work"].value': "userName",
        "displayname": "displayName",
        "name": "name",
        "name.formatted": "displayName",
        "externalid": "externalId",
        "active": "active",
    }
    for operation in operations:
        if not isinstance(operation, dict):
            raise scim.ScimError(400, "Patch operation is invalid", "invalidSyntax")
        op = str(operation.get("op", "")).lower()
        if op not in {"add", "replace", "remove"}:
            raise scim.ScimError(400, "Patch operation is unsupported", "invalidSyntax")
        path = operation.get("path")
        value = operation.get("value")
        if path is None:
            if op == "remove" or not isinstance(value, dict):
                raise scim.ScimError(400, "Patch path or object value is required", "invalidPath")
            for key, item in value.items():
                alias = aliases.get(str(key).lower())
                if alias is not None:
                    merged[alias] = item
            continue
        if not isinstance(path, str) or path.lower() not in aliases:
            raise scim.ScimError(400, "Patch path is unsupported", "invalidPath")
        alias = aliases[path.lower()]
        if alias == "userName" and path.lower().startswith("emails") and isinstance(value, list):
            candidate = next(
                (
                    item.get("value")
                    for item in value
                    if isinstance(item, dict) and isinstance(item.get("value"), str)
                ),
                None,
            )
            value = candidate
        if op == "remove":
            if alias == "userName":
                raise scim.ScimError(400, "userName cannot be removed", "mutability")
            merged[alias] = True if alias == "active" else None
        else:
            merged[alias] = value
    return merged


def _group_name(payload: dict[str, object]) -> str:
    value = payload.get("displayName")
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 512:
        raise scim.ScimError(400, "displayName is required", "invalidValue")
    return value.strip()


async def _list_users(
    request: Request,
    identity: scim.ScimContext,
    session: AsyncSession,
    settings: Settings,
    *,
    filter_expression: str | None,
    start_index: int,
    count: int,
    attributes: str | None,
    excluded_attributes: str | None,
) -> dict[str, object]:
    rows = list(
        (
            await session.execute(
                select(User)
                .where(
                    User.organization_id == identity.organization_id,
                    User.authentication_source == AuthenticationSource.SCIM,
                )
                .order_by(User.email.asc(), User.id.asc())
            )
        ).scalars()
    )
    resource_base = scim.base_url(request, settings)
    resources = [await scim.user_resource(session, row, resource_base) for row in rows]
    resources = scim.filter_resources(resources, filter_expression)
    resources = [
        scim.project_resource(value, attributes, excluded_attributes) for value in resources
    ]
    return scim.page_resources(resources, start_index, min(count, settings.scim_max_page_size))


async def _list_groups(
    request: Request,
    identity: scim.ScimContext,
    session: AsyncSession,
    settings: Settings,
    *,
    filter_expression: str | None,
    start_index: int,
    count: int,
    attributes: str | None,
    excluded_attributes: str | None,
) -> dict[str, object]:
    rows = list(
        (
            await session.execute(
                select(ScimGroup)
                .where(ScimGroup.organization_id == identity.organization_id)
                .order_by(ScimGroup.display_name.asc(), ScimGroup.id.asc())
            )
        ).scalars()
    )
    resource_base = scim.base_url(request, settings)
    resources = [await scim.group_resource(session, row, resource_base) for row in rows]
    resources = scim.filter_resources(resources, filter_expression)
    resources = [
        scim.project_resource(value, attributes, excluded_attributes) for value in resources
    ]
    return scim.page_resources(resources, start_index, min(count, settings.scim_max_page_size))


def _search_string(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 2048:
        raise scim.ScimError(400, f"{key} is invalid", "invalidValue")
    return value


def _search_integer(payload: dict[str, object], key: str, default: int, *, minimum: int) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise scim.ScimError(400, f"{key} is invalid", "invalidValue")
    return value


@router.get("/Users")
async def list_users(
    request: Request,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    filter_expression: Annotated[str | None, Query(alias="filter", max_length=2048)] = None,
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(ge=0)] = 100,
    attributes: Annotated[str | None, Query(max_length=2048)] = None,
    excluded_attributes: Annotated[
        str | None, Query(alias="excludedAttributes", max_length=2048)
    ] = None,
) -> JSONResponse:
    body = await _list_users(
        request,
        identity,
        session,
        settings,
        filter_expression=filter_expression,
        start_index=start_index,
        count=count,
        attributes=attributes,
        excluded_attributes=excluded_attributes,
    )
    scim.log_provisioning(
        session,
        context=identity,
        operation="list",
        status_code=200,
        succeeded=True,
        resource_type="User",
        changes={"total_results": body["totalResults"]},
    )
    return _json(body)


@router.post("/Users/.search")
async def search_users(
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    body = await _list_users(
        request,
        identity,
        session,
        settings,
        filter_expression=_search_string(payload, "filter"),
        start_index=_search_integer(payload, "startIndex", 1, minimum=1),
        count=_search_integer(payload, "count", 100, minimum=0),
        attributes=_search_string(payload, "attributes"),
        excluded_attributes=_search_string(payload, "excludedAttributes"),
    )
    scim.log_provisioning(
        session,
        context=identity,
        operation="search",
        status_code=200,
        succeeded=True,
        resource_type="User",
        changes={"total_results": body["totalResults"]},
    )
    return _json(body)


@router.post("/Users", status_code=201)
async def create_user(
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    scim.require_schema(payload, scim.SCIM_USER_SCHEMA)
    email = scim.normalized_email(payload)
    external = scim.external_id(payload)
    await scim.ensure_user_unique(
        session,
        organization_id=identity.organization_id,
        email=email,
        external=external,
    )
    active = _active(payload, default=True)
    now = datetime.now(UTC)
    user = User(
        organization_id=identity.organization_id,
        email=email,
        hashed_password=None,
        full_name=scim.display_name(payload),
        role=UserRole.VIEWER,
        is_active=active,
        account_status=AccountStatus.ACTIVE if active else AccountStatus.DEACTIVATED,
        authentication_source=AuthenticationSource.SCIM,
        site_access_mode=SiteAccessMode.ASSIGNED,
        scim_external_id=external,
    )
    user.set_account_status(AccountStatus.ACTIVE if active else AccountStatus.DEACTIVATED, now=now)
    session.add(user)
    await session.flush()
    lifecycle_event(
        session,
        user=user,
        event_type="scim_created",
        actor=None,
        new_status=user.account_status,
        reason="SCIM provisioning request",
        metadata={"external_id": external},
    )
    resource = await scim.user_resource(session, user, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="create",
        status_code=201,
        succeeded=True,
        resource_type="User",
        resource_id=user.id,
        external_id=external,
        changes={"active": active},
    )
    return _json(resource, status_code=201, headers=_etag_headers(resource))


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    request: Request,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    attributes: Annotated[str | None, Query(max_length=2048)] = None,
    excluded_attributes: Annotated[
        str | None, Query(alias="excludedAttributes", max_length=2048)
    ] = None,
) -> JSONResponse:
    user = await _owned_user(session, identity.organization_id, _uuid(user_id, "User"))
    resource = await scim.user_resource(session, user, scim.base_url(request, settings))
    resource = scim.project_resource(resource, attributes, excluded_attributes)
    scim.log_provisioning(
        session,
        context=identity,
        operation="get",
        status_code=200,
        succeeded=True,
        resource_type="User",
        resource_id=user.id,
    )
    return _json(resource, headers=_etag_headers(resource))


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    scim.require_schema(payload, scim.SCIM_USER_SCHEMA)
    user = await _owned_user(session, identity.organization_id, _uuid(user_id, "User"))
    changes = await _set_user_values(session, user, payload, replace=True)
    await session.flush()
    resource = await scim.user_resource(session, user, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="replace",
        status_code=200,
        succeeded=True,
        resource_type="User",
        resource_id=user.id,
        external_id=user.scim_external_id,
        changes=changes,
    )
    return _json(resource, headers=_etag_headers(resource))


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    user = await _owned_user(session, identity.organization_id, _uuid(user_id, "User"))
    merged = _merge_user_patch(user, payload)
    changes = await _set_user_values(session, user, merged, replace=False)
    await session.flush()
    resource = await scim.user_resource(session, user, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="patch",
        status_code=200,
        succeeded=True,
        resource_type="User",
        resource_id=user.id,
        external_id=user.scim_external_id,
        changes=changes,
    )
    return _json(resource, headers=_etag_headers(resource))


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    user = await _owned_user(session, identity.organization_id, _uuid(user_id, "User"))
    if user.account_status == AccountStatus.ACTIVE and user.is_active:
        if (
            user.role == UserRole.ADMINISTRATOR
            and await active_admin_count(session, user.organization_id, exclude_user_id=user.id)
            == 0
        ):
            raise scim.ScimError(
                409, "The last active administrator cannot be deactivated", "mutability"
            )
        previous = user.account_status
        user.set_account_status(AccountStatus.DEACTIVATED, now=scim.utcnow())
        await revoke_pending_credentials(session, user)
        lifecycle_event(
            session,
            user=user,
            event_type="scim_deprovisioned",
            actor=None,
            previous_status=previous,
            new_status=AccountStatus.DEACTIVATED,
            reason="SCIM DELETE deactivated the account; history was preserved",
        )
    scim.log_provisioning(
        session,
        context=identity,
        operation="delete",
        status_code=204,
        succeeded=True,
        resource_type="User",
        resource_id=user.id,
        external_id=user.scim_external_id,
        changes={"active": False, "deleted": False},
    )
    return Response(status_code=204)


@router.get("/Groups")
async def list_groups(
    request: Request,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    filter_expression: Annotated[str | None, Query(alias="filter", max_length=2048)] = None,
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(ge=0)] = 100,
    attributes: Annotated[str | None, Query(max_length=2048)] = None,
    excluded_attributes: Annotated[
        str | None, Query(alias="excludedAttributes", max_length=2048)
    ] = None,
) -> JSONResponse:
    body = await _list_groups(
        request,
        identity,
        session,
        settings,
        filter_expression=filter_expression,
        start_index=start_index,
        count=count,
        attributes=attributes,
        excluded_attributes=excluded_attributes,
    )
    scim.log_provisioning(
        session,
        context=identity,
        operation="list",
        status_code=200,
        succeeded=True,
        resource_type="Group",
        changes={"total_results": body["totalResults"]},
    )
    return _json(body)


@router.post("/Groups/.search")
async def search_groups(
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    body = await _list_groups(
        request,
        identity,
        session,
        settings,
        filter_expression=_search_string(payload, "filter"),
        start_index=_search_integer(payload, "startIndex", 1, minimum=1),
        count=_search_integer(payload, "count", 100, minimum=0),
        attributes=_search_string(payload, "attributes"),
        excluded_attributes=_search_string(payload, "excludedAttributes"),
    )
    scim.log_provisioning(
        session,
        context=identity,
        operation="search",
        status_code=200,
        succeeded=True,
        resource_type="Group",
        changes={"total_results": body["totalResults"]},
    )
    return _json(body)


@router.post("/Groups", status_code=201)
async def create_group(
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    scim.require_schema(payload, scim.SCIM_GROUP_SCHEMA)
    name = _group_name(payload)
    external = scim.external_id(payload)
    await scim.ensure_group_unique(
        session,
        organization_id=identity.organization_id,
        name=name,
        external=external,
    )
    group = ScimGroup(
        organization_id=identity.organization_id,
        display_name=name,
        external_id=external,
    )
    session.add(group)
    await session.flush()
    affected = await scim.replace_group_members(
        session, group=group, member_ids=scim.member_ids(payload)
    )
    await session.flush()
    await scim.recompute_users(session, identity.organization_id, affected)
    group.updated_at = scim.utcnow()
    resource = await scim.group_resource(session, group, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="create",
        status_code=201,
        succeeded=True,
        resource_type="Group",
        resource_id=group.id,
        external_id=external,
        changes={"member_count": len(affected)},
    )
    return _json(resource, status_code=201, headers=_etag_headers(resource))


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str,
    request: Request,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    attributes: Annotated[str | None, Query(max_length=2048)] = None,
    excluded_attributes: Annotated[
        str | None, Query(alias="excludedAttributes", max_length=2048)
    ] = None,
) -> JSONResponse:
    group = await _owned_group(session, identity.organization_id, _uuid(group_id, "Group"))
    resource = await scim.group_resource(session, group, scim.base_url(request, settings))
    resource = scim.project_resource(resource, attributes, excluded_attributes)
    scim.log_provisioning(
        session,
        context=identity,
        operation="get",
        status_code=200,
        succeeded=True,
        resource_type="Group",
        resource_id=group.id,
    )
    return _json(resource, headers=_etag_headers(resource))


async def _replace_group(
    session: AsyncSession,
    group: ScimGroup,
    payload: dict[str, object],
) -> tuple[set[uuid.UUID], dict[str, object]]:
    name = _group_name(payload)
    external = scim.external_id(payload)
    await scim.ensure_group_unique(
        session,
        organization_id=group.organization_id,
        name=name,
        external=external,
        exclude_group_id=group.id,
    )
    previous = {
        "displayName": group.display_name,
        "externalId": group.external_id,
    }
    group.display_name = name
    group.external_id = external
    affected = await scim.replace_group_members(
        session, group=group, member_ids=scim.member_ids(payload)
    )
    group.updated_at = scim.utcnow()
    await session.flush()
    await scim.recompute_users(session, group.organization_id, affected)
    return affected, {"previous": previous, "member_count": len(scim.member_ids(payload))}


@router.put("/Groups/{group_id}")
async def replace_group(
    group_id: str,
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    scim.require_schema(payload, scim.SCIM_GROUP_SCHEMA)
    group = await _owned_group(session, identity.organization_id, _uuid(group_id, "Group"))
    _, changes = await _replace_group(session, group, payload)
    resource = await scim.group_resource(session, group, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="replace",
        status_code=200,
        succeeded=True,
        resource_type="Group",
        resource_id=group.id,
        external_id=group.external_id,
        changes=changes,
    )
    return _json(resource, headers=_etag_headers(resource))


def _merge_group_patch(
    group: ScimGroup,
    current_members: set[uuid.UUID],
    payload: dict[str, object],
) -> dict[str, object]:
    schemas = payload.get("schemas")
    if not isinstance(schemas, list) or scim.SCIM_PATCH_SCHEMA not in schemas:
        raise scim.ScimError(400, "PatchOp schema is required", "invalidSyntax")
    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise scim.ScimError(400, "Patch Operations are required", "invalidSyntax")
    merged: dict[str, object] = {
        "displayName": group.display_name,
        "externalId": group.external_id,
        "members": [{"value": str(value)} for value in current_members],
    }
    members = set(current_members)
    member_filter = re.compile(r'^members\[value\s+eq\s+"([^"]+)"\]$', re.IGNORECASE)
    for operation in operations:
        if not isinstance(operation, dict):
            raise scim.ScimError(400, "Patch operation is invalid", "invalidSyntax")
        op = str(operation.get("op", "")).lower()
        if op not in {"add", "replace", "remove"}:
            raise scim.ScimError(400, "Patch operation is unsupported", "invalidSyntax")
        path = operation.get("path")
        value = operation.get("value")
        if path is None:
            if op == "remove" or not isinstance(value, dict):
                raise scim.ScimError(400, "Patch path or object value is required", "invalidPath")
            for key in ("displayName", "externalId", "members"):
                if key in value:
                    merged[key] = value[key]
            if "members" in value:
                members = scim.member_ids({"members": value["members"]})
            continue
        if not isinstance(path, str):
            raise scim.ScimError(400, "Patch path is invalid", "invalidPath")
        lower = path.lower()
        filtered = member_filter.match(path)
        if filtered:
            try:
                member_id = uuid.UUID(filtered.group(1))
            except ValueError as exc:
                raise scim.ScimError(400, "Member path is invalid", "invalidPath") from exc
            if op == "remove":
                members.discard(member_id)
            else:
                members.add(member_id)
        elif lower == "members":
            incoming = scim.member_ids({"members": value})
            if op == "add":
                members |= incoming
            elif op == "replace":
                members = incoming
            else:
                members.clear()
        elif lower == "displayname":
            if op == "remove":
                raise scim.ScimError(400, "displayName cannot be removed", "mutability")
            merged["displayName"] = value
        elif lower == "externalid":
            merged["externalId"] = None if op == "remove" else value
        else:
            raise scim.ScimError(400, "Patch path is unsupported", "invalidPath")
    merged["members"] = [{"value": str(value)} for value in members]
    return merged


@router.patch("/Groups/{group_id}")
async def patch_group(
    group_id: str,
    request: Request,
    payload: Annotated[dict[str, object], Body()],
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    group = await _owned_group(session, identity.organization_id, _uuid(group_id, "Group"))
    current_members = set(
        (
            await session.execute(
                select(ScimGroupMember.user_id).where(
                    ScimGroupMember.organization_id == identity.organization_id,
                    ScimGroupMember.group_id == group.id,
                )
            )
        ).scalars()
    )
    merged = _merge_group_patch(group, current_members, payload)
    _, changes = await _replace_group(session, group, merged)
    resource = await scim.group_resource(session, group, scim.base_url(request, settings))
    scim.log_provisioning(
        session,
        context=identity,
        operation="patch",
        status_code=200,
        succeeded=True,
        resource_type="Group",
        resource_id=group.id,
        external_id=group.external_id,
        changes=changes,
    )
    return _json(resource, headers=_etag_headers(resource))


@router.delete("/Groups/{group_id}", status_code=204)
async def delete_group(
    group_id: str,
    identity: scim.ScimIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    group = await _owned_group(session, identity.organization_id, _uuid(group_id, "Group"))
    affected = set(
        (
            await session.execute(
                select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == group.id)
            )
        ).scalars()
    )
    external = group.external_id
    await session.execute(delete(ScimGroupMember).where(ScimGroupMember.group_id == group.id))
    await session.execute(
        delete(ScimGroupSiteMapping).where(ScimGroupSiteMapping.group_id == group.id)
    )
    await session.delete(group)
    await session.flush()
    await scim.recompute_users(session, identity.organization_id, affected)
    scim.log_provisioning(
        session,
        context=identity,
        operation="delete",
        status_code=204,
        succeeded=True,
        resource_type="Group",
        resource_id=group.id,
        external_id=external,
        changes={"members_removed": len(affected)},
    )
    return Response(status_code=204)


def _service_provider_config(resource_base: str, max_results: int) -> dict[str, object]:
    return {
        "schemas": [scim.SCIM_SERVICE_PROVIDER_SCHEMA],
        "documentationUri": f"{resource_base.rsplit('/scim/v2', 1)[0]}/docs",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": max_results},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Organization bearer token",
                "description": "A rotating Vulna SCIM token shown once at creation",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{resource_base}/ServiceProviderConfig",
        },
    }


def _resource_types(resource_base: str) -> list[dict[str, object]]:
    return [
        {
            "schemas": [scim.SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "SCIM-provisioned Vulna user",
            "schema": scim.SCIM_USER_SCHEMA,
            "schemaExtensions": [],
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{resource_base}/ResourceTypes/User",
            },
        },
        {
            "schemas": [scim.SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "SCIM group mapped to Vulna roles and sites",
            "schema": scim.SCIM_GROUP_SCHEMA,
            "schemaExtensions": [],
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{resource_base}/ResourceTypes/Group",
            },
        },
    ]


def _attribute(
    name: str,
    attribute_type: str,
    *,
    required: bool = False,
    multi: bool = False,
    mutability: str = "readWrite",
) -> dict[str, object]:
    return {
        "name": name,
        "type": attribute_type,
        "multiValued": multi,
        "required": required,
        "caseExact": False,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "server" if name in {"userName", "displayName"} else "none",
    }


def _schemas(resource_base: str) -> list[dict[str, object]]:
    return [
        {
            "schemas": [scim.SCIM_SCHEMA_SCHEMA],
            "id": scim.SCIM_USER_SCHEMA,
            "name": "User",
            "description": "SCIM-provisioned Vulna user",
            "attributes": [
                _attribute("userName", "string", required=True),
                _attribute("externalId", "string"),
                _attribute("displayName", "string"),
                _attribute("name", "complex"),
                _attribute("active", "boolean"),
                _attribute("emails", "complex", multi=True),
                _attribute("roles", "complex", multi=True, mutability="readOnly"),
                _attribute("groups", "complex", multi=True, mutability="readOnly"),
                _attribute("password", "string", mutability="writeOnly"),
            ],
            "meta": {
                "resourceType": "Schema",
                "location": f"{resource_base}/Schemas/{scim.SCIM_USER_SCHEMA}",
            },
        },
        {
            "schemas": [scim.SCIM_SCHEMA_SCHEMA],
            "id": scim.SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "SCIM group mapped to Vulna access",
            "attributes": [
                _attribute("displayName", "string", required=True),
                _attribute("externalId", "string"),
                _attribute("members", "complex", multi=True),
            ],
            "meta": {
                "resourceType": "Schema",
                "location": f"{resource_base}/Schemas/{scim.SCIM_GROUP_SCHEMA}",
            },
        },
    ]


@router.get("/ServiceProviderConfig")
async def service_provider_config(
    request: Request,
    identity: scim.ScimIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    del identity
    return _json(
        _service_provider_config(scim.base_url(request, settings), settings.scim_max_page_size)
    )


@router.get("/ResourceTypes")
async def resource_types(
    request: Request,
    identity: scim.ScimIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    del identity
    values = _resource_types(scim.base_url(request, settings))
    return _json(scim.page_resources(values, 1, len(values)))


@router.get("/ResourceTypes/{resource_type}")
async def resource_type(
    resource_type: str,
    request: Request,
    identity: scim.ScimIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    del identity
    value = next(
        (
            item
            for item in _resource_types(scim.base_url(request, settings))
            if str(item["id"]).lower() == resource_type.lower()
        ),
        None,
    )
    if value is None:
        raise scim.ScimError(404, "ResourceType not found")
    return _json(value)


@router.get("/Schemas")
async def schemas(
    request: Request,
    identity: scim.ScimIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    del identity
    values = _schemas(scim.base_url(request, settings))
    return _json(scim.page_resources(values, 1, len(values)))


@router.get("/Schemas/{schema_id:path}")
async def schema(
    schema_id: str,
    request: Request,
    identity: scim.ScimIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    del identity
    value = next(
        (
            item
            for item in _schemas(scim.base_url(request, settings))
            if str(item["id"]) == schema_id
        ),
        None,
    )
    if value is None:
        raise scim.ScimError(404, "Schema not found")
    return _json(value)
