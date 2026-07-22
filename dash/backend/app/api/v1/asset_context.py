"""Asset context, normalized tags, groups, bulk editing, and ownership APIs."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth import site_scope
from app.auth.dependencies import CurrentUser, require_permission
from app.db.session import get_session
from app.models.asset import Asset
from app.models.asset_context import (
    AssetGroup,
    AssetGroupMembership,
    AssetOwnershipHistory,
    AssetTag,
    AssetTagAssignment,
    DepartmentOwner,
)
from app.models.enums import AssetGroupType, AssetMembershipSource, GrantScopeType
from app.models.finding import Finding
from app.models.scim import ScimGroup
from app.models.user import User
from app.schemas.asset import (
    AssetBulkDelete,
    AssetBulkDeleteResult,
    AssetBulkResult,
    AssetBulkUpdate,
    AssetContextUpdate,
    AssetGroupCreate,
    AssetGroupMembershipRead,
    AssetGroupRead,
    AssetGroupUpdate,
    AssetTagAssignmentRead,
    AssetTagCreate,
    AssetTagRead,
    AssetTagUpdate,
    DepartmentOwnerRead,
    DepartmentOwnerUpsert,
    GroupPreviewMatch,
    GroupPreviewRequest,
    GroupPreviewResponse,
    OwnershipHistoryRead,
    OwnershipResolution,
    StaticMembershipChange,
)
from app.schemas.common import Page
from app.services import asset_context, authorization, risk
from app.services.audit import record_audit

asset_router = APIRouter(
    prefix="/assets",
    tags=["asset context"],
    dependencies=[Depends(require_permission("assets.read"))],
)
tag_router = APIRouter(
    prefix="/asset-tags",
    tags=["asset context"],
    dependencies=[Depends(require_permission("assets.read"))],
)
group_router = APIRouter(
    prefix="/asset-groups",
    tags=["asset context"],
    dependencies=[Depends(require_permission("assets.read"))],
)
department_router = APIRouter(
    prefix="/department-owners",
    tags=["asset context"],
    dependencies=[Depends(require_permission("assets.read"))],
)


def _bad_request(exc: asset_context.AssetContextError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))


async def _get_asset(
    session: AsyncSession,
    asset_id: uuid.UUID,
    current_user: User,
    *,
    permission_key: str,
) -> Asset:
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == current_user.organization_id,
            site_scope.site_scope_clause(
                current_user, Asset.site_id, permission_key=permission_key
            ),
        )
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


async def _require_org_manage(session: AsyncSession, current_user: User) -> None:
    allowed = await authorization.has_permission(
        session,
        current_user,
        "assets.manage",
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=current_user.organization_id,
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Organization-wide asset access is required")


async def _get_tag(session: AsyncSession, tag_id: uuid.UUID, org_id: uuid.UUID) -> AssetTag:
    tag = await session.get(AssetTag, tag_id)
    if tag is None or tag.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Asset tag not found")
    return tag


async def _get_group(
    session: AsyncSession,
    group_id: uuid.UUID,
    current_user: User,
    *,
    permission_key: str,
) -> AssetGroup:
    group = await session.get(AssetGroup, group_id)
    if group is None or group.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Asset group not found")
    if group.site_id is None:
        allowed = await authorization.has_permission(
            session,
            current_user,
            permission_key,
            scope_type=GrantScopeType.ORGANIZATION,
            scope_id=current_user.organization_id,
        )
        if not allowed:
            raise HTTPException(status_code=404, detail="Asset group not found")
    else:
        await site_scope.require_site_access(
            session,
            current_user,
            group.site_id,
            not_found_detail="Asset group not found",
            permission_key=permission_key,
        )
    return group


async def _group_read(session: AsyncSession, group: AssetGroup) -> AssetGroupRead:
    count = await session.scalar(
        select(func.count())
        .select_from(AssetGroupMembership)
        .where(AssetGroupMembership.group_id == group.id)
    )
    return AssetGroupRead.model_validate(group).model_copy(update={"member_count": count or 0})


def _audit(
    session: AsyncSession,
    *,
    action: str,
    actor: User,
    context: RequestContext,
    target_type: str,
    target_id: uuid.UUID | str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    record_audit(
        session,
        action=action,
        actor=actor,
        organization_id=actor.organization_id,
        target_type=target_type,
        target_id=target_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata=metadata,
    )


async def _rescore_asset_findings(
    session: AsyncSession, asset: Asset, actor_user_id: uuid.UUID
) -> None:
    findings = (
        await session.execute(select(Finding).where(Finding.asset_id == asset.id))
    ).scalars()
    for finding in findings:
        await risk.score_finding(session, finding, created_by_user_id=actor_user_id)


@asset_router.patch("/{asset_id}/context", response_model=dict[str, Any])
async def update_asset_context(
    asset_id: uuid.UUID,
    payload: AssetContextUpdate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    asset = await _get_asset(session, asset_id, manager, permission_key="assets.manage")
    changes = payload.model_dump(exclude_unset=True)
    if "context_json" in changes and changes["context_json"] is not None:
        try:
            asset_context.validate_context_json(changes["context_json"])
        except asset_context.AssetContextError as exc:
            raise _bad_request(exc) from exc
    try:
        await asset_context.validate_owner(
            session, manager.organization_id, changes.get("owner_user_id", asset.owner_user_id)
        )
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc
    for field, value in changes.items():
        setattr(asset, field, value)
    await session.flush()
    if {"criticality", "internet_exposed"}.intersection(changes):
        await _rescore_asset_findings(session, asset, manager.id)
    await asset_context.refresh_dynamic_memberships_for_asset(session, asset)
    ownership = await asset_context.resolve_ownership(session, asset)
    await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset.context_updated",
        actor=manager,
        context=context,
        target_type="asset",
        target_id=asset.id,
        metadata={"changed_fields": sorted(changes)},
    )
    return {
        "id": str(asset.id),
        "changed_fields": sorted(changes),
        "ownership": OwnershipResolution(**ownership.__dict__).model_dump(mode="json"),
    }


@asset_router.post("/bulk", response_model=AssetBulkResult)
async def bulk_update_assets(
    payload: AssetBulkUpdate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetBulkResult:
    asset_ids = list(dict.fromkeys(payload.asset_ids))
    assets = list(
        (
            await session.execute(
                select(Asset).where(
                    Asset.id.in_(asset_ids),
                    Asset.organization_id == manager.organization_id,
                    site_scope.site_scope_clause(
                        manager, Asset.site_id, permission_key="assets.manage"
                    ),
                )
            )
        ).scalars()
    )
    if len(assets) != len(asset_ids):
        raise HTTPException(status_code=404, detail="One or more assets were not found")
    context_changes = payload.context.model_dump(exclude_unset=True) if payload.context else {}
    if context_changes.get("context_json") is not None:
        try:
            asset_context.validate_context_json(context_changes["context_json"])
        except asset_context.AssetContextError as exc:
            raise _bad_request(exc) from exc
    try:
        await asset_context.validate_owner(
            session, manager.organization_id, context_changes.get("owner_user_id")
        )
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc

    add_tags = [
        await _get_tag(session, value, manager.organization_id) for value in payload.add_tag_ids
    ]
    remove_tag_ids = set(payload.remove_tag_ids)
    if remove_tag_ids:
        found_remove_tags = set(
            (
                await session.execute(
                    select(AssetTag.id).where(
                        AssetTag.organization_id == manager.organization_id,
                        AssetTag.id.in_(remove_tag_ids),
                    )
                )
            ).scalars()
        )
        if found_remove_tags != remove_tag_ids:
            raise HTTPException(status_code=404, detail="One or more asset tags were not found")

    add_groups = [
        await _get_group(session, value, manager, permission_key="assets.manage")
        for value in payload.add_static_group_ids
    ]
    remove_groups = [
        await _get_group(session, value, manager, permission_key="assets.manage")
        for value in payload.remove_static_group_ids
    ]
    if any(group.group_type != AssetGroupType.STATIC for group in [*add_groups, *remove_groups]):
        raise HTTPException(status_code=409, detail="Bulk membership edits require static groups")

    tags_added = tags_removed = memberships_added = memberships_removed = 0
    for asset in assets:
        for field, value in context_changes.items():
            setattr(asset, field, value)
        for tag in add_tags:
            _, created = await asset_context.assign_tag(
                session, asset, tag, assigned_by_user_id=manager.id
            )
            tags_added += int(created)
        for tag_id in remove_tag_ids:
            tags_removed += int(await asset_context.remove_tag(session, asset, tag_id))
        for group in add_groups:
            if group.site_id is not None and group.site_id != asset.site_id:
                raise HTTPException(status_code=409, detail="Asset is outside a group's site")
            existing = await session.scalar(
                select(AssetGroupMembership.id).where(
                    AssetGroupMembership.group_id == group.id,
                    AssetGroupMembership.asset_id == asset.id,
                )
            )
            if existing is None:
                session.add(
                    AssetGroupMembership(
                        organization_id=manager.organization_id,
                        group_id=group.id,
                        asset_id=asset.id,
                        source=AssetMembershipSource.STATIC,
                        explanation_json={"reason": "Explicit static membership"},
                    )
                )
                memberships_added += 1
        for group in remove_groups:
            removal_count = await session.scalar(
                select(func.count())
                .select_from(AssetGroupMembership)
                .where(
                    AssetGroupMembership.group_id == group.id,
                    AssetGroupMembership.asset_id == asset.id,
                    AssetGroupMembership.source == AssetMembershipSource.STATIC,
                )
            )
            await session.execute(
                delete(AssetGroupMembership).where(
                    AssetGroupMembership.group_id == group.id,
                    AssetGroupMembership.asset_id == asset.id,
                    AssetGroupMembership.source == AssetMembershipSource.STATIC,
                )
            )
            memberships_removed += removal_count or 0
        await session.flush()
        if {"criticality", "internet_exposed"}.intersection(context_changes):
            await _rescore_asset_findings(session, asset, manager.id)
        await asset_context.refresh_dynamic_memberships_for_asset(session, asset)
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset.bulk_updated",
        actor=manager,
        context=context,
        target_type="asset_batch",
        target_id=None,
        metadata={
            "asset_ids": [str(value) for value in asset_ids],
            "changed_fields": sorted(context_changes),
            "tags_added": tags_added,
            "tags_removed": tags_removed,
            "memberships_added": memberships_added,
            "memberships_removed": memberships_removed,
        },
    )
    return AssetBulkResult(
        updated_assets=len(assets),
        tags_added=tags_added,
        tags_removed=tags_removed,
        memberships_added=memberships_added,
        memberships_removed=memberships_removed,
    )


@asset_router.delete("/{asset_id}", status_code=204, response_model=None)
async def delete_asset(
    asset_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    """Permanently remove one accessible asset and its dependent inventory."""
    asset = await _get_asset(session, asset_id, manager, permission_key="assets.manage")
    metadata = {
        "canonical_name": asset.canonical_name,
        "site_id": str(asset.site_id),
    }
    await session.delete(asset)
    _audit(
        session,
        action="asset.deleted",
        actor=manager,
        context=context,
        target_type="asset",
        target_id=asset_id,
        metadata=metadata,
    )


@asset_router.post("/bulk-delete", response_model=AssetBulkDeleteResult)
async def bulk_delete_assets(
    payload: AssetBulkDelete,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetBulkDeleteResult:
    """Remove every accessible asset while treating stale IDs as already absent."""
    asset_ids = list(dict.fromkeys(payload.asset_ids))
    assets = list(
        (
            await session.execute(
                select(Asset).where(
                    Asset.id.in_(asset_ids),
                    Asset.organization_id == manager.organization_id,
                    site_scope.site_scope_clause(
                        manager, Asset.site_id, permission_key="assets.manage"
                    ),
                )
            )
        ).scalars()
    )
    for asset in assets:
        await session.delete(asset)
    skipped_assets = len(asset_ids) - len(assets)
    _audit(
        session,
        action="asset.bulk_deleted",
        actor=manager,
        context=context,
        target_type="asset_batch",
        target_id=None,
        metadata={
            # Record only assets the caller could access. A supplied ID from a
            # different tenant or site remains indistinguishable from a stale ID.
            "asset_ids": [str(asset.id) for asset in assets],
            "requested_assets": len(asset_ids),
            "deleted_assets": len(assets),
            "skipped_assets": skipped_assets,
        },
    )
    return AssetBulkDeleteResult(
        deleted_assets=len(assets),
        skipped_assets=skipped_assets,
    )


@asset_router.get("/{asset_id}/tags", response_model=list[AssetTagAssignmentRead])
async def list_asset_tags(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[AssetTagAssignmentRead]:
    asset = await _get_asset(session, asset_id, current_user, permission_key="assets.read")
    rows = (
        await session.execute(
            select(AssetTagAssignment, AssetTag)
            .join(AssetTag, AssetTag.id == AssetTagAssignment.tag_id)
            .where(AssetTagAssignment.asset_id == asset.id)
            .order_by(AssetTag.normalized_name)
        )
    ).all()
    return [
        AssetTagAssignmentRead(
            asset_id=assignment.asset_id,
            tag=AssetTagRead.model_validate(tag),
            source=assignment.source,
            metadata_json=assignment.metadata_json,
            created_at=assignment.created_at,
        )
        for assignment, tag in rows
    ]


@asset_router.put(
    "/{asset_id}/tags/{tag_id}",
    response_model=AssetTagAssignmentRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_asset_tag(
    asset_id: uuid.UUID,
    tag_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetTagAssignmentRead:
    asset = await _get_asset(session, asset_id, manager, permission_key="assets.manage")
    tag = await _get_tag(session, tag_id, manager.organization_id)
    assignment, created = await asset_context.assign_tag(
        session, asset, tag, assigned_by_user_id=manager.id
    )
    ownership = await asset_context.resolve_ownership(session, asset)
    await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset.tag_assigned",
        actor=manager,
        context=context,
        target_type="asset",
        target_id=asset.id,
        metadata={"tag_id": str(tag.id), "idempotent_replay": not created},
    )
    return AssetTagAssignmentRead(
        asset_id=asset.id,
        tag=AssetTagRead.model_validate(tag),
        source=assignment.source,
        metadata_json=assignment.metadata_json,
        created_at=assignment.created_at,
    )


@asset_router.delete("/{asset_id}/tags/{tag_id}", status_code=204, response_model=None)
async def delete_asset_tag(
    asset_id: uuid.UUID,
    tag_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    asset = await _get_asset(session, asset_id, manager, permission_key="assets.manage")
    if not await asset_context.remove_tag(session, asset, tag_id):
        raise HTTPException(status_code=404, detail="Asset tag assignment not found")
    ownership = await asset_context.resolve_ownership(session, asset)
    await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset.tag_removed",
        actor=manager,
        context=context,
        target_type="asset",
        target_id=asset.id,
        metadata={"tag_id": str(tag_id)},
    )


@asset_router.get("/{asset_id}/ownership", response_model=OwnershipResolution)
async def get_asset_ownership(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    finding_id: Annotated[uuid.UUID | None, Query()] = None,
) -> OwnershipResolution:
    asset = await _get_asset(session, asset_id, current_user, permission_key="assets.read")
    finding = None
    if finding_id is not None:
        finding = await session.get(Finding, finding_id)
        if (
            finding is None
            or finding.organization_id != current_user.organization_id
            or finding.asset_id != asset.id
        ):
            raise HTTPException(status_code=404, detail="Finding not found")
    try:
        result = await asset_context.resolve_ownership(session, asset, finding=finding)
    except asset_context.AssetContextError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return OwnershipResolution(**result.__dict__)


@asset_router.get("/{asset_id}/ownership-history", response_model=Page[OwnershipHistoryRead])
async def list_ownership_history(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[OwnershipHistoryRead]:
    asset = await _get_asset(session, asset_id, current_user, permission_key="assets.read")
    total = await session.scalar(
        select(func.count())
        .select_from(AssetOwnershipHistory)
        .where(AssetOwnershipHistory.asset_id == asset.id)
    )
    rows = list(
        (
            await session.execute(
                select(AssetOwnershipHistory)
                .where(AssetOwnershipHistory.asset_id == asset.id)
                .order_by(AssetOwnershipHistory.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[OwnershipHistoryRead](
        items=[OwnershipHistoryRead.model_validate(row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@tag_router.get("", response_model=Page[AssetTagRead])
async def list_tags(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetTagRead]:
    filters = [AssetTag.organization_id == current_user.organization_id]
    accessible = await site_scope.accessible_site_ids(
        session, current_user, permission_key="assets.read"
    )
    if accessible is not None:
        filters.append(
            AssetTag.id.in_(
                select(AssetTagAssignment.tag_id)
                .join(Asset, Asset.id == AssetTagAssignment.asset_id)
                .where(
                    Asset.organization_id == current_user.organization_id,
                    Asset.site_id.in_(accessible),
                )
            )
        )
    total = await session.scalar(select(func.count()).select_from(AssetTag).where(*filters))
    rows = list(
        (
            await session.execute(
                select(AssetTag)
                .where(*filters)
                .order_by(AssetTag.normalized_name)
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[AssetTagRead](
        items=[AssetTagRead.model_validate(row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@tag_router.post("", response_model=AssetTagRead, status_code=201)
async def create_tag(
    payload: AssetTagCreate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetTagRead:
    await _require_org_manage(session, manager)
    existing = await session.scalar(
        select(AssetTag).where(
            AssetTag.organization_id == manager.organization_id,
            AssetTag.normalized_name == asset_context.normalize_name(payload.name),
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="An asset tag with that name already exists")
    try:
        tag = await asset_context.ensure_tag(
            session,
            manager.organization_id,
            payload.name,
            description=payload.description,
            color=payload.color,
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="An asset tag with that name already exists"
        ) from exc
    _audit(
        session,
        action="asset_tag.created",
        actor=manager,
        context=context,
        target_type="asset_tag",
        target_id=tag.id,
        metadata={"name": tag.name},
    )
    return AssetTagRead.model_validate(tag)


@tag_router.patch("/{tag_id}", response_model=AssetTagRead)
async def update_tag(
    tag_id: uuid.UUID,
    payload: AssetTagUpdate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetTagRead:
    await _require_org_manage(session, manager)
    tag = await _get_tag(session, tag_id, manager.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        tag.name = asset_context.display_name(changes.pop("name"))
        tag.normalized_name = asset_context.normalize_name(tag.name)
    for field, value in changes.items():
        setattr(tag, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="An asset tag with that name already exists"
        ) from exc
    assets = list(
        (
            await session.execute(
                select(Asset)
                .join(AssetTagAssignment, AssetTagAssignment.asset_id == Asset.id)
                .where(AssetTagAssignment.tag_id == tag.id)
            )
        ).scalars()
    )
    for asset in assets:
        await asset_context.sync_legacy_tags(session, asset)
        await asset_context.refresh_dynamic_memberships_for_asset(session, asset)
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_tag.updated",
        actor=manager,
        context=context,
        target_type="asset_tag",
        target_id=tag.id,
        metadata={"changed_fields": sorted(payload.model_fields_set)},
    )
    return AssetTagRead.model_validate(tag)


@tag_router.delete("/{tag_id}", status_code=204, response_model=None)
async def delete_tag(
    tag_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    await _require_org_manage(session, manager)
    tag = await _get_tag(session, tag_id, manager.organization_id)
    assets = list(
        (
            await session.execute(
                select(Asset)
                .join(AssetTagAssignment, AssetTagAssignment.asset_id == Asset.id)
                .where(AssetTagAssignment.tag_id == tag.id)
            )
        ).scalars()
    )
    name = tag.name
    await session.delete(tag)
    await session.flush()
    for asset in assets:
        await asset_context.sync_legacy_tags(session, asset)
        await asset_context.refresh_dynamic_memberships_for_asset(session, asset)
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_tag.deleted",
        actor=manager,
        context=context,
        target_type="asset_tag",
        target_id=tag_id,
        metadata={"name": name, "affected_assets": len(assets)},
    )


@group_router.get("", response_model=Page[AssetGroupRead])
async def list_groups(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetGroupRead]:
    accessible = await site_scope.accessible_site_ids(
        session, current_user, permission_key="assets.read"
    )
    filters = [AssetGroup.organization_id == current_user.organization_id]
    if accessible is not None:
        filters.append(AssetGroup.site_id.in_(accessible))
    total = await session.scalar(select(func.count()).select_from(AssetGroup).where(*filters))
    rows = list(
        (
            await session.execute(
                select(AssetGroup)
                .where(*filters)
                .order_by(AssetGroup.priority.desc(), AssetGroup.name)
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[AssetGroupRead](
        items=[await _group_read(session, row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@group_router.post("/preview", response_model=GroupPreviewResponse)
async def preview_group(
    payload: GroupPreviewRequest,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> GroupPreviewResponse:
    if payload.site_id is not None:
        await site_scope.require_site_access(
            session,
            current_user,
            payload.site_id,
            not_found_detail="Site not found",
            permission_key="assets.read",
        )
    else:
        allowed = await authorization.has_permission(
            session,
            current_user,
            "assets.read",
            scope_type=GrantScopeType.ORGANIZATION,
            scope_id=current_user.organization_id,
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Select an accessible site")
    try:
        matches = await asset_context.preview_rule(
            session,
            current_user.organization_id,
            payload.rule_json,
            site_id=payload.site_id,
        )
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc
    return GroupPreviewResponse(
        matches=[
            GroupPreviewMatch(
                asset_id=asset.id,
                canonical_name=asset.canonical_name,
                explanation=why,
            )
            for asset, why in matches[: payload.limit]
        ],
        total=len(matches),
        truncated=len(matches) > payload.limit,
    )


@group_router.post("", response_model=AssetGroupRead, status_code=201)
async def create_group(
    payload: AssetGroupCreate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetGroupRead:
    if payload.site_id is None:
        await _require_org_manage(session, manager)
    else:
        await site_scope.require_site_access(
            session,
            manager,
            payload.site_id,
            not_found_detail="Site not found",
            permission_key="assets.manage",
        )
    try:
        if payload.rule_json is not None:
            asset_context.validate_rule(payload.rule_json)
        await asset_context.validate_owner(session, manager.organization_id, payload.owner_user_id)
        await asset_context.validate_group_tie(
            session,
            organization_id=manager.organization_id,
            priority=payload.priority,
            owner_user_id=payload.owner_user_id,
            enabled=payload.enabled,
            site_id=payload.site_id,
        )
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc
    group = AssetGroup(
        organization_id=manager.organization_id,
        created_by_user_id=manager.id,
        **payload.model_dump(),
    )
    session.add(group)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="An asset group with that name already exists"
        ) from exc
    if group.group_type == AssetGroupType.DYNAMIC:
        await asset_context.materialize_dynamic_group(session, group)
        member_ids = list(
            (
                await session.execute(
                    select(AssetGroupMembership.asset_id).where(
                        AssetGroupMembership.group_id == group.id
                    )
                )
            ).scalars()
        )
        for asset_id in member_ids:
            asset = await session.get(Asset, asset_id)
            if asset is not None:
                ownership = await asset_context.resolve_ownership(session, asset)
                await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.created",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={"name": group.name, "group_type": group.group_type.value},
    )
    return await _group_read(session, group)


@group_router.get("/{group_id}", response_model=AssetGroupRead)
async def get_group(
    group_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AssetGroupRead:
    group = await _get_group(session, group_id, current_user, permission_key="assets.read")
    return await _group_read(session, group)


@group_router.patch("/{group_id}", response_model=AssetGroupRead)
async def update_group(
    group_id: uuid.UUID,
    payload: AssetGroupUpdate,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetGroupRead:
    group = await _get_group(session, group_id, manager, permission_key="assets.manage")
    changes = payload.model_dump(exclude_unset=True)
    prior_member_ids = set(
        (
            await session.execute(
                select(AssetGroupMembership.asset_id).where(
                    AssetGroupMembership.group_id == group.id
                )
            )
        ).scalars()
    )
    target_site_id = changes.get("site_id", group.site_id)
    if target_site_id is None:
        await _require_org_manage(session, manager)
    else:
        await site_scope.require_site_access(
            session,
            manager,
            target_site_id,
            not_found_detail="Site not found",
            permission_key="assets.manage",
        )
    target_rule = changes.get("rule_json", group.rule_json)
    if group.group_type == AssetGroupType.DYNAMIC and target_rule is None:
        raise HTTPException(status_code=422, detail="Dynamic groups require rule_json")
    if group.group_type == AssetGroupType.STATIC and "rule_json" in changes:
        raise HTTPException(status_code=422, detail="Static groups cannot define rule_json")
    try:
        if target_rule is not None:
            asset_context.validate_rule(target_rule)
        await asset_context.validate_owner(
            session, manager.organization_id, changes.get("owner_user_id", group.owner_user_id)
        )
        await asset_context.validate_group_tie(
            session,
            organization_id=manager.organization_id,
            priority=changes.get("priority", group.priority),
            owner_user_id=changes.get("owner_user_id", group.owner_user_id),
            enabled=changes.get("enabled", group.enabled),
            site_id=target_site_id,
            exclude_group_id=group.id,
        )
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc
    for field, value in changes.items():
        setattr(group, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="An asset group with that name already exists"
        ) from exc
    reevaluate_fields = {"rule_json", "site_id", "enabled"}
    if group.group_type == AssetGroupType.DYNAMIC and reevaluate_fields & changes.keys():
        await asset_context.materialize_dynamic_group(session, group)
    member_ids = set(
        (
            await session.execute(
                select(AssetGroupMembership.asset_id).where(
                    AssetGroupMembership.group_id == group.id
                )
            )
        ).scalars()
    )
    for asset_id in prior_member_ids | member_ids:
        asset = await session.get(Asset, asset_id)
        if asset is not None:
            ownership = await asset_context.resolve_ownership(session, asset)
            await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.updated",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={"changed_fields": sorted(changes)},
    )
    return await _group_read(session, group)


@group_router.delete("/{group_id}", status_code=204, response_model=None)
async def delete_group(
    group_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    group = await _get_group(session, group_id, manager, permission_key="assets.manage")
    name = group.name
    member_ids = list(
        (
            await session.execute(
                select(AssetGroupMembership.asset_id).where(
                    AssetGroupMembership.group_id == group.id
                )
            )
        ).scalars()
    )
    scim_groups = list(
        (
            await session.execute(
                select(ScimGroup).where(ScimGroup.organization_id == manager.organization_id)
            )
        ).scalars()
    )
    updated_scim_group_ids: list[str] = []
    for scim_group in scim_groups:
        retained_targets = [
            target
            for target in scim_group.asset_group_targets_json or []
            if target.get("asset_group_id") != str(group.id)
        ]
        if retained_targets != (scim_group.asset_group_targets_json or []):
            scim_group.asset_group_targets_json = retained_targets
            updated_scim_group_ids.append(str(scim_group.id))
    await session.delete(group)
    await session.flush()
    for asset_id in member_ids:
        asset = await session.get(Asset, asset_id)
        if asset is not None:
            ownership = await asset_context.resolve_ownership(session, asset)
            await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.deleted",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={"name": name, "updated_scim_group_ids": updated_scim_group_ids},
    )


@group_router.post("/{group_id}/evaluate", response_model=AssetGroupRead)
async def evaluate_group(
    group_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetGroupRead:
    group = await _get_group(session, group_id, manager, permission_key="assets.manage")
    prior_member_ids = set(
        (
            await session.execute(
                select(AssetGroupMembership.asset_id).where(
                    AssetGroupMembership.group_id == group.id
                )
            )
        ).scalars()
    )
    try:
        added, removed = await asset_context.materialize_dynamic_group(session, group)
    except asset_context.AssetContextError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    current_member_ids = set(
        (
            await session.execute(
                select(AssetGroupMembership.asset_id).where(
                    AssetGroupMembership.group_id == group.id
                )
            )
        ).scalars()
    )
    for asset_id in prior_member_ids | current_member_ids:
        asset = await session.get(Asset, asset_id)
        if asset is not None:
            ownership = await asset_context.resolve_ownership(session, asset)
            await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.evaluated",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={"added": added, "removed": removed},
    )
    return await _group_read(session, group)


@group_router.get("/{group_id}/members", response_model=Page[AssetGroupMembershipRead])
async def list_group_members(
    group_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetGroupMembershipRead]:
    group = await _get_group(session, group_id, current_user, permission_key="assets.read")
    total = await session.scalar(
        select(func.count())
        .select_from(AssetGroupMembership)
        .where(AssetGroupMembership.group_id == group.id)
    )
    rows = list(
        (
            await session.execute(
                select(AssetGroupMembership)
                .where(AssetGroupMembership.group_id == group.id)
                .order_by(AssetGroupMembership.created_at)
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[AssetGroupMembershipRead](
        items=[AssetGroupMembershipRead.model_validate(row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@group_router.put("/{group_id}/members", response_model=AssetGroupRead)
async def add_group_members(
    group_id: uuid.UUID,
    payload: StaticMembershipChange,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetGroupRead:
    group = await _get_group(session, group_id, manager, permission_key="assets.manage")
    if group.group_type != AssetGroupType.STATIC:
        raise HTTPException(status_code=409, detail="Dynamic group membership is rule-derived")
    assets = [
        await _get_asset(session, asset_id, manager, permission_key="assets.manage")
        for asset_id in dict.fromkeys(payload.asset_ids)
    ]
    added = 0
    for asset in assets:
        if group.site_id is not None and asset.site_id != group.site_id:
            raise HTTPException(status_code=409, detail="Asset is outside the group's site")
        existing = await session.scalar(
            select(AssetGroupMembership.id).where(
                AssetGroupMembership.group_id == group.id,
                AssetGroupMembership.asset_id == asset.id,
            )
        )
        if existing is None:
            session.add(
                AssetGroupMembership(
                    organization_id=manager.organization_id,
                    group_id=group.id,
                    asset_id=asset.id,
                    source=AssetMembershipSource.STATIC,
                    explanation_json={"reason": "Explicit static membership"},
                )
            )
            added += 1
    await session.flush()
    for asset in assets:
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.members_added",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={"asset_ids": [str(asset.id) for asset in assets], "added": added},
    )
    return await _group_read(session, group)


@group_router.delete("/{group_id}/members", response_model=AssetGroupRead)
async def remove_group_members(
    group_id: uuid.UUID,
    payload: StaticMembershipChange,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetGroupRead:
    group = await _get_group(session, group_id, manager, permission_key="assets.manage")
    if group.group_type != AssetGroupType.STATIC:
        raise HTTPException(status_code=409, detail="Dynamic group membership is rule-derived")
    assets = [
        await _get_asset(session, asset_id, manager, permission_key="assets.manage")
        for asset_id in dict.fromkeys(payload.asset_ids)
    ]
    removal_count = await session.scalar(
        select(func.count())
        .select_from(AssetGroupMembership)
        .where(
            AssetGroupMembership.group_id == group.id,
            AssetGroupMembership.asset_id.in_([asset.id for asset in assets]),
            AssetGroupMembership.source == AssetMembershipSource.STATIC,
        )
    )
    await session.execute(
        delete(AssetGroupMembership).where(
            AssetGroupMembership.group_id == group.id,
            AssetGroupMembership.asset_id.in_([asset.id for asset in assets]),
            AssetGroupMembership.source == AssetMembershipSource.STATIC,
        )
    )
    await session.flush()
    for asset in assets:
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="asset_group.members_removed",
        actor=manager,
        context=context,
        target_type="asset_group",
        target_id=group.id,
        metadata={
            "asset_ids": [str(asset.id) for asset in assets],
            "removed": removal_count or 0,
        },
    )
    return await _group_read(session, group)


@department_router.get("", response_model=list[DepartmentOwnerRead])
async def list_department_owners(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[DepartmentOwnerRead]:
    rows = list(
        (
            await session.execute(
                select(DepartmentOwner)
                .where(DepartmentOwner.organization_id == current_user.organization_id)
                .order_by(DepartmentOwner.department_key)
            )
        ).scalars()
    )
    accessible = await site_scope.accessible_site_ids(
        session, current_user, permission_key="assets.read"
    )
    if accessible is not None:
        department_values = set(
            (
                await session.execute(
                    select(Asset.department).where(
                        Asset.organization_id == current_user.organization_id,
                        Asset.site_id.in_(accessible),
                        Asset.department.is_not(None),
                    )
                )
            ).scalars()
        )
        department_keys = {
            asset_context.normalize_name(value) for value in department_values if value is not None
        }
        rows = [row for row in rows if row.department_key in department_keys]
    return [DepartmentOwnerRead.model_validate(row) for row in rows]


@department_router.put("", response_model=DepartmentOwnerRead)
async def upsert_department_owner(
    payload: DepartmentOwnerUpsert,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> DepartmentOwnerRead:
    await _require_org_manage(session, manager)
    try:
        await asset_context.validate_owner(session, manager.organization_id, payload.owner_user_id)
    except asset_context.AssetContextError as exc:
        raise _bad_request(exc) from exc
    key = asset_context.normalize_name(payload.department)
    row = await session.scalar(
        select(DepartmentOwner).where(
            DepartmentOwner.organization_id == manager.organization_id,
            DepartmentOwner.department_key == key,
        )
    )
    if row is None:
        row = DepartmentOwner(
            organization_id=manager.organization_id,
            department=asset_context.display_name(payload.department),
            department_key=key,
            owner_user_id=payload.owner_user_id,
        )
        session.add(row)
    else:
        row.department = asset_context.display_name(payload.department)
        row.owner_user_id = payload.owner_user_id
    await session.flush()
    candidate_assets = list(
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == manager.organization_id,
                    Asset.department.is_not(None),
                )
            )
        ).scalars()
    )
    assets = [
        asset
        for asset in candidate_assets
        if asset.department is not None and asset_context.normalize_name(asset.department) == key
    ]
    for asset in assets:
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="department_owner.upserted",
        actor=manager,
        context=context,
        target_type="department_owner",
        target_id=row.id,
        metadata={"department": row.department, "owner_user_id": str(row.owner_user_id)},
    )
    return DepartmentOwnerRead.model_validate(row)


@department_router.delete("/{department_id}", status_code=204, response_model=None)
async def delete_department_owner(
    department_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("assets.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    await _require_org_manage(session, manager)
    row = await session.get(DepartmentOwner, department_id)
    if row is None or row.organization_id != manager.organization_id:
        raise HTTPException(status_code=404, detail="Department owner not found")
    department = row.department
    key = row.department_key
    await session.delete(row)
    await session.flush()
    candidate_assets = list(
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == manager.organization_id,
                    Asset.department.is_not(None),
                )
            )
        ).scalars()
    )
    assets = [
        asset
        for asset in candidate_assets
        if asset.department is not None and asset_context.normalize_name(asset.department) == key
    ]
    for asset in assets:
        ownership = await asset_context.resolve_ownership(session, asset)
        await asset_context.record_ownership_snapshot(session, ownership)
    _audit(
        session,
        action="department_owner.deleted",
        actor=manager,
        context=context,
        target_type="department_owner",
        target_id=department_id,
        metadata={"department": department},
    )
