"""Credential vault, deterministic assignment, test, and usage APIs (Phase 42)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, StepUpIdentity, require_permission
from app.auth.site_scope import require_site_access, site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.asset import Asset, AssetIdentifier
from app.models.asset_context import AssetGroup, AssetTag
from app.models.credential import (
    CredentialAssignment,
    CredentialRecord,
    CredentialTest,
    CredentialUsageAudit,
)
from app.models.enums import (
    CredentialAssignmentTarget,
    CredentialTestStatus,
    CredentialUsageStatus,
    GrantScopeType,
    IdentifierType,
    JobMode,
    JobStatus,
    ProbeStatus,
)
from app.models.network import Network
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.models.user import User
from app.schemas.common import Page
from app.schemas.credential import (
    CredentialAssignmentCreate,
    CredentialAssignmentRead,
    CredentialCreate,
    CredentialRead,
    CredentialResolution,
    CredentialResolveRequest,
    CredentialRotate,
    CredentialTestRead,
    CredentialTestRequest,
    CredentialUpdate,
    CredentialUsageRead,
)
from app.services import authorization
from app.services import credentials as service
from app.services.audit import record_audit
from app.services.jobs import JobValidationError, create_scan_job
from app.services.presets import PresetError, get_preset

router = APIRouter(
    prefix="/credentials",
    tags=["credentials"],
    dependencies=[Depends(require_permission("credentials.read"))],
)


async def _owned_credential(
    session: AsyncSession, credential_id: uuid.UUID, user: User
) -> CredentialRecord:
    record = await session.scalar(
        select(CredentialRecord).where(
            CredentialRecord.id == credential_id,
            CredentialRecord.organization_id == user.organization_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    return record


async def _serialize_credential(session: AsyncSession, record: CredentialRecord) -> CredentialRead:
    version = await service.latest_secret_version(session, record.id)
    return CredentialRead(
        id=record.id,
        organization_id=record.organization_id,
        name=record.name,
        description=record.description,
        protocol=record.protocol,
        auth_type=record.auth_type,
        username=record.username,
        metadata=dict(record.metadata_json or {}),
        is_active=record.is_active,
        has_secret=version is not None,
        current_version=version.version if version else 0,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


async def _assignment_target(
    session: AsyncSession,
    user: User,
    target_type: CredentialAssignmentTarget,
    target_id: str,
) -> uuid.UUID | None:
    site_id: uuid.UUID | None = None
    if target_type == CredentialAssignmentTarget.PRESET:
        try:
            get_preset(target_id)
        except PresetError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        return None
    try:
        identifier = uuid.UUID(target_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{target_type.value} target_id must be a UUID",
        ) from exc

    if target_type == CredentialAssignmentTarget.ASSET:
        target = await session.scalar(
            select(Asset).where(
                Asset.id == identifier, Asset.organization_id == user.organization_id
            )
        )
        site_id = target.site_id if target else None
    elif target_type == CredentialAssignmentTarget.GROUP:
        target = await session.scalar(
            select(AssetGroup).where(
                AssetGroup.id == identifier,
                AssetGroup.organization_id == user.organization_id,
            )
        )
        site_id = target.site_id if target else None
    elif target_type == CredentialAssignmentTarget.TAG:
        target = await session.scalar(
            select(AssetTag).where(
                AssetTag.id == identifier, AssetTag.organization_id == user.organization_id
            )
        )
    elif target_type == CredentialAssignmentTarget.NETWORK:
        target = await session.scalar(
            select(Network).where(
                Network.id == identifier, Network.organization_id == user.organization_id
            )
        )
        site_id = target.site_id if target else None
    else:
        target = await session.scalar(
            select(Site).where(Site.id == identifier, Site.organization_id == user.organization_id)
        )
        site_id = target.id if target else None
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Assignment target not found"
        )
    if site_id is not None:
        await require_site_access(
            session,
            user,
            site_id,
            not_found_detail="Assignment target not found",
            permission_key="credentials.manage",
        )
    return site_id


@router.get("", response_model=Page[CredentialRead])
async def list_credentials(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CredentialRead]:
    filters = [CredentialRecord.organization_id == current_user.organization_id]
    total = await session.scalar(select(func.count()).select_from(CredentialRecord).where(*filters))
    rows = list(
        (
            await session.execute(
                select(CredentialRecord)
                .where(*filters)
                .order_by(CredentialRecord.name)
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[CredentialRead](
        items=[await _serialize_credential(session, row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
async def create_credential(
    payload: CredentialCreate,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> CredentialRead:
    if await session.scalar(
        select(CredentialRecord.id).where(
            CredentialRecord.organization_id == manager.organization_id,
            CredentialRecord.name == payload.name,
        )
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Credential name exists")
    try:
        metadata = service.validate_credential_material(
            payload.protocol, payload.auth_type, payload.secret, payload.metadata
        )
    except service.CredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    record = CredentialRecord(
        organization_id=manager.organization_id,
        name=payload.name,
        description=payload.description,
        protocol=payload.protocol,
        auth_type=payload.auth_type,
        username=payload.username,
        metadata_json=metadata,
        is_active=True,
        created_by_user_id=authorization.user_actor_id(manager),
    )
    session.add(record)
    await session.flush()
    await service.store_secret_version(
        session,
        record,
        payload.secret,
        master_secret=settings.require_secret_key(),
        created_by=authorization.user_actor_id(manager),
    )
    record_audit(
        session,
        action="credential.created",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential",
        target_id=record.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={"protocol": record.protocol.value, "auth_type": record.auth_type.value},
    )
    return await _serialize_credential(session, record)


@router.post("/resolve-preview", response_model=list[CredentialResolution])
async def preview_resolution(
    payload: CredentialResolveRequest,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[CredentialResolution]:
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == payload.asset_id,
            Asset.organization_id == current_user.organization_id,
            site_scope_clause(current_user, Asset.site_id, permission_key="credentials.read"),
        )
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    response: list[CredentialResolution] = []
    for protocol in dict.fromkeys(payload.protocols):
        resolved = await service.resolve_credential(
            session,
            asset,
            protocol,
            network_id=payload.network_id,
            preset_key=payload.preset_key,
        )
        if resolved.conflict:
            level = resolved.matched_level.value if resolved.matched_level else "unknown"
            message = f"Conflict at {level} level"
        elif resolved.record is None:
            message = "No credential assigned"
        else:
            level = resolved.matched_level.value if resolved.matched_level else "unknown"
            message = f"Resolved from {level} assignment"
        response.append(
            CredentialResolution(
                protocol=protocol,
                credential_id=resolved.record.id if resolved.record else None,
                credential_name=resolved.record.name if resolved.record else None,
                secret_version_id=resolved.version.id if resolved.version else None,
                matched_level=resolved.matched_level,
                conflict=resolved.conflict,
                candidates=list(resolved.candidates),
                message=message,
            )
        )
    return response


@router.get("/assignments", response_model=Page[CredentialAssignmentRead])
async def list_assignments(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CredentialAssignmentRead]:
    filters = [CredentialAssignment.organization_id == current_user.organization_id]
    total = await session.scalar(
        select(func.count()).select_from(CredentialAssignment).where(*filters)
    )
    rows = (
        await session.execute(
            select(CredentialAssignment, CredentialRecord)
            .join(CredentialRecord, CredentialRecord.id == CredentialAssignment.credential_id)
            .where(*filters)
            .order_by(CredentialAssignment.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return Page[CredentialAssignmentRead](
        items=[
            CredentialAssignmentRead(
                id=assignment.id,
                credential_id=record.id,
                protocol=record.protocol,
                credential_name=record.name,
                target_type=assignment.target_type,
                target_id=assignment.target_id,
                site_id=assignment.site_id,
                enabled=assignment.enabled,
                created_at=assignment.created_at,
            )
            for assignment, record in rows
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/usage", response_model=Page[CredentialUsageRead])
async def list_usage(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CredentialUsageRead]:
    filters = [CredentialUsageAudit.organization_id == current_user.organization_id]
    total = await session.scalar(
        select(func.count()).select_from(CredentialUsageAudit).where(*filters)
    )
    rows = list(
        (
            await session.execute(
                select(CredentialUsageAudit)
                .where(*filters)
                .order_by(CredentialUsageAudit.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[CredentialUsageRead](
        items=[
            CredentialUsageRead(
                id=row.id,
                credential_id=row.credential_id,
                secret_version_id=row.secret_version_id,
                asset_id=row.asset_id,
                probe_id=row.probe_id,
                scan_job_id=row.scan_job_id,
                protocol=row.protocol,
                status=row.status,
                detail=row.detail,
                created_at=row.created_at,
            )
            for row in rows
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/tests", response_model=Page[CredentialTestRead])
async def list_credential_tests(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    credential_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CredentialTestRead]:
    filters = [CredentialTest.organization_id == current_user.organization_id]
    if credential_id is not None:
        filters.append(CredentialTest.credential_id == credential_id)
    total = await session.scalar(select(func.count()).select_from(CredentialTest).where(*filters))
    rows = list(
        (
            await session.execute(
                select(CredentialTest)
                .where(*filters)
                .order_by(CredentialTest.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    return Page[CredentialTestRead](
        items=[
            CredentialTestRead(
                id=row.id,
                credential_id=row.credential_id,
                asset_id=row.asset_id,
                scan_job_id=row.scan_job_id,
                status=row.status,
                message=row.message,
                created_at=row.created_at,
                finished_at=row.finished_at,
            )
            for row in rows
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{credential_id}", response_model=CredentialRead)
async def get_credential(
    credential_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CredentialRead:
    return await _serialize_credential(
        session, await _owned_credential(session, credential_id, current_user)
    )


@router.patch("/{credential_id}", response_model=CredentialRead)
async def update_credential(
    credential_id: uuid.UUID,
    payload: CredentialUpdate,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> CredentialRead:
    record = await _owned_credential(session, credential_id, manager)
    updates = payload.model_dump(exclude_unset=True)
    for required_field in ("name", "username", "metadata", "is_active"):
        if required_field in updates and updates[required_field] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{required_field} cannot be null",
            )
    if "name" in updates and await session.scalar(
        select(CredentialRecord.id).where(
            CredentialRecord.organization_id == manager.organization_id,
            CredentialRecord.name == updates["name"],
            CredentialRecord.id != record.id,
        )
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Credential name exists")
    if "metadata" in updates:
        version = await service.latest_secret_version(session, record.id)
        if version is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Credential has no secret"
            )
        secret = service.decrypt_resolved_secret(
            service.ResolvedCredential(record.protocol, record, version, None),
            master_secret=settings.require_secret_key(),
        )
        try:
            record.metadata_json = service.validate_credential_material(
                record.protocol, record.auth_type, secret, updates.pop("metadata")
            )
        except service.CredentialError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
    for field in ("name", "description", "username", "is_active"):
        if field in updates:
            setattr(record, field, updates[field])
    cancelled_jobs = 0
    if updates.get("is_active") is False:
        now = datetime.now(UTC)
        active_jobs = list(
            (
                await session.execute(
                    select(ScanJob)
                    .join(CredentialUsageAudit, CredentialUsageAudit.scan_job_id == ScanJob.id)
                    .where(
                        CredentialUsageAudit.organization_id == manager.organization_id,
                        CredentialUsageAudit.credential_id == record.id,
                        ScanJob.status.in_(
                            [
                                JobStatus.QUEUED,
                                JobStatus.OFFERED,
                                JobStatus.ACCEPTED,
                                JobStatus.RUNNING,
                            ]
                        ),
                    )
                )
            ).scalars()
        )
        for job in {row.id: row for row in active_jobs}.values():
            job.cancel_requested_at = now
            if job.status == JobStatus.QUEUED:
                job.status = JobStatus.CANCELLED
                job.finished_at = now
            cancelled_jobs += 1
        usage_rows = list(
            (
                await session.execute(
                    select(CredentialUsageAudit).where(
                        CredentialUsageAudit.organization_id == manager.organization_id,
                        CredentialUsageAudit.credential_id == record.id,
                        CredentialUsageAudit.status == CredentialUsageStatus.ENCRYPTED_FOR_JOB,
                    )
                )
            ).scalars()
        )
        for usage in usage_rows:
            usage.status = CredentialUsageStatus.FAILED
            usage.detail = "credential_deactivated"
    record_audit(
        session,
        action="credential.updated",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential",
        target_id=record.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={
            "fields": sorted(payload.model_fields_set),
            "active_jobs_cancelled_or_signalled": cancelled_jobs,
        },
    )
    await session.flush()
    return await _serialize_credential(session, record)


@router.post("/{credential_id}/rotate", response_model=CredentialRead)
async def rotate_credential(
    credential_id: uuid.UUID,
    payload: CredentialRotate,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> CredentialRead:
    record = await _owned_credential(session, credential_id, manager)
    try:
        service.validate_credential_material(
            record.protocol, record.auth_type, payload.secret, record.metadata_json
        )
    except service.CredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    version = await service.store_secret_version(
        session,
        record,
        payload.secret,
        master_secret=settings.require_secret_key(),
        created_by=authorization.user_actor_id(manager),
    )
    record_audit(
        session,
        action="credential.rotated",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential",
        target_id=record.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={"version": version.version},
    )
    return await _serialize_credential(session, record)


@router.post(
    "/{credential_id}/assignments",
    response_model=CredentialAssignmentRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_assignment(
    credential_id: uuid.UUID,
    payload: CredentialAssignmentCreate,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> CredentialAssignmentRead:
    record = await _owned_credential(session, credential_id, manager)
    site_id = await _assignment_target(session, manager, payload.target_type, payload.target_id)
    if await session.scalar(
        select(CredentialAssignment.id).where(
            CredentialAssignment.credential_id == record.id,
            CredentialAssignment.target_type == payload.target_type,
            CredentialAssignment.target_id == payload.target_id,
        )
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Assignment exists")
    assignment = CredentialAssignment(
        organization_id=manager.organization_id,
        credential_id=record.id,
        target_type=payload.target_type,
        target_id=payload.target_id,
        site_id=site_id,
        enabled=True,
        assigned_by_user_id=authorization.user_actor_id(manager),
    )
    session.add(assignment)
    await session.flush()
    record_audit(
        session,
        action="credential.assignment_created",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential_assignment",
        target_id=assignment.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={"level": assignment.target_type.value, "target_id": assignment.target_id},
    )
    return CredentialAssignmentRead(
        id=assignment.id,
        credential_id=record.id,
        protocol=record.protocol,
        credential_name=record.name,
        target_type=assignment.target_type,
        target_id=assignment.target_id,
        site_id=assignment.site_id,
        enabled=assignment.enabled,
        created_at=assignment.created_at,
    )


@router.delete("/assignments/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assignment(
    assignment_id: uuid.UUID,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    assignment = await session.scalar(
        select(CredentialAssignment).where(
            CredentialAssignment.id == assignment_id,
            CredentialAssignment.organization_id == manager.organization_id,
        )
    )
    if assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignment not found")
    if assignment.site_id is not None:
        await require_site_access(
            session,
            manager,
            assignment.site_id,
            not_found_detail="Assignment not found",
            permission_key="credentials.manage",
        )
    await session.delete(assignment)
    record_audit(
        session,
        action="credential.assignment_deleted",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential_assignment",
        target_id=assignment.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
    )


@router.post("/{credential_id}/test", response_model=CredentialTestRead)
async def test_credential(
    credential_id: uuid.UUID,
    payload: CredentialTestRequest,
    manager: Annotated[User, Depends(require_permission("credentials.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> CredentialTestRead:
    record = await _owned_credential(session, credential_id, manager)
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == payload.asset_id,
            Asset.organization_id == manager.organization_id,
        )
    )
    probe = await session.scalar(
        select(Probe).where(
            Probe.id == payload.probe_id,
            Probe.organization_id == manager.organization_id,
        )
    )
    if asset is None or probe is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset or Scout not found"
        )
    await require_site_access(
        session,
        manager,
        asset.site_id,
        not_found_detail="Asset not found",
        permission_key="credentials.manage",
    )
    for permission_key in ("credentials.use", "jobs.create"):
        if not await authorization.has_permission(
            session,
            manager,
            permission_key,
            scope_type=GrantScopeType.SITE,
            scope_id=asset.site_id,
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to test credentials at this site",
            )
    if probe.status != ProbeStatus.ENROLLED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scout is not enrolled")
    resolved = await service.resolve_credential(
        session, asset, record.protocol, network_id=payload.network_id
    )
    if resolved.conflict or resolved.record is None or resolved.record.id != record.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This credential is not the unambiguous resolved credential for the asset",
        )
    target = await session.scalar(
        select(AssetIdentifier.identifier_value)
        .where(
            AssetIdentifier.asset_id == asset.id,
            AssetIdentifier.identifier_type == IdentifierType.IP_ADDRESS,
        )
        .order_by(AssetIdentifier.confidence.desc())
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset has no IP address")
    try:
        job = await create_scan_job(
            session,
            probe,
            settings,
            targets=[target],
            mode=JobMode.VULNERABILITY_ASSESSMENT,
            created_by=authorization.user_actor_id(manager),
            network_id=payload.network_id,
            asset_id=asset.id,
            authenticated_protocols=[record.protocol],
            include_default_workflow=False,
        )
    except JobValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if resolved.version is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Credential secret version is unavailable",
        )
    test = CredentialTest(
        organization_id=manager.organization_id,
        credential_id=record.id,
        secret_version_id=resolved.version.id,
        asset_id=asset.id,
        scan_job_id=job.id,
        status=CredentialTestStatus.PENDING,
        tested_by_user_id=authorization.user_actor_id(manager),
    )
    session.add(test)
    await session.flush()
    record_audit(
        session,
        action="credential.test_started",
        actor=manager,
        organization_id=manager.organization_id,
        target_type="credential_test",
        target_id=test.id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={"asset_id": str(asset.id), "job_id": str(job.id)},
    )
    return CredentialTestRead(
        id=test.id,
        credential_id=test.credential_id,
        asset_id=test.asset_id,
        scan_job_id=test.scan_job_id,
        status=test.status,
        message=test.message,
        created_at=test.created_at,
        finished_at=test.finished_at,
    )
