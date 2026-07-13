"""Operator-facing scan-job endpoints: create, list, get, and cancel.

Job creation and cancellation require the Administrator or Security Operator
role. The probe-facing delivery (`/probes/{id}/jobs/next`) and status-report
endpoints live in ``app.api.v1.probes`` alongside the other probe endpoints.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentUser,
    require_permission,
    require_step_up_permission,
)
from app.auth.site_scope import accessible_site_ids, require_site_access, site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.asset import Asset
from app.models.enums import GrantScopeType, JobStatus, ProbeStatus, WebScanProfile
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.common import Page
from app.schemas.job import JobCreate, JobDiagnosticsRead, JobFailureLogEntry, JobRead
from app.services import authorization, reaper
from app.services.audit import record_audit
from app.services.demo import is_demo_mode
from app.services.jobs import JobValidationError, create_scan_job

router = APIRouter(
    prefix="/jobs",
    tags=["jobs"],
    dependencies=[Depends(require_permission("jobs.read"))],
)

_require_operator = require_permission("jobs.manage")
# Job creation also admits pentest approvers (for active web assessments); the
# handler enforces which profiles each role may request.
_require_job_creator = require_permission("jobs.create")

# Statuses at which a job is still active and can be cancelled.
_CANCELLABLE = {JobStatus.QUEUED, JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING}


async def _get_owned_job(
    session: AsyncSession,
    job_id: uuid.UUID,
    current_user: User,
    *,
    permission_key: str = "jobs.read",
) -> ScanJob:
    job = await session.scalar(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.organization_id == current_user.organization_id,
            site_scope_clause(current_user, ScanJob.site_id, permission_key=permission_key),
        )
    )
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.post(
    "",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create and sign a scan job",
)
async def create_job(
    payload: JobCreate,
    operator: Annotated[User, Depends(_require_job_creator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobRead:
    """Create a signed scan job for an enrolled probe.

    Regular scans and passive web assessments are for operators/administrators;
    an active web assessment is intrusive and requires approval — only an
    administrator or pentest approver may request the limited-active profile.
    """
    if payload.authenticated_protocols:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Use /api/v1/jobs/authenticated for credentialed inventory",
        )
    return await _create_job_impl(payload, operator, session, settings, context)


@router.post(
    "/authenticated",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Scout-encrypted authenticated inventory job",
)
async def create_authenticated_job(
    payload: JobCreate,
    operator: Annotated[User, Depends(_require_job_creator)],
    _credential_access: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("credentials.use"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobRead:
    if not payload.authenticated_protocols:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="authenticated_protocols is required",
        )
    return await _create_job_impl(payload, operator, session, settings, context)


async def _create_job_impl(
    payload: JobCreate,
    operator: User,
    session: AsyncSession,
    settings: Settings,
    context: RequestContext,
) -> JobRead:
    org = await session.get(Organization, operator.organization_id)
    if org is not None and is_demo_mode(org):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Demo mode is read-only and cannot run real scans. Disable demo mode "
                "in Settings to scan real targets."
            ),
        )

    probe = await session.get(Probe, payload.probe_id)
    if probe is None or probe.organization_id != operator.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")
    await require_site_access(
        session,
        operator,
        probe.site_id,
        not_found_detail="Probe not found",
        permission_key="jobs.create",
    )
    if probe.status != ProbeStatus.ENROLLED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Probe must be enrolled/approved to receive jobs (is '{probe.status.value}')",
        )
    if payload.authenticated_protocols:
        if payload.asset_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="asset_id is required for authenticated inventory",
            )
        asset = await session.scalar(
            select(Asset).where(
                Asset.id == payload.asset_id,
                Asset.organization_id == operator.organization_id,
            )
        )
        if asset is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        await require_site_access(
            session,
            operator,
            asset.site_id,
            not_found_detail="Asset not found",
            permission_key="credentials.use",
        )

    web_profile = payload.web_scan.profile if payload.web_scan else None
    web_start_urls = payload.web_scan.start_urls if payload.web_scan else None
    if web_profile == WebScanProfile.LIMITED_ACTIVE:
        if not await authorization.has_permission(
            session,
            operator,
            "pentest.approve",
            scope_type=GrantScopeType.SITE,
            scope_id=probe.site_id,
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "An active web assessment requires administrator or pentest-approver approval"
                ),
            )
    elif not await authorization.has_permission(
        session,
        operator,
        "jobs.manage",
        scope_type=GrantScopeType.SITE,
        scope_id=probe.site_id,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Creating scans requires the operator or administrator role",
        )

    try:
        job = await create_scan_job(
            session,
            probe,
            settings,
            targets=payload.targets,
            mode=payload.mode,
            created_by=authorization.user_actor_id(operator),
            not_before=payload.not_before,
            expires_at=payload.expires_at,
            web_profile=web_profile,
            web_start_urls=web_start_urls,
            network_id=payload.network_id,
            asset_id=payload.asset_id,
            authenticated_protocols=payload.authenticated_protocols,
            preset_key=payload.preset_key,
        )
    except JobValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    record_audit(
        session,
        action="job.created",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="scan_job",
        target_id=job.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "probe_id": str(probe.id),
            "mode": job.mode.value,
            "targets": job.requested_targets_json,
            "asset_id": str(job.asset_id) if job.asset_id else None,
            "credential_protocols": job.credential_protocols_json,
        },
    )
    return JobRead.model_validate(job)


@router.post("/reap", summary="Expire stale (timed-out) jobs")
async def reap_jobs(
    current_user: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, int]:
    """Expire active jobs past their deadline in the caller's organization and fail
    any workflow stage waiting on them. Also runs opportunistically on heartbeats."""
    reaped = await reaper.reap_stale_jobs(
        session,
        settings,
        organization_id=current_user.organization_id,
        site_ids=await accessible_site_ids(session, current_user, permission_key="jobs.manage"),
    )
    return {"reaped": reaped}


@router.get("", response_model=Page[JobRead], summary="List scan jobs")
async def list_jobs(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    probe_id: Annotated[uuid.UUID | None, Query()] = None,
    job_status: Annotated[JobStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[JobRead]:
    """List scan jobs in the caller's organization (any authenticated role)."""
    filters = [
        ScanJob.organization_id == current_user.organization_id,
        site_scope_clause(current_user, ScanJob.site_id, permission_key="jobs.read"),
    ]
    if probe_id is not None:
        filters.append(ScanJob.probe_id == probe_id)
    if job_status is not None:
        filters.append(ScanJob.status == job_status)
    total = await session.scalar(select(func.count()).select_from(ScanJob).where(*filters))
    result = await session.execute(
        select(ScanJob)
        .where(*filters)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    jobs = result.scalars().all()
    return Page[JobRead](
        items=[JobRead.model_validate(j) for j in jobs],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{job_id}", response_model=JobRead, summary="Get a scan job")
async def get_job(
    job_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JobRead:
    job = await _get_owned_job(session, job_id, current_user)
    return JobRead.model_validate(job)


@router.get(
    "/{job_id}/diagnostics",
    response_model=JobDiagnosticsRead,
    summary="Get sanitized scan failure diagnostics",
)
async def get_job_diagnostics(
    job_id: uuid.UUID,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobDiagnosticsRead:
    """Return the durable failure log to an operator with site-scoped job access."""
    job = await _get_owned_job(session, job_id, operator, permission_key="jobs.manage")
    failures = [JobFailureLogEntry.model_validate(item) for item in job.failure_log_json or []]
    record_audit(
        session,
        action="job.diagnostics_viewed",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="scan_job",
        target_id=job.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"diagnostic_entries": len(failures)},
    )
    return JobDiagnosticsRead(
        job_id=job.id,
        status=job.status,
        error_code=job.error_code,
        error_message=job.error_message,
        failures=failures,
    )


@router.post("/{job_id}/cancel", response_model=JobRead, summary="Cancel a scan job")
async def cancel_job(
    job_id: uuid.UUID,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobRead:
    """Request cancellation of a job (Operator/Administrator).

    A job that has not yet been delivered is cancelled immediately; an active
    job is flagged so the probe stops it and confirms via a status report.
    """
    job = await _get_owned_job(session, job_id, operator, permission_key="jobs.manage")
    if job.status not in _CANCELLABLE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Job in status '{job.status.value}' cannot be cancelled",
        )
    now = datetime.now(UTC)
    job.cancel_requested_at = now
    if job.status == JobStatus.QUEUED:
        # Not yet offered — cancel outright so it is never delivered.
        job.status = JobStatus.CANCELLED
        job.finished_at = now
    await session.flush()

    record_audit(
        session,
        action="job.cancel_requested",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="scan_job",
        target_id=job.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"previous_status": job.status.value},
    )
    return JobRead.model_validate(job)
