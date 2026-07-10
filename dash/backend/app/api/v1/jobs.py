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
from app.auth.dependencies import CurrentUser, require_roles
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import JobStatus, ProbeStatus, UserRole
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.common import Page
from app.schemas.job import JobCreate, JobRead
from app.services.audit import record_audit
from app.services.jobs import JobValidationError, create_scan_job

router = APIRouter(prefix="/jobs", tags=["jobs"])

_require_operator = require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)

# Statuses at which a job is still active and can be cancelled.
_CANCELLABLE = {JobStatus.QUEUED, JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING}


async def _get_owned_job(session: AsyncSession, job_id: uuid.UUID, org_id: uuid.UUID) -> ScanJob:
    job = await session.get(ScanJob, job_id)
    if job is None or job.organization_id != org_id:
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
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobRead:
    """Create a signed scan job for an enrolled probe (Operator/Administrator)."""
    probe = await session.get(Probe, payload.probe_id)
    if probe is None or probe.organization_id != operator.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")
    if probe.status != ProbeStatus.ENROLLED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Probe must be enrolled/approved to receive jobs (is '{probe.status.value}')",
        )

    try:
        job = await create_scan_job(
            session,
            probe,
            settings,
            targets=payload.targets,
            mode=payload.mode,
            created_by=operator.id,
            not_before=payload.not_before,
            expires_at=payload.expires_at,
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
        },
    )
    return JobRead.model_validate(job)


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
    filters = [ScanJob.organization_id == current_user.organization_id]
    if probe_id is not None:
        filters.append(ScanJob.probe_id == probe_id)
    if job_status is not None:
        filters.append(ScanJob.status == job_status)
    total = await session.scalar(select(func.count()).select_from(ScanJob).where(*filters))
    result = await session.execute(
        select(ScanJob).where(*filters).order_by(ScanJob.created_at.desc()).limit(limit).offset(offset)
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
    job = await _get_owned_job(session, job_id, current_user.organization_id)
    return JobRead.model_validate(job)


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
    job = await _get_owned_job(session, job_id, operator.organization_id)
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
