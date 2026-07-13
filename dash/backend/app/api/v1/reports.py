"""Report generation, listing, and download endpoints.

Any authenticated user in the organization may generate and download reports for
their organization's scans; reports are strictly organization-scoped, so a user
from another organization (or an unauthenticated caller) cannot download them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser
from app.auth.site_scope import optional_site_scope_clause, require_site_access
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ReportFormat, ReportStatus
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.schemas.common import Page
from app.schemas.report import ReportCreate, ReportRead
from app.services.audit import record_audit
from app.services.reports import generate_reports

router = APIRouter(prefix="/reports", tags=["reports"])

_MEDIA_TYPES = {
    ReportFormat.PDF: "application/pdf",
    ReportFormat.CSV: "text/csv",
    ReportFormat.JSON: "application/json",
}


async def _get_owned_report(
    session: AsyncSession, report_id: uuid.UUID, current_user: CurrentUser
) -> Report:
    report = await session.scalar(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
            optional_site_scope_clause(current_user, Report.site_id),
        )
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.post(
    "",
    response_model=list[ReportRead],
    status_code=status.HTTP_201_CREATED,
    summary="Generate reports for a scan",
)
async def create_reports(
    payload: ReportCreate,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> list[ReportRead]:
    """Render the requested report artifacts from a completed scan's snapshot."""
    scan_job = await session.get(ScanJob, payload.scan_job_id)
    if scan_job is None or scan_job.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    await require_site_access(
        session, current_user, scan_job.site_id, not_found_detail="Scan job not found"
    )
    if not payload.report_types:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one report type is required",
        )

    reports = await generate_reports(
        session,
        scan_job=scan_job,
        report_types=payload.report_types,
        requested_by=current_user.id,
        settings=settings,
        now=datetime.now(UTC),
    )
    record_audit(
        session,
        action="report.generate",
        actor=current_user,
        organization_id=current_user.organization_id,
        target_type="scan_job",
        target_id=scan_job.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"report_types": [r.value for r in payload.report_types]},
    )
    return [ReportRead.model_validate(r) for r in reports]


@router.get("", response_model=Page[ReportRead], summary="List reports")
async def list_reports(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    scan_job_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ReportRead]:
    filters = [
        Report.organization_id == current_user.organization_id,
        optional_site_scope_clause(current_user, Report.site_id),
    ]
    if scan_job_id is not None:
        filters.append(Report.scan_job_id == scan_job_id)
    total = await session.scalar(select(func.count()).select_from(Report).where(*filters))
    result = await session.execute(
        select(Report).where(*filters).order_by(Report.created_at.desc()).limit(limit).offset(offset)
    )
    return Page[ReportRead](
        items=[ReportRead.model_validate(r) for r in result.scalars().all()],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{report_id}", response_model=ReportRead, summary="Get report metadata")
async def get_report(
    report_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ReportRead:
    report = await _get_owned_report(session, report_id, current_user)
    return ReportRead.model_validate(report)


@router.get("/{report_id}/download", summary="Download a report artifact")
async def download_report(
    report_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FileResponse:
    """Stream a report's stored file (organization-scoped authorization)."""
    report = await _get_owned_report(session, report_id, current_user)
    if report.status != ReportStatus.COMPLETED or not report.storage_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Report is not available for download"
        )
    # Honor the report's expiry: an expired artifact must not be downloadable,
    # even if retention cleanup has not yet removed the file. Treat a stored
    # naive timestamp (some backends drop tzinfo) as UTC.
    if report.expires_at is not None:
        expires_at = report.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_410_GONE, detail="Report has expired"
            )
    path = Path(report.storage_path)
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE, detail="Report artifact is no longer stored"
        )
    filename = f"{report.report_type.value}.{report.format.value}"
    return FileResponse(
        path,
        media_type=_MEDIA_TYPES.get(report.format, "application/octet-stream"),
        filename=filename,
    )
