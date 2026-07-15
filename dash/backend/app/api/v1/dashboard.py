"""Home-dashboard and global-search endpoints (Phase 22)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.auth.site_scope import (
    accessible_site_ids,
    optional_site_scope_clause,
    site_scope_clause,
)
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.services.dashboard import build_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", summary="Home-dashboard summary")
async def summary(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return what needs attention, what changed, what wasn't assessed, health, and
    the next recommended action for the current organization."""
    return await build_summary(
        session,
        settings,
        current_user.organization_id,
        site_ids=await accessible_site_ids(
            session, current_user, permission_key="assets.read"
        ),
    )


search_router = APIRouter(prefix="/search", tags=["search"])


@search_router.get("", summary="Global search across the workspace")
async def global_search(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    q: Annotated[str, Query(min_length=1, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=25)] = 8,
) -> dict[str, list[dict[str, str]]]:
    """Search assets, findings, scans, sites, and reports by name/title. Results
    are always scoped to the caller's organization."""
    org = current_user.organization_id
    like = f"%{q.strip()}%"

    assets = (
        await session.execute(
            select(Asset)
            .where(
                Asset.organization_id == org,
                site_scope_clause(current_user, Asset.site_id, permission_key="assets.read"),
                Asset.canonical_name.ilike(like),
            )
            .limit(limit)
        )
    ).scalars().all()
    findings = (
        await session.execute(
            select(Finding)
            .where(
                Finding.organization_id == org,
                site_scope_clause(current_user, Finding.site_id, permission_key="findings.read"),
                Finding.title.ilike(like),
            )
            .limit(limit)
        )
    ).scalars().all()
    sites = (
        await session.execute(
            select(Site)
            .where(
                Site.organization_id == org,
                site_scope_clause(current_user, Site.id, permission_key="sites.read"),
                Site.name.ilike(like),
            )
            .limit(limit)
        )
    ).scalars().all()
    scans = (
        await session.execute(
            select(ScanJob)
            .where(
                ScanJob.organization_id == org,
                site_scope_clause(current_user, ScanJob.site_id, permission_key="jobs.read"),
                or_(
                    cast(ScanJob.id, String).ilike(like),
                    cast(ScanJob.mode, String).ilike(like),
                    cast(ScanJob.status, String).ilike(like),
                ),
            )
            .order_by(ScanJob.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    reports = (
        await session.execute(
            select(Report)
            .where(
                Report.organization_id == org,
                optional_site_scope_clause(
                    current_user, Report.site_id, permission_key="reports.read"
                ),
                or_(
                    cast(Report.id, String).ilike(like),
                    cast(Report.report_type, String).ilike(like),
                ),
            )
            .order_by(Report.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    return {
        "assets": [
            {"id": str(a.id), "label": a.canonical_name, "kind": "asset"} for a in assets
        ],
        "findings": [
            {"id": str(f.id), "label": f.title, "kind": "finding"} for f in findings
        ],
        "sites": [{"id": str(s.id), "label": s.name, "kind": "site"} for s in sites],
        "scans": [
            {"id": str(j.id), "label": f"{j.mode.value} · {j.status.value}", "kind": "scan"}
            for j in scans
        ],
        "reports": [
            {"id": str(r.id), "label": f"{r.report_type.value} report", "kind": "report"}
            for r in reports
        ],
    }
