"""Unified Maintenance Center endpoints (Phase 28).

One place to see whether updates, backups, feeds, certificates, and storage are
healthy, plus a fail-closed retention/cleanup workflow. Read views follow normal
authorization; cleanup deletes data and therefore requires an administrator, a
password re-check (recent reauthentication for a high-impact action), an explicit
confirmation, and is audited with the exact manifest of what was removed.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.auth.password import verify_password
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.report import Report
from app.models.retention_hold import HOLD_REPORT, HOLD_SCAN_JOB, RetentionHold
from app.models.scan_artifact import ScanArtifact
from app.models.user import User
from app.services import maintenance as maint
from app.services import retention
from app.services.audit import record_audit
from app.services.diagnostics import _ca_cert_result, _probe_cert_result  # cert status reuse
from app.services.diagnostics import as_dicts as diag_dicts

router = APIRouter(prefix="/maintenance", tags=["maintenance"])

_HOLD_TYPES = {HOLD_REPORT, HOLD_SCAN_JOB}


class RetentionRequest(BaseModel):
    raw_output_days: int | None = None
    report_days: int | None = None


class CleanupRequest(RetentionRequest):
    confirm: bool = False
    password: str = Field(default="", max_length=1024)


class HoldRequest(BaseModel):
    target_type: str
    target_id: uuid.UUID
    reason: str = Field(default="", max_length=512)


@router.get("", summary="Maintenance overview")
async def maintenance_overview(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    items = await maint.run_maintenance(session, settings, current_user.organization_id)
    return {
        "overall_state": maint.overall_state(items),
        "summary": maint.summarize(items),
        "items": maint.as_dicts(items),
    }


@router.get("/storage", summary="Storage budgets by category")
async def storage_budgets(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    categories = await retention.storage_breakdown(session, current_user.organization_id)
    disk = _disk_info(settings.reports_dir)
    return {"categories": categories, "disk": disk}


@router.get("/health-report", summary="Self-hosting health report summary")
async def health_report(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    return await maint.health_report(session, settings, current_user.organization_id)


@router.get("/certificate", summary="Certificate status and rotation preflight")
async def certificate_status(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Certificate expiry plus a rotation preflight and recovery guidance. Rotation
    itself is an operator action (re-enrollment / CLI), never an in-app key
    operation, so it stays atomic and recoverable."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    ca = _ca_cert_result(settings, now)
    scouts = await _probe_cert_result(session, current_user.organization_id, now)
    return {
        "certificates": diag_dicts([ca, scouts]),
        "preflight": [
            "Confirm a recent, verified, encrypted backup exists (CA key included).",
            "Confirm you can reach each Scout to re-enroll it after rotation.",
            "Keep the recovery sheet handy in case re-enrollment is needed.",
        ],
        "recovery": (
            "If a Scout cannot re-establish mutual TLS after rotation, run "
            "`vulnascout reset` on it and re-enroll with a fresh token. The internal "
            "CA and keys are backed up and restored with `vulna backup`."
        ),
        "doc": "docs/maintenance.md",
    }


@router.get("/retention/preview", summary="Preview a retention cleanup (admin)")
async def retention_preview(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    raw_output_days: int | None = None,
    report_days: int | None = None,
) -> dict[str, Any]:
    """Show exactly what a cleanup would delete (and what is protected and why)
    before any policy is applied. This manifest matches the deletion."""
    try:
        policy = retention.RetentionPolicy.from_request(raw_output_days, report_days)
    except retention.RetentionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    plan = await retention.build_cleanup_plan(session, admin.organization_id, policy)
    return plan.manifest()


@router.post("/retention/cleanup", summary="Run a safe retention cleanup (admin)")
async def retention_cleanup(
    payload: CleanupRequest,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Delete only the eligible (old, unreferenced, unheld) objects from the plan.
    Requires confirm=true and a password re-check; audited with the manifest."""
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cleanup requires confirm=true"
        )
    if not verify_password(payload.password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="password re-check failed; re-authenticate to run cleanup",
        )
    try:
        policy = retention.RetentionPolicy.from_request(
            payload.raw_output_days, payload.report_days
        )
    except retention.RetentionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    plan = await retention.build_cleanup_plan(session, admin.organization_id, policy)
    deleted = {"raw_output": 0, "report": 0}
    for item in plan.eligible:
        if item.kind == "raw_output":
            art = await session.get(ScanArtifact, uuid.UUID(item.id))
            if art is not None:
                await session.delete(art)
                deleted["raw_output"] += 1
        elif item.kind == "report":
            rep = await session.get(Report, uuid.UUID(item.id))
            if rep is not None:
                if rep.storage_path:
                    Path(rep.storage_path).unlink(missing_ok=True)
                await session.delete(rep)
                deleted["report"] += 1

    record_audit(
        session,
        action="maintenance.cleanup",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="retention",
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"deleted": deleted, "manifest": plan.manifest()},
    )
    await session.commit()
    return {"deleted": deleted, "reclaimed_bytes": plan.reclaimable_bytes}


@router.get("/holds", summary="List retention holds")
async def list_holds(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    rows = (
        await session.execute(
            select(RetentionHold).where(
                RetentionHold.organization_id == current_user.organization_id
            )
        )
    ).scalars().all()
    return {
        "holds": [
            {
                "id": str(h.id),
                "target_type": h.target_type,
                "target_id": str(h.target_id),
                "reason": h.reason,
                "created_at": h.created_at.isoformat(),
            }
            for h in rows
        ]
    }


@router.post("/holds", summary="Place a legal/retention hold (admin)", status_code=201)
async def place_hold(
    payload: HoldRequest,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    if payload.target_type not in _HOLD_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"target_type must be one of {sorted(_HOLD_TYPES)}",
        )
    existing = await session.scalar(
        select(RetentionHold).where(
            RetentionHold.organization_id == admin.organization_id,
            RetentionHold.target_type == payload.target_type,
            RetentionHold.target_id == payload.target_id,
        )
    )
    if existing is not None:
        return {"id": str(existing.id), "already": True}
    hold = RetentionHold(
        organization_id=admin.organization_id,
        target_type=payload.target_type,
        target_id=payload.target_id,
        reason=payload.reason,
        created_by=admin.id,
    )
    session.add(hold)
    record_audit(
        session,
        action="maintenance.hold_placed",
        actor=admin,
        organization_id=admin.organization_id,
        target_type=payload.target_type,
        target_id=payload.target_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.commit()
    return {"id": str(hold.id), "already": False}


@router.delete("/holds/{hold_id}", summary="Lift a hold (admin)")
async def lift_hold(
    hold_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    hold = await session.get(RetentionHold, hold_id)
    if hold is None or hold.organization_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="hold not found")
    await session.delete(hold)
    record_audit(
        session,
        action="maintenance.hold_lifted",
        actor=admin,
        organization_id=admin.organization_id,
        target_type=hold.target_type,
        target_id=hold.target_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.commit()
    return {"lifted": True}


def _disk_info(path: str) -> dict[str, Any]:
    probe = path if Path(path).exists() else "/"
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return {"free_pct": 100.0, "total_bytes": 0}
    free_pct = round(100.0 * usage.free / usage.total, 1) if usage.total else 100.0
    return {"free_pct": free_pct, "total_bytes": usage.total, "free_bytes": usage.free}
