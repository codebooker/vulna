"""Vulna Doctor: diagnostics, support bundle, timeline, and safe repairs (Phase 26).

All endpoints follow normal authorization; the support bundle and repair actions
require an administrator and are audited. Repairs are a narrow, allowlisted set of
reversible actions over derived state — they never alter scopes, permissions,
users, credentials, or retention, and never weaken a security setting.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, StepUpIdentity, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.user import User
from app.services.audit import record_audit
from app.services.diagnostics import as_dicts, run_diagnostics, summarize
from app.services.support_bundle import build_support_bundle, build_timeline

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])

# Allowlisted, safe, reversible repair actions.
_REPAIRS = {"recreate_storage_dirs"}


class RepairRequest(BaseModel):
    action: str
    confirm: bool = False


@router.get("", summary="Run all diagnostics (Vulna Doctor)")
async def diagnostics(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    results = await run_diagnostics(session, settings, current_user.organization_id)
    return {"summary": summarize(results), "checks": as_dicts(results)}


@router.get("/timeline", summary="Local event timeline")
async def timeline(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    return {"events": await build_timeline(session, current_user.organization_id)}


@router.get("/support-bundle", summary="Redacted support bundle (preview, admin)")
async def support_bundle(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Return a redacted support bundle for review before export. Built from an
    allowlist (no secrets), with a secret-scanner result as a second check."""
    result = await build_support_bundle(session, settings, admin.organization_id)
    record_audit(
        session,
        action="diagnostics.support_bundle_generated",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="support_bundle",
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"secret_scan_clean": result["secret_scan"]["clean"]},
    )
    await session.commit()
    return result


@router.post("/repair", summary="Run a safe, confirmed repair action (admin)")
async def repair(
    payload: RepairRequest,
    admin: Annotated[User, Depends(require_admin)],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    if payload.action not in _REPAIRS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unknown or disallowed repair; allowed: {sorted(_REPAIRS)}",
        )
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this repair requires confirm=true",
        )

    detail: dict[str, Any] = {}
    if payload.action == "recreate_storage_dirs":
        created = []
        for path in _storage_paths(settings):
            if not Path(path).exists():
                os.makedirs(path, mode=0o700, exist_ok=True)
                created.append(path)
        detail = {"created": created}

    record_audit(
        session,
        action="diagnostics.repair",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="repair",
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"repair": payload.action, **detail},
    )
    await session.commit()
    return {"action": payload.action, "result": detail}


def _storage_paths(settings: Settings) -> list[str]:
    reports = settings.reports_dir
    evidence = str(Path(reports).parent / "evidence")
    return [reports, evidence]
