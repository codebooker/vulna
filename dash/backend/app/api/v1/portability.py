"""Data portability endpoints (Phase 31).

Export an organization's non-secret data as a versioned, checksummed bundle;
validate an untrusted bundle without applying it; and show the checklist for
moving Vulna to another host. The actual move is a backup/restore (which
preserves the CA and Scout identity), never a cross-organization data merge.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.db.session import get_session
from app.models.user import User
from app.services import export as export_svc
from app.services.audit import record_audit

router = APIRouter(
    prefix="/portability",
    tags=["portability"],
    dependencies=[Depends(require_permission("portability.read"))],
)


class ValidateRequest(BaseModel):
    bundle: dict[str, Any]


@router.get("/export", summary="Export organization data (admin)")
async def export_data(
    admin: Annotated[User, Depends(require_permission("portability.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    bundle = await export_svc.build_export(session, admin.organization_id)
    record_audit(
        session, action="portability.exported", actor=admin,
        organization_id=admin.organization_id, target_type="export",
        source_ip=context.source_ip, user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"schema_version": bundle["schema_version"], "checksum": bundle["checksum"]},
    )
    await session.commit()
    return bundle


@router.post("/validate", summary="Validate an export bundle without applying it (admin)")
async def validate(
    payload: ValidateRequest,
    admin: Annotated[User, Depends(require_permission("portability.manage"))],
) -> dict[str, Any]:
    """Independently validate a bundle: schema version, checksum, ownership, and
    conflicts. Never applies anything; refuses another organization's data."""
    return export_svc.validate_import(payload.bundle, expected_org_id=admin.organization_id)


@router.get("/migration-plan", summary="Move Vulna to another host: checklist")
async def migration_plan(current_user: CurrentUser) -> dict[str, Any]:
    return {
        "steps": [
            {"step": "backup", "action": "vulna backup create --encrypt",
             "detail": "Create a verified, encrypted backup including the CA and Scout state."},
            {"step": "verify", "action": "vulna backup verify <bundle>",
             "detail": "Confirm the backup is usable before moving."},
            {"step": "restore", "action": "vulna backup restore <bundle>",
             "detail": "Restore on the new host. The internal CA and Scout identity "
                       "are restored, so enrolled Scouts keep their mutual-TLS trust."},
            {"step": "url", "action": "Update the public URL / certificate",
             "detail": "Point the new host's URL and TLS certificate; see docs/networking.md."},
            {"step": "scouts", "action": "vulna doctor / vulnascout doctor",
             "detail": "Confirm each Scout re-connects. Re-enroll any that cannot."},
        ],
        "preserves_scout_trust": True,
        "doc": "docs/portability.md",
    }
