"""Low-resource operating profile and offline bundle endpoints (Phase 27).

`GET /resources` is display-only: it reports the operating profile and budgets
derived from the primary Scout's reported resources, the storage-pressure
admission status of the dashboard host, and the documented reference tiers.

The offline-bundle endpoints verify and import signed, **data-only** intelligence
or update bundles for air-gapped and low-bandwidth sites. Import requires an
administrator, is audited (which provides the import history), and fails closed on
a bad signature; it can never side-load an executable or plugin.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.audit import AuditEvent
from app.models.probe import Probe
from app.models.user import User
from app.services import resources as res
from app.services.audit import record_audit
from app.services.offline_bundle import BundleError, inspect, plan_import
from app.services.signing import get_signer, public_key_from_raw_b64

router = APIRouter(prefix="/resources", tags=["resources"])

_IMPORT_ACTION = "offline_bundle.imported"


class BundleRequest(BaseModel):
    manifest: dict[str, Any]


def _deployment_pubkey() -> Any:
    """The Ed25519 public key that offline bundles must be signed with.

    Bundles are signed by a key trusted by this deployment; by default that is the
    deployment's own signing key, so an internet-connected sibling can export
    intelligence this air-gapped instance will accept.
    """
    return public_key_from_raw_b64(get_signer().public_key_raw_b64)


@router.get("", summary="Operating profile, budgets, and admission (display only)")
async def resource_profile(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Show the Lite/Standard/Full plan for the primary Scout and the current
    storage-admission status. Read-only; the authoritative rate/concurrency clamps
    are still applied from signed local policy at run time."""
    probe = await session.scalar(
        select(Probe)
        .where(Probe.organization_id == current_user.organization_id)
        .order_by(desc(Probe.last_seen_at))
        .limit(1)
    )
    host = res.host_resources_from_health(probe.health_json if probe else None)
    plan = res.plan(host)

    # Storage admission uses the dashboard host's data volume.
    free_pct = _disk_free_pct(settings.reports_dir)
    pressure = res.SystemPressure(
        disk_free_pct=free_pct,
        queue_depth=0,
        queue_max=plan.queue_depth,
        ingestion_backlog=0,
    )
    admission = res.admit(pressure, heavy=True)

    return {
        "profile": plan.profile,
        "measured": asdict(host),
        "plan": {
            "max_concurrency": plan.max_concurrency,
            "queue_depth": plan.queue_depth,
            "one_heavy_stage_at_a_time": plan.one_heavy_stage_at_a_time,
            "disabled_components": [asdict(d) for d in plan.disabled],
            "stage_budgets": {k: asdict(v) for k, v in plan.stage_budgets.items()},
            "notes": plan.notes,
        },
        "admission": asdict(admission),
        "reference_tiers": _REFERENCE_TIERS,
    }


@router.post("/offline-bundle/inspect", summary="Inspect an offline bundle (admin)")
async def offline_bundle_inspect(
    payload: BundleRequest,
    admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Validate a bundle manifest and return its metadata without importing.

    Reports whether the signature is valid and whether the bundle is stale so the
    operator can decide before importing. Never applies any data."""
    try:
        info = inspect(payload.manifest, _deployment_pubkey())
    except BundleError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return asdict(info)


@router.post("/offline-bundle/import", summary="Import a signed offline bundle (admin)")
async def offline_bundle_import(
    payload: BundleRequest,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Verify and import a data-only offline bundle. Fails closed on a bad
    signature or a disallowed (non-data) kind; the import is audited, which is the
    source of the import history."""
    try:
        result = plan_import(payload.manifest, _deployment_pubkey())
    except BundleError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if not result.usable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "bundle cannot be imported", "blockers": result.blockers},
        )

    record_audit(
        session,
        action=_IMPORT_ACTION,
        actor=admin,
        organization_id=admin.organization_id,
        target_type="offline_bundle",
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "kind": result.info.kind,
            "created_at": result.info.created_at,
            "content_versions": result.info.content_versions,
            "item_count": result.info.item_count,
            "stale": result.info.stale,
        },
    )
    await session.commit()
    return {
        "imported": True,
        "info": asdict(result.info),
        "warnings": result.warnings,
    }


@router.get("/offline-bundle/history", summary="Offline bundle import history")
async def offline_bundle_history(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Return recent offline-bundle imports (from the audit log)."""
    rows = await session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == current_user.organization_id,
            AuditEvent.action == _IMPORT_ACTION,
        )
        .order_by(desc(AuditEvent.created_at))
        .limit(50)
    )
    history = [
        {"imported_at": e.created_at.isoformat(), **(e.metadata_json or {})}
        for e in rows
    ]
    return {"history": history}


def _disk_free_pct(path: str) -> float:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return 100.0
    if usage.total <= 0:
        return 100.0
    return round(100.0 * usage.free / usage.total, 1)


_REFERENCE_TIERS = [
    {
        "profile": res.LITE,
        "example": "Raspberry Pi 3B+/4 (1-2 GB), thin client",
        "memory": "up to 2 GB",
        "behavior": "one heavy stage at a time; expensive components off",
    },
    {
        "profile": res.STANDARD,
        "example": "Mini PC / NUC / small VM (2-6 GB)",
        "memory": "2-6 GB",
        "behavior": "moderate concurrency; all safe stages",
    },
    {
        "profile": res.FULL,
        "example": "Server or large VM (6 GB+)",
        "memory": "6 GB and up",
        "behavior": "full concurrency and components",
    },
]
