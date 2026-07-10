"""System and health endpoints (Phase 0).

These endpoints are intentionally unauthenticated and expose only non-sensitive
information so that container orchestration and the frontend can verify liveness.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.schemas.system import SystemInfoResponse
from app.services.health import component_health

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/health", summary="Structured health check")
def system_health(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    """Return a structured health payload for monitoring."""
    return {"status": "ok", "service": settings.app_name, "version": settings.version}


@router.get("/component-health", summary="Per-component health")
async def system_component_health(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Distinguish application, database, local-Scout, scanner-capability, and
    intelligence-feed health (Phase 17)."""
    health = await component_health(session, settings, datetime.now(UTC))
    return asdict(health)


@router.get("/info", response_model=SystemInfoResponse, summary="Service information")
def system_info(settings: Settings = Depends(get_settings)) -> SystemInfoResponse:
    """Return non-sensitive information about the running service."""
    return SystemInfoResponse(
        service=settings.app_name,
        version=settings.version,
        environment=settings.env,
        api_version="v1",
    )


@router.get("/update", summary="Update center (display only)")
def update_center(
    current_user: CurrentUser,
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """Show the current version and update channel. The web UI is display-only —
    the running app never fetches or applies releases (that would make it a
    package-execution channel). Updates are checked and applied by the operator
    with the signature-verifying `vulna` CLI, which keeps application, Scout,
    scanner-binary, scanner-template, and intelligence-feed updates separate."""
    return {
        "current_version": settings.version,
        "channel": settings.update_channel,
        "channels": ["stable", "candidate", "development"],
        "update_types": [
            "Vulna application",
            "VulnaScout",
            "scanner binaries",
            "scanner templates",
            "intelligence feeds",
        ],
        "how_to_check": "vulna update check --channel " + settings.update_channel,
        "how_to_apply": (
            "vulna update   (takes an automatic pre-update backup; roll back with `vulna rollback`)"
        ),
        "note": "Automatic installation is opt-in; there is no forced remote update path.",
    }
