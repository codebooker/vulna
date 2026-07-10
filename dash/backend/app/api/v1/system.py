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
