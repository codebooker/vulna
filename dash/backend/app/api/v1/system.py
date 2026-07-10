"""System and health endpoints (Phase 0).

These endpoints are intentionally unauthenticated and expose only non-sensitive
information so that container orchestration and the frontend can verify liveness.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.schemas.system import SystemInfoResponse

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/health", summary="Structured health check")
def system_health(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    """Return a structured health payload for monitoring."""
    return {"status": "ok", "service": settings.app_name, "version": settings.version}


@router.get("/info", response_model=SystemInfoResponse, summary="Service information")
def system_info(settings: Settings = Depends(get_settings)) -> SystemInfoResponse:
    """Return non-sensitive information about the running service."""
    return SystemInfoResponse(
        service=settings.app_name,
        version=settings.version,
        environment=settings.env,
        api_version="v1",
    )
