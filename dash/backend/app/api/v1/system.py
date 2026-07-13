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

from app.auth.dependencies import require_permission
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.user import User
from app.schemas.system import SystemInfoResponse
from app.services.experience import CAPABILITIES
from app.services.health import component_health

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/capabilities", summary="Public capability status matrix")
def capability_status() -> dict[str, object]:
    """Return non-sensitive implementation status without making readiness claims."""
    return {
        "production_ready": False,
        "capabilities": [dict(capability) for capability in CAPABILITIES],
        "note": "Production-ready remains false until final release qualification passes.",
    }


@router.get("/health", summary="Structured health check")
def system_health(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    """Return a structured health payload for monitoring."""
    return {"status": "ok", "service": settings.app_name, "version": settings.version}


@router.get("/component-health", summary="Per-component health")
async def system_component_health(
    current_user: Annotated[User, Depends(require_permission("system.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Distinguish application, database, local-Scout, scanner-capability, and
    intelligence-feed health (Phase 17)."""
    health = await component_health(session, settings, datetime.now(UTC))
    return asdict(health)


@router.get("/backups", summary="Backup center (display only)")
def backup_center(
    current_user: Annotated[User, Depends(require_permission("system.read"))],
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """Show backup policy and the CLI commands. Backups are created, verified, and
    restored by the operator with the `vulna backup` CLI — the web UI never handles
    the recovery passphrase or key material."""
    return {
        "default_destination": "local filesystem",
        "destinations": ["local", "s3-compatible"],
        "retention_days": settings.backup_retention_days,
        "contents": [
            "database",
            "config",
            "ca",
            "scout_state",
            "reports",
            "evidence",
            "branding",
            "presets",
        ],
        "encryption": (
            "AES-256-GCM with a user-controlled recovery passphrase; required for backups "
            "containing credentials, CA material, evidence, or application secrets"
        ),
        "how_to_create": "vulna backup create --archive <tar.gz> --encrypt",
        "how_to_verify": "vulna backup verify <bundle>",
        "how_to_restore": "vulna backup restore <bundle>",
        "warning": (
            "Keep a recent, VERIFIED, encrypted backup off-host. If you lose the recovery "
            "passphrase, or the CA key and it was not backed up, that data cannot be recovered."
        ),
    }


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
    current_user: Annotated[User, Depends(require_permission("system.read"))],
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
