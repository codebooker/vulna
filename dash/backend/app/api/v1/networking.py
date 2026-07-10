"""Networking / URL / TLS / reverse-proxy assistant endpoints (Phase 23).

Helps an operator reach VulnaDash securely from the intended network. Nothing here
disables certificate validation, and private key material is never accepted or
returned. Application-access TLS is kept clearly separate from VulnaScout mutual
TLS — changing the browser-facing certificate never affects Scout identity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.user import User
from app.services import networking as net
from app.services.health import component_health

router = APIRouter(prefix="/networking", tags=["networking"])


class ValidateRequest(BaseModel):
    mode: str = "public_dns"
    hostname: str = "localhost"
    scheme: str = "https"
    certificate_pem: str | None = None
    clock_skew_seconds: float | None = None


class UrlChangeRequest(BaseModel):
    new_url: str


def _no_keys(pem: str | None) -> None:
    if pem and "PRIVATE KEY" in pem:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Do not submit private keys. Provide the certificate only; "
                "keep the key on the proxy."
            ),
        )


@router.get("/status", summary="Current access configuration (no secrets)")
async def status_(
    current_user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    return {
        "public_base_url": settings.public_base_url,
        "cors_origins": settings.cors_origin_list,
        "trusted_proxies": settings.trusted_proxies,
        "access_modes": list(net.ACCESS_MODES),
        "note": "Application TLS is separate from VulnaScout mutual TLS; changing one "
        "does not affect the other.",
    }


@router.post("/validate", summary="Validate a proposed access configuration")
async def validate(
    payload: ValidateRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    if payload.mode not in net.ACCESS_MODES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"mode must be one of {list(net.ACCESS_MODES)}",
        )
    _no_keys(payload.certificate_pem)

    cert_info: dict[str, Any] | None = None
    if payload.certificate_pem:
        try:
            cert_info = net.inspect_certificate(payload.certificate_pem)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

    issues = net.detect_issues(
        mode=payload.mode,
        hostname=payload.hostname,
        scheme=payload.scheme,
        cert_info=cert_info,
        clock_skew_seconds=payload.clock_skew_seconds,
    )
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "certificate": cert_info,
        "settings": net.access_mode_settings(payload.mode, payload.hostname),
        "proxy_snippet": net.reverse_proxy_snippet(payload.hostname),
    }


@router.get("/test-browser", summary="Test what the server sees from this browser")
async def test_browser(
    request: Request,
    current_user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Report exactly what the server observed about this request so the operator
    can confirm the proxy is configured correctly (and cannot be spoofed)."""
    peer = request.client.host if request.client else None
    peer_trusted = net.is_trusted_peer(peer, settings.trusted_proxy_networks)
    xff = request.headers.get("x-forwarded-for")
    xfp = request.headers.get("x-forwarded-proto")
    fp_header = request.headers.get(settings.probe_cert_fingerprint_header)
    return {
        "reachable": True,
        "peer": peer,
        "peer_is_trusted_proxy": peer_trusted,
        "host_header": request.headers.get("host"),
        "forwarded_for": xff,
        "forwarded_proto": xfp,
        # The fingerprint header is honored only from a trusted peer; report whether
        # a value present here would be trusted (it must NOT be from the browser).
        "fingerprint_header_present": fp_header is not None,
        "fingerprint_header_would_be_trusted": peer_trusted and fp_header is not None,
        "note": "If a client-cert fingerprint header is present on the browser path, or a "
        "forwarded header from an untrusted peer, it is ignored — it cannot spoof identity.",
    }


@router.get("/test-scout", summary="Local Scout connectivity")
async def test_scout(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    health = await component_health(session, settings, datetime.now(UTC))
    return {
        "local_scout": health.local_scout,
        "note": "On a remote Scout, run `vulnascout doctor` for a full DNS/TLS/time/"
        "enrollment/heartbeat/upload connection test.",
    }


@router.get("/proxy-snippet", summary="Generate a reverse-proxy snippet")
async def proxy_snippet(
    current_user: CurrentUser,
    hostname: str = "vulna.example.com",
) -> dict[str, str]:
    if not net.valid_hostname(hostname):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid hostname"
        )
    return {"hostname": hostname, "nginx": net.reverse_proxy_snippet(hostname)}


@router.post("/url-change", summary="Plan a safe URL change (with rollback)")
async def url_change(
    payload: UrlChangeRequest,
    admin: Annotated[User, Depends(require_admin)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Validate a proposed new URL and return an *atomic change plan* with rollback.

    This does not mutate the running configuration (which comes from the
    environment) — it returns the exact values to set so the change is applied
    deliberately. The prior URL keeps working until you apply and restart, so
    rollback is simply not applying (or reverting) these values."""
    from urllib.parse import urlparse

    parsed = urlparse(payload.new_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="new_url must be an absolute http(s) URL with a hostname",
        )
    if not net.valid_hostname(parsed.hostname):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid hostname in URL"
        )

    new_origin = f"{parsed.scheme}://{parsed.netloc}"
    return {
        "apply": {
            "VULNA_PUBLIC_BASE_URL": new_origin,
            "VULNA_DOMAIN": parsed.hostname,
            "VULNA_CORS_ORIGINS": new_origin,
        },
        "rollback": {
            "VULNA_PUBLIC_BASE_URL": settings.public_base_url,
            "VULNA_CORS_ORIGINS": settings.cors_origins,
        },
        "scout_impact": "None to Scout identity: VulnaScout mutual-TLS certificates are issued by "
        "the internal CA and are unaffected by the browser-facing URL/cert. Update each Scout's "
        "server URL only if the hostname changed (`vulnascout enroll/run --server`).",
        "note": "The prior URL keeps working until you apply these values and restart the "
        "proxy/API, so the change is reversible.",
    }
