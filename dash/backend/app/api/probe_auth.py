"""Probe authentication via mutual-TLS client-certificate fingerprint.

The reverse proxy (Caddy) terminates mutual TLS, verifies the probe's client
certificate against the internal CA, and forwards its SHA-256 fingerprint in a
trusted header. The API authenticates the probe by matching that fingerprint to
a ``Probe`` row.

Trust boundary: the API is never exposed directly to probes — only the proxy can
reach it — so the fingerprint header can only originate from the proxy after a
successful mTLS handshake. Deployments MUST NOT publish the API port directly.
See docs/threat-model.md.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ProbeStatus
from app.models.probe import Probe

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Probe client certificate required",
)


async def get_current_probe(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Probe:
    """Resolve the authenticated probe from the verified client-cert fingerprint.

    Raises 401 if no/unknown certificate is presented and 403 if the probe has
    been revoked or disabled.
    """
    fingerprint = request.headers.get(settings.probe_cert_fingerprint_header)
    if not fingerprint:
        raise _UNAUTHENTICATED
    fingerprint = fingerprint.strip().lower()

    result = await session.execute(
        select(Probe).where(Probe.certificate_fingerprint == fingerprint)
    )
    probe = result.scalar_one_or_none()
    if probe is None:
        raise _UNAUTHENTICATED

    if probe.status in (ProbeStatus.REVOKED, ProbeStatus.DISABLED):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Probe is {probe.status.value}",
        )
    return probe


CurrentProbe = Annotated[Probe, Depends(get_current_probe)]
