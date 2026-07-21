"""VulnaRelay control-channel authentication via mutual-TLS fingerprint (Phase 16).

Mirrors probe authentication: the reverse proxy terminates mutual TLS, verifies
the relay's client certificate against the internal CA, and forwards its SHA-256
fingerprint in a trusted header — honored only from a trusted proxy peer so an
untrusted peer reaching the API directly cannot spoof a relay identity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import RelayStatus
from app.models.relay import Relay

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Relay client certificate required"
)


async def get_current_relay(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Relay:
    from app.services.networking import is_trusted_peer

    peer = request.client.host if request.client else None
    if not is_trusted_peer(peer, settings.trusted_proxy_networks):
        raise _UNAUTHENTICATED

    fingerprint = request.headers.get(settings.probe_cert_fingerprint_header)
    if not fingerprint:
        raise _UNAUTHENTICATED
    fingerprint = fingerprint.strip().lower()

    relay = (
        await session.execute(
            select(Relay).where(
                or_(
                    Relay.certificate_fingerprint == fingerprint,
                    and_(
                        Relay.previous_certificate_fingerprint == fingerprint,
                        Relay.previous_certificate_valid_until.is_not(None),
                        Relay.previous_certificate_valid_until > datetime.now(UTC),
                    ),
                )
            )
        )
    ).scalar_one_or_none()
    if relay is None:
        raise _UNAUTHENTICATED
    if relay.status == RelayStatus.REVOKED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Relay revoked")
    return relay


CurrentRelay = Annotated[Relay, Depends(get_current_relay)]
