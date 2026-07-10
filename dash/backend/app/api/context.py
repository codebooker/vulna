"""Request-context helper used to enrich audit events."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.core.config import get_settings
from app.services.networking import client_ip_from_request


@dataclass(frozen=True)
class RequestContext:
    """Non-sensitive request metadata recorded on audit events."""

    source_ip: str | None
    user_agent: str | None
    request_id: str | None


def get_request_context(request: Request) -> RequestContext:
    """Extract client IP, user agent, and request id from the request.

    The real client IP is taken from ``X-Forwarded-For`` only when the immediate
    peer is a trusted proxy; otherwise the peer address is used, so an untrusted
    peer cannot spoof the recorded source address.
    """
    peer = request.client.host if request.client else None
    forwarded_for = request.headers.get("x-forwarded-for")
    source_ip = client_ip_from_request(peer, forwarded_for, get_settings().trusted_proxy_networks)

    request_id = request.headers.get("x-request-id")
    user_agent = request.headers.get("user-agent")
    return RequestContext(
        source_ip=source_ip,
        user_agent=user_agent[:512] if user_agent else None,
        request_id=request_id[:64] if request_id else None,
    )
