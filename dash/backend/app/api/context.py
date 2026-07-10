"""Request-context helper used to enrich audit events."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request


@dataclass(frozen=True)
class RequestContext:
    """Non-sensitive request metadata recorded on audit events."""

    source_ip: str | None
    user_agent: str | None
    request_id: str | None


def get_request_context(request: Request) -> RequestContext:
    """Extract client IP, user agent, and request id from the request."""
    client_host = request.client.host if request.client else None
    request_id = request.headers.get("x-request-id")
    user_agent = request.headers.get("user-agent")
    return RequestContext(
        source_ip=client_host,
        user_agent=user_agent[:512] if user_agent else None,
        request_id=request_id[:64] if request_id else None,
    )
