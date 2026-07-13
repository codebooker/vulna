"""Bounded, DNS-pinned JSON transport shared by ticket adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from app.services import notifications

MAX_RESPONSE_BYTES = 1_048_576


class TicketHttpError(RuntimeError):
    """A safe provider transport error that never embeds response content."""


@dataclass(frozen=True)
class JsonResponse:
    status_code: int
    data: Any
    headers: dict[str, str]


async def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    timeout_seconds: int = 15,
    allow_private: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JsonResponse:
    """Send one HTTPS request after validation and connection-IP pinning."""

    try:
        host, ip = notifications.resolve_validated(url, allow_private=allow_private)
    except notifications.NotificationError as exc:
        raise TicketHttpError(str(exc).replace("Webhook", "Ticket connector")) from exc
    pinned_url = notifications.pin_url_to_ip(url, ip)
    request_headers = {
        **headers,
        "Host": host,
        "Accept": headers.get("Accept", "application/json"),
        "User-Agent": "Vulna-Ticket-Connector/1",
    }
    try:
        async with httpx.AsyncClient(
            timeout=float(timeout_seconds),
            follow_redirects=False,
            transport=transport,
        ) as client, client.stream(
            method,
            pinned_url,
            headers=request_headers,
            json=json_body,
            extensions={"sni_hostname": host},
        ) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise TicketHttpError("ticket provider response exceeded 1 MiB")
            if response.status_code < 200 or response.status_code >= 300:
                raise TicketHttpError(
                    f"ticket provider returned HTTP {response.status_code}"
                )
            try:
                data = json.loads(bytes(body)) if body else {}
            except (UnicodeDecodeError, ValueError) as exc:
                raise TicketHttpError("ticket provider returned invalid JSON") from exc
            return JsonResponse(
                status_code=response.status_code,
                data=data,
                headers={key.lower(): value for key, value in response.headers.items()},
            )
    except httpx.HTTPError as exc:
        raise TicketHttpError(f"ticket provider request failed: {type(exc).__name__}") from exc
