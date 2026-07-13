"""Bounded generic webhook/JSON API ticket adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from app.models.ticketing import TicketConnector
from app.services.ticket_adapters.http import JsonResponse, request_json
from app.services.ticketing import TicketingError, TicketResult

SendJson = Callable[..., Awaitable[JsonResponse]]
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_METHODS = {"POST", "PUT", "PATCH"}
_BLOCKED_HEADERS = {"host", "content-length", "connection", "transfer-encoding"}


class GenericTicketAdapter:
    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def _request(
        self,
        connector: TicketConnector,
        secret: str,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> JsonResponse:
        headers = _auth_headers(connector, secret)
        if idempotency_key:
            headers["Idempotency-Key"] = _operation_key(idempotency_key)
        return await self._sender(
            method,
            _endpoint(connector.base_url, path),
            headers=headers,
            json_body=body,
            timeout_seconds=connector.timeout_seconds,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        path = _path(connector.config_json.get("test_path", ""), allow_id=False)
        method = str(connector.config_json.get("test_method", "GET")).upper()
        if method not in {"GET", "POST"}:
            raise TicketingError("generic test_method must be GET or POST")
        response = await self._request(
            connector,
            secret,
            method,
            path,
            {"version": "1", "action": "test", "project": connector.project_key}
            if method == "POST"
            else None,
        )
        data = response.data if isinstance(response.data, dict) else {}
        return {
            "status_code": response.status_code,
            "service": str(data.get("service") or data.get("name") or "")[:255],
            "mode": str(connector.config_json.get("mode", "api"))[:32],
        }

    async def upsert(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str | None,
        idempotency_key: str,
    ) -> TicketResult:
        operation_key = _operation_key(idempotency_key)
        path = _path(connector.config_json.get("upsert_path", ""), allow_id=True)
        if "{id}" in path:
            path = path.replace("{id}", quote(external_id or operation_key, safe=""))
        method_name = "update_method" if external_id else "create_method"
        default_method = "PATCH" if external_id else "POST"
        method = _write_method(connector.config_json.get(method_name, default_method))
        response = await self._request(
            connector,
            secret,
            method,
            path,
            {
                "version": "1",
                "action": "upsert",
                "idempotency_key": operation_key,
                "project": connector.project_key,
                "external_id": external_id,
                "finding": payload,
            },
            idempotency_key=idempotency_key,
        )
        return _result(connector, response.data, fallback_id=external_id or operation_key)

    async def close(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str,
        idempotency_key: str,
    ) -> TicketResult:
        path_value = connector.config_json.get(
            "close_path", connector.config_json.get("upsert_path", "")
        )
        path = _path(path_value, allow_id=True).replace(
            "{id}", quote(external_id, safe="")
        )
        method = _write_method(connector.config_json.get("close_method", "POST"))
        operation_key = _operation_key(idempotency_key)
        response = await self._request(
            connector,
            secret,
            method,
            path,
            {
                "version": "1",
                "action": "close",
                "idempotency_key": operation_key,
                "project": connector.project_key,
                "external_id": external_id,
                "finding": payload,
            },
            idempotency_key=idempotency_key,
        )
        return _result(connector, response.data, fallback_id=external_id, state="closed")


def _auth_headers(connector: TicketConnector, secret: str) -> dict[str, str]:
    scheme = str(connector.config_json.get("auth_scheme", "bearer"))
    if scheme == "bearer":
        if not secret.strip():
            raise TicketingError("generic bearer token is required")
        return {"Authorization": f"Bearer {secret.strip()}"}
    if scheme == "header":
        name = str(connector.config_json.get("auth_header", "X-API-Key"))
        if not _HEADER_RE.fullmatch(name) or name.casefold() in _BLOCKED_HEADERS:
            raise TicketingError("generic auth_header is invalid or reserved")
        return {name: secret}
    if scheme == "basic":
        username, password = _basic_credentials(secret)
        value = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {value}"}
    raise TicketingError("generic auth_scheme must be bearer, header, or basic")


def _basic_credentials(secret: str) -> tuple[str, str]:
    try:
        parsed = json.loads(secret)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        username, password = parsed.get("username"), parsed.get("password")
    elif ":" in secret:
        username, password = secret.split(":", 1)
    else:
        username = password = None
    if (
        not isinstance(username, str)
        or not username
        or not isinstance(password, str)
        or not password
    ):
        raise TicketingError("generic basic secret requires username and password")
    return username, password


def _endpoint(base_url: str, path: str) -> str:
    parts = urlsplit(base_url)
    if not path:
        return base_url
    base_path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, f"{base_path}{path}", "", ""))


def _path(value: Any, *, allow_id: bool) -> str:
    if not isinstance(value, str):
        raise TicketingError("generic connector paths must be strings")
    path = value.strip()
    if not path:
        return ""
    parts = urlsplit(path)
    if (
        not path.startswith("/")
        or parts.scheme
        or parts.netloc
        or parts.query
        or parts.fragment
        or any(segment in {".", ".."} for segment in parts.path.split("/"))
        or ("{" in path or "}" in path) and (not allow_id or path.count("{id}") != 1)
    ):
        raise TicketingError("generic connector path must be a safe relative path")
    return path


def _write_method(value: Any) -> str:
    method = str(value).upper()
    if method not in _METHODS:
        raise TicketingError("generic write methods must be POST, PUT, or PATCH")
    return method


def _operation_key(value: str) -> str:
    return f"vulna-{hashlib.sha256(value.encode()).hexdigest()}"


def _response_field(connector: TicketConnector, name: str, default: str) -> str:
    field = str(connector.config_json.get(name, default))
    if not _FIELD_RE.fullmatch(field):
        raise TicketingError(f"generic {name} must be a single field name")
    return field


def _result(
    connector: TicketConnector,
    value: Any,
    *,
    fallback_id: str,
    state: str = "synchronized",
) -> TicketResult:
    data = value if isinstance(value, dict) else {}
    id_field = _response_field(connector, "response_id_field", "id")
    url_field = _response_field(connector, "response_url_field", "url")
    external_id = str(data.get(id_field) or fallback_id)[:512]
    raw_url = data.get(url_field)
    external_url = str(raw_url)[:2048] if isinstance(raw_url, str) else None
    return TicketResult(
        external_id=external_id,
        external_url=external_url,
        metadata={"state": state, "response_status": str(data.get("status") or "")[:64]},
    )
