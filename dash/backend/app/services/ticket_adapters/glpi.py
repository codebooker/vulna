"""GLPI legacy REST API v1 ticket adapter."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote, urlsplit

from app.models.ticketing import TicketConnector
from app.services.ticket_adapters.http import JsonResponse, request_json
from app.services.ticketing import TicketingError, TicketResult

SendJson = Callable[..., Awaitable[JsonResponse]]


class GlpiTicketAdapter:
    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def _request(
        self,
        connector: TicketConnector,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
    ) -> JsonResponse:
        return await self._sender(
            method,
            f"{connector.base_url.rstrip('/')}{path}",
            headers=headers,
            json_body=body,
            timeout_seconds=connector.timeout_seconds,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )

    async def _start_session(
        self, connector: TicketConnector, secret: str
    ) -> tuple[str, dict[str, str]]:
        if not urlsplit(connector.base_url).path.rstrip("/").endswith("/apirest.php"):
            raise TicketingError("GLPI base_url must end with /apirest.php")
        user_token, app_token = _tokens(secret)
        headers = {"Authorization": f"user_token {user_token}"}
        if app_token:
            headers["App-Token"] = app_token
        response = await self._request(
            connector, "GET", "/initSession", headers=headers
        )
        data = _object(response.data)
        session_token = data.get("session_token")
        if not isinstance(session_token, str) or not session_token:
            raise TicketingError("GLPI did not return a session token")
        session_headers = {"Session-Token": session_token}
        if app_token:
            session_headers["App-Token"] = app_token
        return session_token, session_headers

    async def _kill_session(
        self, connector: TicketConnector, headers: dict[str, str]
    ) -> None:
        try:
            await self._request(connector, "GET", "/killSession", headers=headers)
        except Exception:  # noqa: BLE001 - primary operation outcome takes precedence
            return

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        _entity_id(connector.project_key)
        _session, headers = await self._start_session(connector, secret)
        try:
            response = await self._request(
                connector, "GET", "/getActiveProfile", headers=headers
            )
            data = _object(response.data)
            return {
                "profile_id": _bounded_int(data.get("id")),
                "profile_name": str(data.get("name") or "")[:255],
                "entity_id": _entity_id(connector.project_key),
                "api_version": "v1",
            }
        finally:
            await self._kill_session(connector, headers)

    async def upsert(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str | None,
        idempotency_key: str,
    ) -> TicketResult:
        entity_id = _entity_id(connector.project_key)
        _session, headers = await self._start_session(connector, secret)
        marker = _marker(idempotency_key)
        ticket_input: dict[str, Any] = {
            "name": f"[{marker}] {payload['title']}"[:255],
            "content": _content(payload, marker),
            "entities_id": entity_id,
            "urgency": _priority(payload.get("severity")),
            "priority": _priority(payload.get("priority")),
            "type": (
                connector.config_json["ticket_type"]
                if connector.config_json.get("ticket_type") in {1, 2}
                else 1
            ),
        }
        request_type = connector.config_json.get("request_type_id")
        if isinstance(request_type, int) and request_type > 0:
            ticket_input["requesttypes_id"] = request_type
        try:
            if external_id is not None:
                ticket_id = _ticket_id(external_id)
                await self._request(
                    connector,
                    "PUT",
                    f"/Ticket/{ticket_id}",
                    headers=headers,
                    body={"input": ticket_input},
                )
                return _result(connector, ticket_id, "updated")

            search = await self._request(
                connector,
                "GET",
                "/search/Ticket?criteria%5B0%5D%5Bfield%5D=1"
                "&criteria%5B0%5D%5Bsearchtype%5D=contains"
                f"&criteria%5B0%5D%5Bvalue%5D={quote(marker, safe='')}"
                "&forcedisplay%5B0%5D=2&range=0-49",
                headers=headers,
            )
            existing_id = _search_id(search.data, marker)
            if existing_id is not None:
                return _result(connector, existing_id, "existing")
            created = await self._request(
                connector,
                "POST",
                "/Ticket",
                headers=headers,
                body={"input": ticket_input},
            )
            data = _object(created.data)
            return _result(connector, _ticket_id(str(data.get("id"))), "created")
        finally:
            await self._kill_session(connector, headers)

    async def close(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str,
        idempotency_key: str,
    ) -> TicketResult:
        del payload, idempotency_key
        ticket_id = _ticket_id(external_id)
        close_status = connector.config_json.get("close_status", 6)
        if close_status not in {5, 6}:
            close_status = 6
        _session, headers = await self._start_session(connector, secret)
        try:
            await self._request(
                connector,
                "PUT",
                f"/Ticket/{ticket_id}",
                headers=headers,
                body={"input": {"status": close_status}},
            )
            return _result(connector, ticket_id, "closed")
        finally:
            await self._kill_session(connector, headers)


def _tokens(secret: str) -> tuple[str, str | None]:
    try:
        parsed = json.loads(secret)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        user_token = parsed.get("user_token")
        app_token = parsed.get("app_token")
        if not isinstance(user_token, str) or not user_token:
            raise TicketingError("GLPI secret JSON requires user_token")
        if app_token is not None and not isinstance(app_token, str):
            raise TicketingError("GLPI app_token must be a string")
        return user_token, app_token or None
    if not secret.strip():
        raise TicketingError("GLPI user token is required")
    return secret.strip(), None


def _marker(value: str) -> str:
    return f"VULNA-{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _entity_id(value: str) -> int:
    try:
        entity_id = int(value)
    except ValueError as exc:
        raise TicketingError("GLPI project_key must be a numeric entity id") from exc
    if entity_id < 0:
        raise TicketingError("GLPI entity id cannot be negative")
    return entity_id


def _ticket_id(value: str) -> int:
    try:
        ticket_id = int(value)
    except (TypeError, ValueError) as exc:
        raise TicketingError("GLPI ticket id must be numeric") from exc
    if ticket_id < 1:
        raise TicketingError("GLPI ticket id must be positive")
    return ticket_id


def _priority(value: Any) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(str(value), 1)


def _content(payload: dict[str, Any], marker: str) -> str:
    cves = ", ".join(str(item) for item in payload.get("cve_ids", [])) or "None"
    return "\n".join(
        [
            str(payload.get("summary") or "No summary provided.")[:4000],
            "",
            f"Vulna marker: {marker}",
            f"Severity: {payload.get('severity')}",
            f"Priority: {payload.get('priority')}",
            f"Status: {payload.get('status')}",
            f"CVEs: {cves}",
            f"Due: {payload.get('due_at') or 'Not set'}",
            "",
            str(payload.get("remediation") or "No remediation guidance provided.")[:4000],
        ]
    )[:12000]


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TicketingError("GLPI returned an invalid response")
    return value


def _bounded_int(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _search_id(value: Any, marker: str) -> int | None:
    data = value.get("data") if isinstance(value, dict) else None
    if not isinstance(data, list):
        return None
    for item in data:
        if not isinstance(item, dict) or marker not in str(item.get("1") or item.get("name") or ""):
            continue
        raw = item.get("2", item.get("id"))
        try:
            return _ticket_id(str(raw))
        except TicketingError:
            continue
    return None


def _result(connector: TicketConnector, ticket_id: int, state: str) -> TicketResult:
    base = connector.base_url.split("/apirest.php", 1)[0].rstrip("/")
    return TicketResult(
        external_id=str(ticket_id),
        external_url=f"{base}/front/ticket.form.php?id={ticket_id}",
        metadata={"id": ticket_id, "state": state, "api_version": "v1"},
    )
