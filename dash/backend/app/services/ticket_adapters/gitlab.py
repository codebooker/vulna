"""GitLab.com and self-managed GitLab Issues adapter."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

from app.models.ticketing import TicketConnector
from app.services.ticket_adapters.http import JsonResponse, request_json
from app.services.ticketing import TicketingError, TicketResult

SendJson = Callable[..., Awaitable[JsonResponse]]
_PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")


class GitLabIssuesAdapter:
    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    @staticmethod
    def _project(connector: TicketConnector) -> tuple[str, str]:
        project = connector.project_key.strip().strip("/")
        if len(project) > 512 or not _PROJECT_RE.fullmatch(project):
            raise TicketingError("GitLab project_key must be a namespace/project path")
        return project, quote(project, safe="")

    @staticmethod
    def _headers(connector: TicketConnector, secret: str) -> dict[str, str]:
        if connector.config_json.get("auth_scheme") == "bearer":
            return {"Authorization": f"Bearer {secret}"}
        return {"PRIVATE-TOKEN": secret}

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
        headers = self._headers(connector, secret)
        if idempotency_key:
            headers["Idempotency-Key"] = _operation_key(idempotency_key)
        return await self._sender(
            method,
            f"{connector.base_url.rstrip('/')}{path}",
            headers=headers,
            json_body=body,
            timeout_seconds=connector.timeout_seconds,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        project, encoded = self._project(connector)
        response = await self._request(connector, secret, "GET", f"/projects/{encoded}")
        data = _object(response.data)
        return {
            "project": str(data.get("path_with_namespace") or project)[:512],
            "visibility": str(data.get("visibility") or "")[:32],
            "issues_enabled": bool(data.get("issues_enabled", True)),
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
        _project, encoded = self._project(connector)
        request: dict[str, Any] = {
            "title": str(payload["title"])[:255],
            "description": _description(payload, idempotency_key),
        }
        labels = connector.config_json.get("labels")
        if isinstance(labels, list):
            request["labels"] = ",".join(str(label) for label in labels[:20])
        assignee_ids = connector.config_json.get("assignee_ids")
        if isinstance(assignee_ids, list):
            request["assignee_ids"] = [
                int(value) for value in assignee_ids[:10] if str(value).isdigit()
            ]
        milestone_id = connector.config_json.get("milestone_id")
        if isinstance(milestone_id, int) and milestone_id > 0:
            request["milestone_id"] = milestone_id

        if external_id is not None:
            response = await self._request(
                connector,
                secret,
                "PUT",
                f"/projects/{encoded}/issues/{_issue_iid(external_id)}",
                request,
                idempotency_key=idempotency_key,
            )
        else:
            marker = _operation_key(idempotency_key)
            search_value = quote(marker, safe="")
            search = await self._request(
                connector,
                secret,
                "GET",
                f"/projects/{encoded}/issues?scope=all&state=all&search={search_value}"
                "&in=description&per_page=100",
            )
            if isinstance(search.data, list):
                for item in search.data:
                    if isinstance(item, dict) and marker in str(item.get("description") or ""):
                        return _result(item)
            response = await self._request(
                connector,
                secret,
                "POST",
                f"/projects/{encoded}/issues",
                request,
                idempotency_key=idempotency_key,
            )
        return _result(response.data)

    async def close(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str,
        idempotency_key: str,
    ) -> TicketResult:
        del payload
        _project, encoded = self._project(connector)
        response = await self._request(
            connector,
            secret,
            "PUT",
            f"/projects/{encoded}/issues/{_issue_iid(external_id)}",
            {"state_event": "close"},
            idempotency_key=idempotency_key,
        )
        return _result(response.data)


def _operation_key(value: str) -> str:
    return f"vulna-{hashlib.sha256(value.encode()).hexdigest()}"


def _description(payload: dict[str, Any], idempotency_key: str) -> str:
    cves = ", ".join(str(item) for item in payload.get("cve_ids", [])) or "None"
    marker = _operation_key(idempotency_key)
    return "\n".join(
        [
            str(payload.get("summary") or "No summary provided.")[:4000],
            "",
            "## Vulna remediation context",
            f"- Severity: {payload.get('severity')}",
            f"- Priority: {payload.get('priority')}",
            f"- Status: {payload.get('status')}",
            f"- CVEs: {cves}",
            f"- Due: {payload.get('due_at') or 'Not set'}",
            "",
            "## Recommended remediation",
            str(payload.get("remediation") or "No remediation guidance provided.")[:4000],
            "",
            f"<!-- {marker} -->",
        ]
    )[:12000]


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TicketingError("GitLab returned an invalid response")
    return value


def _issue_iid(value: str) -> int:
    try:
        iid = int(value)
    except ValueError as exc:
        raise TicketingError("GitLab issue iid must be numeric") from exc
    if iid < 1:
        raise TicketingError("GitLab issue iid must be positive")
    return iid


def _result(value: Any) -> TicketResult:
    data = _object(value)
    iid = data.get("iid")
    if not isinstance(iid, int) or iid < 1:
        raise TicketingError("GitLab response did not include an issue iid")
    web_url = data.get("web_url")
    return TicketResult(
        external_id=str(iid),
        external_url=str(web_url)[:2048] if isinstance(web_url, str) else None,
        metadata={"iid": iid, "state": str(data.get("state") or "")[:32]},
    )
