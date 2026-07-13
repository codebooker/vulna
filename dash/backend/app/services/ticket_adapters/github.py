"""GitHub and GitHub Enterprise Issues adapter."""

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
_PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


class GitHubIssuesAdapter:
    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    @staticmethod
    def _project(connector: TicketConnector) -> str:
        project = connector.project_key.strip()
        if not _PROJECT_RE.fullmatch(project):
            raise TicketingError("GitHub project_key must be an owner/repository pair")
        return project

    @staticmethod
    def _headers(secret: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {secret}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _request(
        self,
        connector: TicketConnector,
        secret: str,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> JsonResponse:
        return await self._sender(
            method,
            f"{connector.base_url.rstrip('/')}{path}",
            headers=self._headers(secret),
            json_body=body,
            timeout_seconds=connector.timeout_seconds,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        project = self._project(connector)
        response = await self._request(connector, secret, "GET", f"/repos/{project}")
        data = _object(response.data)
        return {
            "repository": str(data.get("full_name") or project)[:255],
            "private": bool(data.get("private", False)),
            "issues_enabled": bool(data.get("has_issues", True)),
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
        project = self._project(connector)
        marker = _marker(idempotency_key)
        request: dict[str, Any] = {
            "title": str(payload["title"])[:256],
            "body": _issue_body(payload, marker),
        }
        labels = connector.config_json.get("labels")
        assignees = connector.config_json.get("assignees")
        if isinstance(labels, list):
            request["labels"] = labels[:20]
        if isinstance(assignees, list):
            request["assignees"] = assignees[:10]
        milestone = connector.config_json.get("milestone")
        if isinstance(milestone, int) and milestone > 0:
            request["milestone"] = milestone

        if external_id is not None:
            issue = await self._request(
                connector,
                secret,
                "PATCH",
                f"/repos/{project}/issues/{_issue_number(external_id)}",
                request,
            )
            return _result(issue.data)

        # GitHub Issues has no native idempotency header. Search for our stable,
        # non-secret body marker before creation to close the common retry window.
        query = quote(f'repo:{project} in:body "{marker}"', safe="")
        search = await self._request(connector, secret, "GET", f"/search/issues?q={query}")
        search_data = _object(search.data)
        items = search_data.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and marker in str(item.get("body") or ""):
                    return _result(item)
        created = await self._request(
            connector, secret, "POST", f"/repos/{project}/issues", request
        )
        return _result(created.data)

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
        project = self._project(connector)
        reason = connector.config_json.get("close_reason", "completed")
        if reason not in {"completed", "not_planned"}:
            reason = "completed"
        response = await self._request(
            connector,
            secret,
            "PATCH",
            f"/repos/{project}/issues/{_issue_number(external_id)}",
            {"state": "closed", "state_reason": reason},
        )
        return _result(response.data)


def _marker(idempotency_key: str) -> str:
    digest = hashlib.sha256(idempotency_key.encode()).hexdigest()[:32]
    return f"vulna-idempotency:{digest}"


def _issue_body(payload: dict[str, Any], marker: str) -> str:
    cves = ", ".join(str(value) for value in payload.get("cve_ids", [])) or "None"
    lines = [
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
    return "\n".join(lines)[:12000]


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TicketingError("GitHub returned an invalid response")
    return value


def _issue_number(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise TicketingError("GitHub issue id must be numeric") from exc
    if number < 1:
        raise TicketingError("GitHub issue id must be positive")
    return number


def _result(value: Any) -> TicketResult:
    data = _object(value)
    number = data.get("number")
    if not isinstance(number, int) or number < 1:
        raise TicketingError("GitHub response did not include an issue number")
    url = data.get("html_url")
    return TicketResult(
        external_id=str(number),
        external_url=str(url)[:2048] if isinstance(url, str) else None,
        metadata={"number": number, "state": str(data.get("state") or "")[:32]},
    )
