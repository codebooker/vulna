"""Jira Cloud REST v3 and Jira Data Center REST v2 issue adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

from app.models.ticketing import TicketConnector
from app.services.ticket_adapters.http import JsonResponse, request_json
from app.services.ticketing import TicketingError, TicketResult

SendJson = Callable[..., Awaitable[JsonResponse]]
_PROJECT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_ISSUE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}-[1-9][0-9]*$")


class JiraIssueAdapter:
    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    @staticmethod
    def _project(connector: TicketConnector) -> str:
        project = connector.project_key.strip()
        if not _PROJECT_RE.fullmatch(project):
            raise TicketingError("Jira project_key is invalid")
        return project.upper()

    @staticmethod
    def _version(connector: TicketConnector) -> str:
        version = str(connector.config_json.get("api_version", "3"))
        if version not in {"2", "3"}:
            raise TicketingError("Jira api_version must be 2 or 3")
        return version

    @staticmethod
    def _headers(connector: TicketConnector, secret: str) -> dict[str, str]:
        if connector.config_json.get("auth_scheme") == "bearer":
            if not secret.strip():
                raise TicketingError("Jira bearer token is required")
            return {"Authorization": f"Bearer {secret.strip()}"}
        email, api_token = _basic_credentials(secret)
        encoded = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

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
            headers=self._headers(connector, secret),
            json_body=body,
            timeout_seconds=connector.timeout_seconds,
            allow_private=bool(connector.config_json.get("allow_private", False)),
        )

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        project = self._project(connector)
        version = self._version(connector)
        response = await self._request(
            connector, secret, "GET", f"/rest/api/{version}/project/{project}"
        )
        data = _object(response.data)
        return {
            "project_key": str(data.get("key") or project)[:64],
            "project_name": str(data.get("name") or "")[:255],
            "api_version": version,
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
        version = self._version(connector)
        marker = _marker(idempotency_key)
        fields: dict[str, Any] = {
            "summary": str(payload["title"])[:255],
            "description": _description(payload, version),
            "labels": _labels(connector, marker),
        }
        priority_name = connector.config_json.get(f"priority_{payload.get('severity')}")
        if isinstance(priority_name, str) and priority_name.strip():
            fields["priority"] = {"name": priority_name.strip()[:255]}

        if external_id is not None:
            issue_key = _issue_key(external_id)
            await self._request(
                connector,
                secret,
                "PUT",
                f"/rest/api/{version}/issue/{issue_key}",
                {"fields": fields},
            )
            return _result(connector, issue_key, "updated")

        jql = quote(f'project = {project} AND labels = "{marker}"', safe="")
        search_path = (
            f"/rest/api/3/search/jql?jql={jql}&maxResults=2&fields=key"
            if version == "3"
            else f"/rest/api/2/search?jql={jql}&maxResults=2&fields=key"
        )
        search = await self._request(connector, secret, "GET", search_path)
        existing = _search_key(search.data)
        if existing is not None:
            return _result(connector, existing, "existing")

        fields["project"] = {"key": project}
        fields["issuetype"] = {
            "name": str(connector.config_json.get("issue_type", "Task"))[:255]
        }
        created = await self._request(
            connector,
            secret,
            "POST",
            f"/rest/api/{version}/issue",
            {"fields": fields},
        )
        data = _object(created.data)
        return _result(connector, _issue_key(str(data.get("key") or "")), "created")

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
        version = self._version(connector)
        issue_key = _issue_key(external_id)
        transition_id = connector.config_json.get("close_transition_id")
        if not isinstance(transition_id, str) or not transition_id.strip():
            response = await self._request(
                connector,
                secret,
                "GET",
                f"/rest/api/{version}/issue/{issue_key}/transitions",
            )
            transition_id = _select_transition(
                response.data,
                str(connector.config_json.get("close_transition_name", "Done")),
            )
        await self._request(
            connector,
            secret,
            "POST",
            f"/rest/api/{version}/issue/{issue_key}/transitions",
            {"transition": {"id": transition_id.strip()}},
        )
        return _result(connector, issue_key, "closed")


def _basic_credentials(secret: str) -> tuple[str, str]:
    try:
        parsed = json.loads(secret)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        email, api_token = parsed.get("email"), parsed.get("api_token")
    elif ":" in secret:
        email, api_token = secret.split(":", 1)
    else:
        email = api_token = None
    if not isinstance(email, str) or not email or not isinstance(api_token, str) or not api_token:
        raise TicketingError("Jira basic secret requires email and api_token")
    return email, api_token


def _marker(value: str) -> str:
    return f"vulna-{hashlib.sha256(value.encode()).hexdigest()[:24]}"


def _labels(connector: TicketConnector, marker: str) -> list[str]:
    labels = connector.config_json.get("labels")
    configured = [str(item)[:255] for item in labels[:20]] if isinstance(labels, list) else []
    return list(dict.fromkeys([*configured, marker]))


def _description(payload: dict[str, Any], version: str) -> str | dict[str, Any]:
    cves = ", ".join(str(item) for item in payload.get("cve_ids", [])) or "None"
    text = "\n".join(
        [
            str(payload.get("summary") or "No summary provided.")[:4000],
            "",
            f"Severity: {payload.get('severity')}",
            f"Priority: {payload.get('priority')}",
            f"Status: {payload.get('status')}",
            f"CVEs: {cves}",
            f"Due: {payload.get('due_at') or 'Not set'}",
            "",
            str(payload.get("remediation") or "No remediation guidance provided.")[:4000],
        ]
    )[:12000]
    if version == "2":
        return text
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": line or " "}],
            }
            for line in text.splitlines()
        ],
    }


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TicketingError("Jira returned an invalid response")
    return value


def _issue_key(value: str) -> str:
    key = value.strip().upper()
    if not _ISSUE_KEY_RE.fullmatch(key):
        raise TicketingError("Jira issue key is invalid")
    return key


def _search_key(value: Any) -> str | None:
    issues = value.get("issues") if isinstance(value, dict) else None
    if not isinstance(issues, list):
        return None
    for issue in issues:
        if isinstance(issue, dict) and isinstance(issue.get("key"), str):
            return _issue_key(issue["key"])
    return None


def _select_transition(value: Any, preferred: str) -> str:
    transitions = value.get("transitions") if isinstance(value, dict) else None
    if not isinstance(transitions, list):
        raise TicketingError("Jira returned an invalid transition list")
    names = [preferred, "Done", "Close", "Closed", "Resolve", "Resolved"]
    for name in names:
        for transition in transitions:
            if (
                isinstance(transition, dict)
                and str(transition.get("name") or "").casefold() == name.casefold()
                and str(transition.get("id") or "").strip()
            ):
                return str(transition["id"])
    raise TicketingError("Jira has no configured closing transition available")


def _result(connector: TicketConnector, issue_key: str, state: str) -> TicketResult:
    return TicketResult(
        external_id=issue_key,
        external_url=f"{connector.base_url.rstrip('/')}/browse/{issue_key}",
        metadata={"key": issue_key, "state": state},
    )
