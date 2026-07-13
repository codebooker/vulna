"""GitHub Issues adapter protocol, idempotency, and transport security."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from app.models.enums import TicketConnectorType
from app.models.ticketing import TicketConnector
from app.services import notifications, ticketing
from app.services.ticket_adapters.github import GitHubIssuesAdapter
from app.services.ticket_adapters.http import (
    MAX_RESPONSE_BYTES,
    JsonResponse,
    TicketHttpError,
    request_json,
)
from app.services.ticketing import TicketingError

pytestmark = pytest.mark.release_gate


class FakeSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.search_items: list[dict[str, Any]] = []

    async def __call__(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if url.endswith("/repos/acme/security"):
            data: Any = {
                "full_name": "acme/security",
                "private": True,
                "has_issues": True,
            }
        elif "/search/issues?" in url:
            data = {"items": self.search_items}
        else:
            body = kwargs.get("json_body") or {}
            data = {
                "number": 42,
                "html_url": "https://github.example/acme/security/issues/42",
                "state": body.get("state", "open"),
                "body": body.get("body", ""),
            }
        return JsonResponse(status_code=200, data=data, headers={})


def _connector() -> TicketConnector:
    return TicketConnector(
        name="GitHub",
        connector_type=TicketConnectorType.GITHUB,
        base_url="https://github.example/api/v3",
        project_key="acme/security",
        config_json={"labels": ["security", "vulna"], "assignees": ["secops"]},
        encrypted_secret="not-used-by-adapter-test",
        enabled=True,
        close_after_verification=True,
        timeout_seconds=12,
    )


def _payload() -> dict[str, Any]:
    return {
        "title": "Critical package issue",
        "summary": "Upgrade the affected package.",
        "severity": "critical",
        "priority": "critical",
        "status": "new",
        "cve_ids": ["CVE-2026-4300"],
        "remediation": "Install the vendor update.",
        "due_at": "2026-07-20T00:00:00Z",
    }


async def test_github_test_create_update_close_and_marker_replay() -> None:
    sender = FakeSender()
    adapter = GitHubIssuesAdapter(sender)
    connector = _connector()
    metadata = await adapter.test(connector, "github-token")
    assert metadata == {
        "repository": "acme/security",
        "private": True,
        "issues_enabled": True,
    }
    assert sender.calls[0]["headers"]["Authorization"] == "Bearer github-token"

    created = await adapter.upsert(
        connector,
        "github-token",
        _payload(),
        external_id=None,
        idempotency_key="operation-one",
    )
    assert created.external_id == "42"
    create_call = next(call for call in sender.calls if call["method"] == "POST")
    body = create_call["json_body"]["body"]
    assert "CVE-2026-4300" in body and "vulna-idempotency:" in body
    assert create_call["json_body"]["labels"] == ["security", "vulna"]

    sender.search_items = [
        {
            "number": 42,
            "html_url": "https://github.example/acme/security/issues/42",
            "state": "open",
            "body": body,
        }
    ]
    post_count = sum(call["method"] == "POST" for call in sender.calls)
    replay = await adapter.upsert(
        connector,
        "github-token",
        _payload(),
        external_id=None,
        idempotency_key="operation-one",
    )
    assert replay.external_id == "42"
    assert sum(call["method"] == "POST" for call in sender.calls) == post_count

    updated = await adapter.upsert(
        connector,
        "github-token",
        _payload(),
        external_id="42",
        idempotency_key="operation-two",
    )
    assert updated.external_id == "42"
    assert sender.calls[-1]["url"].endswith("/repos/acme/security/issues/42")
    closed = await adapter.close(
        connector,
        "github-token",
        _payload(),
        external_id="42",
        idempotency_key="operation-three",
    )
    assert closed.metadata["state"] == "closed"
    assert sender.calls[-1]["json_body"] == {
        "state": "closed",
        "state_reason": "completed",
    }


async def test_github_rejects_invalid_project_and_is_registered() -> None:
    connector = _connector()
    connector.project_key = "not-an-owner-repository"
    with pytest.raises(TicketingError, match="owner/repository"):
        await GitHubIssuesAdapter(FakeSender()).test(connector, "secret")
    assert isinstance(ticketing.ADAPTERS[TicketConnectorType.GITHUB], GitHubIssuesAdapter)


async def test_shared_transport_pins_dns_disables_redirects_and_bounds_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers["Host"]
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["authorization"] = request.headers["Authorization"]
        return httpx.Response(200, content=json.dumps({"ok": True}).encode())

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, *, allow_private=False: ("github.example", "203.0.113.10"),
    )
    response = await request_json(
        "GET",
        "https://github.example/api/v3/repos/acme/security",
        headers={"Authorization": "Bearer secret"},
        transport=httpx.MockTransport(handler),
    )
    assert response.data == {"ok": True}
    assert seen == {
        "url": "https://203.0.113.10/api/v3/repos/acme/security",
        "host": "github.example",
        "sni": "github.example",
        "authorization": "Bearer secret",
    }

    redirect = httpx.MockTransport(
        lambda _request: httpx.Response(302, headers={"Location": "https://internal.test"})
    )
    with pytest.raises(TicketHttpError, match="HTTP 302"):
        await request_json(
            "GET",
            "https://github.example/api/v3",
            headers={},
            transport=redirect,
        )

    secret_error = httpx.MockTransport(
        lambda _request: httpx.Response(401, content=b"github-token must not leak")
    )
    with pytest.raises(TicketHttpError, match="HTTP 401") as error:
        await request_json(
            "GET",
            "https://github.example/api/v3",
            headers={},
            transport=secret_error,
        )
    assert "github-token" not in str(error.value)

    oversized = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
    )
    with pytest.raises(TicketHttpError, match="exceeded 1 MiB"):
        await request_json(
            "GET",
            "https://github.example/api/v3",
            headers={},
            transport=oversized,
        )
