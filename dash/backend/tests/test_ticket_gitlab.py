"""GitLab Issues connector contract tests."""

from __future__ import annotations

from typing import Any

import pytest
from app.models.enums import TicketConnectorType
from app.models.ticketing import TicketConnector
from app.services import ticketing
from app.services.ticket_adapters.gitlab import GitLabIssuesAdapter
from app.services.ticket_adapters.http import JsonResponse
from app.services.ticketing import TicketingError

pytestmark = pytest.mark.release_gate


class FakeSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.search_items: list[dict[str, Any]] = []

    async def __call__(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        body = kwargs.get("json_body") or {}
        if "/issues?" in url:
            data = self.search_items
        elif method == "GET":
            data: dict[str, Any] = {
                "path_with_namespace": "platform/security/app",
                "visibility": "private",
                "issues_enabled": True,
            }
        else:
            data = {
                "iid": 17,
                "web_url": "https://gitlab.example/platform/security/app/-/issues/17",
                "state": "closed" if body.get("state_event") == "close" else "opened",
            }
        return JsonResponse(200, data, {})


def _connector() -> TicketConnector:
    return TicketConnector(
        name="GitLab",
        connector_type=TicketConnectorType.GITLAB,
        base_url="https://gitlab.example/api/v4",
        project_key="platform/security/app",
        config_json={"labels": ["security", "vulna"], "assignee_ids": [12]},
        encrypted_secret="unused",
        enabled=True,
        close_after_verification=True,
        timeout_seconds=15,
    )


def _payload() -> dict[str, Any]:
    return {
        "title": "Critical finding",
        "summary": "Selected summary",
        "severity": "critical",
        "priority": "critical",
        "status": "new",
        "cve_ids": ["CVE-2026-4301"],
        "remediation": "Apply update",
        "due_at": None,
    }


async def test_gitlab_test_create_update_and_close() -> None:
    sender = FakeSender()
    adapter = GitLabIssuesAdapter(sender)
    connector = _connector()
    assert await adapter.test(connector, "gitlab-token") == {
        "project": "platform/security/app",
        "visibility": "private",
        "issues_enabled": True,
    }
    assert sender.calls[0]["url"].endswith("/projects/platform%2Fsecurity%2Fapp")
    assert sender.calls[0]["headers"] == {"PRIVATE-TOKEN": "gitlab-token"}

    created = await adapter.upsert(
        connector,
        "gitlab-token",
        _payload(),
        external_id=None,
        idempotency_key="gitlab-create",
    )
    assert created.external_id == "17"
    create = sender.calls[-1]
    assert create["method"] == "POST"
    assert create["headers"]["Idempotency-Key"].startswith("vulna-")
    assert create["json_body"]["labels"] == "security,vulna"
    assert "CVE-2026-4301" in create["json_body"]["description"]

    sender.search_items = [
        {
            "iid": 17,
            "web_url": "https://gitlab.example/platform/security/app/-/issues/17",
            "state": "opened",
            "description": create["json_body"]["description"],
        }
    ]
    post_count = sum(call["method"] == "POST" for call in sender.calls)
    replay = await adapter.upsert(
        connector,
        "gitlab-token",
        _payload(),
        external_id=None,
        idempotency_key="gitlab-create",
    )
    assert replay.external_id == "17"
    assert sum(call["method"] == "POST" for call in sender.calls) == post_count

    await adapter.upsert(
        connector,
        "gitlab-token",
        _payload(),
        external_id="17",
        idempotency_key="gitlab-update",
    )
    assert sender.calls[-1]["method"] == "PUT"
    assert sender.calls[-1]["url"].endswith("/issues/17")
    closed = await adapter.close(
        connector,
        "gitlab-token",
        _payload(),
        external_id="17",
        idempotency_key="gitlab-close",
    )
    assert closed.metadata["state"] == "closed"
    assert sender.calls[-1]["json_body"] == {"state_event": "close"}


async def test_gitlab_bearer_mode_validation_and_registration() -> None:
    connector = _connector()
    connector.config_json = {"auth_scheme": "bearer"}
    sender = FakeSender()
    await GitLabIssuesAdapter(sender).test(connector, "oauth-token")
    assert sender.calls[0]["headers"] == {"Authorization": "Bearer oauth-token"}
    connector.project_key = "invalid"
    with pytest.raises(TicketingError, match="namespace/project"):
        await GitLabIssuesAdapter(sender).test(connector, "secret")
    assert isinstance(ticketing.ADAPTERS[TicketConnectorType.GITLAB], GitLabIssuesAdapter)
