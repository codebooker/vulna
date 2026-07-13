"""Jira Cloud/Data Center issue adapter tests."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from app.models.enums import TicketConnectorType
from app.models.ticketing import TicketConnector
from app.services import ticketing
from app.services.ticket_adapters.http import JsonResponse
from app.services.ticket_adapters.jira import JiraIssueAdapter
from app.services.ticketing import TicketingError

pytestmark = pytest.mark.release_gate


class FakeSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.search_issues: list[dict[str, Any]] = []

    async def __call__(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if "/project/SEC" in url:
            data: Any = {"key": "SEC", "name": "Security"}
        elif "/search" in url:
            data = {"issues": self.search_issues}
        elif url.endswith("/transitions") and method == "GET":
            data = {
                "transitions": [
                    {"id": "21", "name": "In Progress"},
                    {"id": "31", "name": "Done"},
                ]
            }
        elif method == "POST" and url.endswith("/issue"):
            data = {"id": "10001", "key": "SEC-42"}
        else:
            data = {}
        return JsonResponse(200, data, {})


def _connector() -> TicketConnector:
    return TicketConnector(
        name="Jira",
        connector_type=TicketConnectorType.JIRA,
        base_url="https://acme.atlassian.net",
        project_key="SEC",
        config_json={
            "api_version": "3",
            "issue_type": "Task",
            "labels": ["security", "vulna"],
            "priority_critical": "Highest",
        },
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
        "cve_ids": ["CVE-2026-4303"],
        "remediation": "Apply update",
        "due_at": None,
    }


async def test_jira_cloud_test_create_replay_update_and_transition() -> None:
    sender = FakeSender()
    adapter = JiraIssueAdapter(sender)
    connector = _connector()
    secret = json.dumps({"email": "security@example.com", "api_token": "jira-api-value"})
    assert await adapter.test(connector, secret) == {
        "project_key": "SEC",
        "project_name": "Security",
        "api_version": "3",
    }
    encoded = sender.calls[0]["headers"]["Authorization"].removeprefix("Basic ")
    assert base64.b64decode(encoded).decode() == "security@example.com:jira-api-value"

    created = await adapter.upsert(
        connector,
        secret,
        _payload(),
        external_id=None,
        idempotency_key="jira-create",
    )
    assert created.external_id == "SEC-42"
    create_call = next(
        call for call in sender.calls if call["method"] == "POST" and call["url"].endswith("/issue")
    )
    fields = create_call["json_body"]["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["priority"] == {"name": "Highest"}
    assert fields["description"]["type"] == "doc"
    marker = next(label for label in fields["labels"] if label.startswith("vulna-"))

    sender.search_issues = [{"key": "SEC-42", "fields": {"labels": [marker]}}]
    post_count = sum(call["method"] == "POST" for call in sender.calls)
    replay = await adapter.upsert(
        connector,
        secret,
        _payload(),
        external_id=None,
        idempotency_key="jira-create",
    )
    assert replay.external_id == "SEC-42"
    assert sum(call["method"] == "POST" for call in sender.calls) == post_count

    updated = await adapter.upsert(
        connector,
        secret,
        _payload(),
        external_id="sec-42",
        idempotency_key="jira-update",
    )
    assert updated.metadata["state"] == "updated"
    assert sender.calls[-1]["method"] == "PUT"
    closed = await adapter.close(
        connector,
        secret,
        _payload(),
        external_id="SEC-42",
        idempotency_key="jira-close",
    )
    assert closed.metadata["state"] == "closed"
    assert sender.calls[-1]["json_body"] == {"transition": {"id": "31"}}


async def test_jira_data_center_bearer_plain_description_and_validation() -> None:
    connector = _connector()
    connector.base_url = "https://jira.example"
    connector.config_json = {
        "api_version": "2",
        "auth_scheme": "bearer",
        "close_transition_id": "41",
    }
    sender = FakeSender()
    adapter = JiraIssueAdapter(sender)
    await adapter.test(connector, "jira-pat")
    assert sender.calls[0]["headers"] == {"Authorization": "Bearer jira-pat"}
    await adapter.upsert(
        connector,
        "jira-pat",
        _payload(),
        external_id="SEC-9",
        idempotency_key="update",
    )
    assert isinstance(sender.calls[-1]["json_body"]["fields"]["description"], str)
    await adapter.close(
        connector,
        "jira-pat",
        _payload(),
        external_id="SEC-9",
        idempotency_key="close",
    )
    assert sender.calls[-1]["json_body"] == {"transition": {"id": "41"}}
    assert isinstance(ticketing.ADAPTERS[TicketConnectorType.JIRA], JiraIssueAdapter)

    connector.project_key = "not valid"
    with pytest.raises(TicketingError, match="project_key"):
        await adapter.test(connector, "jira-pat")
    bad_version = _connector()
    bad_version.config_json = {"api_version": "4"}
    with pytest.raises(TicketingError, match="api_version"):
        await adapter.test(bad_version, "email:value")
    with pytest.raises(TicketingError, match="email and api_token"):
        await JiraIssueAdapter(sender).test(_connector(), "missing-separator")
