"""GLPI REST v1 session and ticket contract tests."""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.models.enums import TicketConnectorType
from app.models.ticketing import TicketConnector
from app.services import ticketing
from app.services.ticket_adapters.glpi import GlpiTicketAdapter
from app.services.ticket_adapters.http import JsonResponse
from app.services.ticketing import TicketingError

pytestmark = pytest.mark.release_gate


class FakeSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.search_data: list[dict[str, Any]] = []

    async def __call__(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if url.endswith("/initSession"):
            data: Any = {"session_token": "ephemeral-session"}
        elif url.endswith("/getActiveProfile"):
            data = {"id": 4, "name": "Vulna integration"}
        elif "/search/Ticket?" in url:
            data = {"data": self.search_data}
        elif method == "POST" and url.endswith("/Ticket"):
            data = {"id": 81, "message": "Item successfully added"}
        else:
            data = {}
        return JsonResponse(200, data, {})


def _connector() -> TicketConnector:
    return TicketConnector(
        name="GLPI",
        connector_type=TicketConnectorType.GLPI,
        base_url="https://glpi.example/apirest.php",
        project_key="7",
        config_json={"ticket_type": 1, "request_type_id": 3},
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
        "cve_ids": ["CVE-2026-4302"],
        "remediation": "Apply update",
        "due_at": None,
    }


async def test_glpi_session_test_create_replay_update_and_close() -> None:
    sender = FakeSender()
    adapter = GlpiTicketAdapter(sender)
    connector = _connector()
    encrypted_value = json.dumps(
        {"user_token": "glpi-user-token", "app_token": "glpi-app-token"}
    )
    assert await adapter.test(connector, encrypted_value) == {
        "profile_id": 4,
        "profile_name": "Vulna integration",
        "entity_id": 7,
        "api_version": "v1",
    }
    init = sender.calls[0]
    assert init["headers"] == {
        "Authorization": "user_token glpi-user-token",
        "App-Token": "glpi-app-token",
    }
    assert sender.calls[-1]["url"].endswith("/killSession")

    created = await adapter.upsert(
        connector,
        encrypted_value,
        _payload(),
        external_id=None,
        idempotency_key="glpi-create",
    )
    assert created.external_id == "81"
    create_call = next(call for call in sender.calls if call["method"] == "POST")
    ticket_input = create_call["json_body"]["input"]
    assert ticket_input["entities_id"] == 7
    assert ticket_input["urgency"] == 5
    assert "CVE-2026-4302" in ticket_input["content"]
    marker = ticket_input["name"].split("]", 1)[0].removeprefix("[")

    sender.search_data = [{"1": f"[{marker}] Critical finding", "2": 81}]
    post_count = sum(call["method"] == "POST" for call in sender.calls)
    replay = await adapter.upsert(
        connector,
        encrypted_value,
        _payload(),
        external_id=None,
        idempotency_key="glpi-create",
    )
    assert replay.external_id == "81"
    assert sum(call["method"] == "POST" for call in sender.calls) == post_count

    updated = await adapter.upsert(
        connector,
        encrypted_value,
        _payload(),
        external_id="81",
        idempotency_key="glpi-update",
    )
    assert updated.metadata["state"] == "updated"
    assert any(
        call["method"] == "PUT" and call["url"].endswith("/Ticket/81")
        for call in sender.calls
    )
    closed = await adapter.close(
        connector,
        encrypted_value,
        _payload(),
        external_id="81",
        idempotency_key="glpi-close",
    )
    assert closed.metadata["state"] == "closed"
    assert sender.calls[-2]["json_body"] == {"input": {"status": 6}}
    assert sender.calls[-1]["url"].endswith("/killSession")


async def test_glpi_plain_user_token_validation_and_registration() -> None:
    sender = FakeSender()
    connector = _connector()
    await GlpiTicketAdapter(sender).test(connector, "plain-user-token")
    assert sender.calls[0]["headers"] == {
        "Authorization": "user_token plain-user-token"
    }
    connector.project_key = "entity-seven"
    with pytest.raises(TicketingError, match="numeric entity"):
        await GlpiTicketAdapter(sender).test(connector, "secret")
    with pytest.raises(TicketingError, match="requires user_token"):
        await GlpiTicketAdapter(sender).test(_connector(), '{"app_token":"only"}')
    bad_url = _connector()
    bad_url.base_url = "https://glpi.example/api"
    with pytest.raises(TicketingError, match="apirest.php"):
        await GlpiTicketAdapter(sender).test(bad_url, "secret")
    assert isinstance(ticketing.ADAPTERS[TicketConnectorType.GLPI], GlpiTicketAdapter)
