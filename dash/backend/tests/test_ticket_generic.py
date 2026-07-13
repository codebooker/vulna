"""Bounded generic webhook/API connector tests."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from app.models.enums import TicketConnectorType
from app.models.ticketing import TicketConnector
from app.services import ticketing
from app.services.ticket_adapters.generic import GenericTicketAdapter
from app.services.ticket_adapters.http import JsonResponse
from app.services.ticketing import TicketingError

pytestmark = pytest.mark.release_gate


class FakeSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if method == "GET":
            data: Any = {"service": "Acme ticket API"}
        else:
            data = {
                "ticket_key": kwargs.get("json_body", {}).get("external_id") or "ACME-42",
                "ticket_url": "https://tickets.example/items/ACME-42",
                "status": "ok",
            }
        return JsonResponse(200, data, {})


def _connector() -> TicketConnector:
    return TicketConnector(
        name="Generic",
        connector_type=TicketConnectorType.GENERIC,
        base_url="https://tickets.example/api/v1",
        project_key="security",
        config_json={
            "auth_scheme": "header",
            "auth_header": "X-Service-Key",
            "test_path": "/health",
            "upsert_path": "/tickets/{id}",
            "close_path": "/tickets/{id}/close",
            "create_method": "POST",
            "update_method": "PATCH",
            "close_method": "POST",
            "response_id_field": "ticket_key",
            "response_url_field": "ticket_url",
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
        "cve_ids": ["CVE-2026-4304"],
        "remediation": "Apply update",
        "due_at": None,
    }


async def test_generic_test_create_update_and_close_selected_payload() -> None:
    sender = FakeSender()
    adapter = GenericTicketAdapter(sender)
    connector = _connector()
    assert await adapter.test(connector, "service-value") == {
        "status_code": 200,
        "service": "Acme ticket API",
        "mode": "api",
    }
    assert sender.calls[0]["url"] == "https://tickets.example/api/v1/health"
    assert sender.calls[0]["headers"] == {"X-Service-Key": "service-value"}

    created = await adapter.upsert(
        connector,
        "service-value",
        _payload(),
        external_id=None,
        idempotency_key="generic-create",
    )
    assert created.external_id == "ACME-42"
    create = sender.calls[-1]
    assert create["method"] == "POST"
    assert "/tickets/vulna-" in create["url"]
    assert create["headers"]["Idempotency-Key"].startswith("vulna-")
    assert create["json_body"]["finding"] == _payload()
    assert set(create["json_body"]) == {
        "version",
        "action",
        "idempotency_key",
        "project",
        "external_id",
        "finding",
    }

    updated = await adapter.upsert(
        connector,
        "service-value",
        _payload(),
        external_id="ACME-42",
        idempotency_key="generic-update",
    )
    assert updated.external_id == "ACME-42"
    assert sender.calls[-1]["method"] == "PATCH"
    assert sender.calls[-1]["url"].endswith("/tickets/ACME-42")
    closed = await adapter.close(
        connector,
        "service-value",
        _payload(),
        external_id="ACME-42",
        idempotency_key="generic-close",
    )
    assert closed.metadata["state"] == "closed"
    assert sender.calls[-1]["url"].endswith("/tickets/ACME-42/close")
    assert sender.calls[-1]["json_body"]["action"] == "close"


async def test_generic_auth_modes_and_path_field_guards() -> None:
    sender = FakeSender()
    connector = _connector()
    connector.config_json = {"auth_scheme": "basic"}
    secret = json.dumps({"username": "integration", "password": "test-value"})
    await GenericTicketAdapter(sender).test(connector, secret)
    encoded = sender.calls[-1]["headers"]["Authorization"].removeprefix("Basic ")
    assert base64.b64decode(encoded).decode() == "integration:test-value"

    connector.config_json = {"auth_scheme": "bearer"}
    await GenericTicketAdapter(sender).test(connector, "bearer-value")
    assert sender.calls[-1]["headers"] == {"Authorization": "Bearer bearer-value"}

    for config, message in (
        ({"auth_scheme": "header", "auth_header": "Host"}, "auth_header"),
        ({"upsert_path": "https://evil.example"}, "safe relative path"),
        ({"upsert_path": "/../admin"}, "safe relative path"),
        ({"upsert_path": "/tickets/{other}"}, "safe relative path"),
        ({"create_method": "DELETE"}, "write methods"),
        ({"response_id_field": "nested.id"}, "single field"),
    ):
        guarded = _connector()
        guarded.config_json = config
        with pytest.raises(TicketingError, match=message):
            await GenericTicketAdapter(sender).upsert(
                guarded,
                "secret",
                _payload(),
                external_id=None,
                idempotency_key="guard",
            )
    assert isinstance(ticketing.ADAPTERS[TicketConnectorType.GENERIC], GenericTicketAdapter)
