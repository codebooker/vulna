"""Kea DHCP read-only adapter contract and safety coverage."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import notifications, passive_inventory
from app.services.inventory_dhcp import DhcpInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, request_json

pytestmark = pytest.mark.release_gate


async def test_kea_dhcp_maps_a_fixed_paginated_read_command() -> None:
    calls: list[dict[str, Any]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append({"method": method, "url": url, **kwargs})
        return JsonResponse(
            status_code=200,
            data=[
                {
                    "result": 0,
                    "arguments": {
                        "leases": [
                            {
                                "ip-address": "192.0.2.10",
                                "hw-address": "00-0C-01-02-03-04",
                                "hostname": "Web-01.example.test.",
                                "client-id": "01:00:0c:01:02:03:04",
                                "cltt": 1_700_000_000,
                                "valid-lft": 3600,
                                "state": 0,
                                "subnet-id": 7,
                            },
                            {
                                "ip-address": "192.0.2.11",
                                "hw-address": "00:0c:01:02:03:05",
                                "hostname": "db-01",
                                "cltt": 1_700_000_010,
                                "valid-lft": 1800,
                                "state": 0,
                                "subnet-id": 7,
                            },
                            {
                                "ip-address": "192.0.2.12",
                                "hw-address": "00:0c:01:02:03:06",
                                "hostname": "old-host",
                                "cltt": 1_700_000_020,
                                "valid-lft": 0,
                                "state": 2,
                                "subnet-id": 7,
                            },
                        ]
                    },
                }
            ],
            headers={},
        )

    connector = InventoryConnector(
        name="Kea DHCP",
        connector_type=PassiveConnectorType.DHCP,
        base_url="https://kea.internal.test:8000/",
        config_json={
            "username": "vulna-reader",
            "page_size": 3,
            "allow_private": True,
            "legacy_control_agent": True,
        },
    )
    adapter = DhcpInventoryAdapter(sender=send)
    observations, cursor = await adapter.collect(
        connector,
        "one-way-password",
        cursor={"from": "192.0.2.9"},
        source_data=None,
    )
    assert len(observations) == 2
    assert cursor == {"from": "192.0.2.12"}
    assert observations[0].source_record_id == "kea4:192.0.2.10"
    assert observations[0].identifiers == [
        {"type": "ip_address", "value": "192.0.2.10"},
        {"type": "mac_address", "value": "00:0c:01:02:03:04"},
        {"type": "fqdn", "value": "web-01.example.test"},
    ]
    assert observations[0].attributes["dhcp_subnet_id"] == 7
    assert observations[0].attributes["lease_valid_lifetime_seconds"] == 3600
    call = calls[-1]
    assert call["method"] == "POST"
    assert call["url"] == "https://kea.internal.test:8000/"
    assert call["json_body"] == {
        "command": "lease4-get-page",
        "arguments": {"from": "192.0.2.9", "limit": 3},
        "service": ["dhcp4"],
    }
    expected = base64.b64encode(b"vulna-reader:one-way-password").decode("ascii")
    assert call["headers"]["Authorization"] == f"Basic {expected}"
    assert call["allow_private"] is True
    assert call["user_agent"] == "Vulna-DHCP-Inventory/1"
    assert PassiveConnectorType.DHCP in passive_inventory.ADAPTERS


async def test_kea_dhcp_test_empty_page_and_strict_failures() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        return JsonResponse(status_code=200, data={"result": 3}, headers={})

    connector = InventoryConnector(
        name="Kea empty",
        connector_type=PassiveConnectorType.DHCP,
        base_url="https://kea.example.test/",
        config_json={"allow_unauthenticated": True, "page_size": 2},
    )
    adapter = DhcpInventoryAdapter(sender=empty)
    tested = await adapter.test(connector, None, source_data=None)
    assert tested == {
        "leases_returned": 0,
        "records_visible": 0,
        "has_more": False,
        "command": "lease4-get-page",
        "read_only": True,
    }

    connector.config_json = {"username": "reader"}
    with pytest.raises(passive_inventory.InventoryConnectorError, match="requires a password"):
        await adapter.test(connector, None, source_data=None)

    connector.config_json = {"allow_unauthenticated": True}
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor is invalid"):
        await adapter.collect(
            connector,
            None,
            cursor={"command": "lease4-del"},
            source_data=None,
        )

    async def oversized(method: str, url: str, **kwargs: Any) -> JsonResponse:
        leases = [{"ip-address": f"192.0.2.{index}", "state": 0} for index in range(1, 4)]
        return JsonResponse(
            status_code=200,
            data={"result": 0, "arguments": {"leases": leases}},
            headers={},
        )

    connector.config_json = {"allow_unauthenticated": True, "page_size": 2}
    with pytest.raises(passive_inventory.InventoryConnectorError, match="more leases"):
        await DhcpInventoryAdapter(sender=oversized).collect(
            connector, None, cursor={}, source_data=None
        )


async def test_kea_dhcp_transport_pins_dns_and_preserves_nonstandard_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["host"] = request.headers["Host"]
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, content=b'{"result": 3}')

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, *, allow_private=False: ("kea.example.test", "203.0.113.20"),
    )
    transport = httpx.MockTransport(handler)

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        return await request_json(method, url, transport=transport, **kwargs)

    connector = InventoryConnector(
        name="Kea pinned",
        connector_type=PassiveConnectorType.DHCP,
        base_url="https://kea.example.test:8443/",
        config_json={"allow_unauthenticated": True},
    )
    assert (await DhcpInventoryAdapter(sender=send).test(connector, None, source_data=None))[
        "read_only"
    ]
    assert seen == {
        "method": "POST",
        "url": "https://203.0.113.20:8443/",
        "host": "kea.example.test:8443",
        "sni": "kea.example.test",
        "body": {
            "command": "lease4-get-page",
            "arguments": {"from": "start", "limit": 500},
        },
    }
