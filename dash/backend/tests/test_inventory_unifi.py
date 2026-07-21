"""UniFi Site Manager read-only importer contract and security coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_unifi import UnifiInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse

pytestmark = pytest.mark.release_gate

HOST_ID = "host-01:region"
SECOND_HOST_ID = "host-02:region"
DEVICE_ID = "F4E2C6C23F13"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="UniFi Site Manager inventory",
        connector_type=PassiveConnectorType.UNIFI,
        base_url=None,
        config_json=config,
    )


async def test_unifi_maps_paged_site_manager_devices_read_only() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if "nextToken=" in url:
            return JsonResponse(
                200,
                {
                    "data": [
                        {
                            "hostId": SECOND_HOST_ID,
                            "hostName": "branch-console.example.test",
                            "updatedAt": "2026-07-21T13:00:00Z",
                            "devices": [
                                {
                                    "id": "001122334466",
                                    "mac": "00-11-22-33-44-66",
                                    "ip": "2001:db8::10",
                                    "name": "Lobby AP",
                                    "model": "U7-Pro",
                                    "status": "offline",
                                }
                            ],
                        }
                    ],
                    "httpStatusCode": 200,
                    "traceId": "trace-two",
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "data": [
                    {
                        "hostId": HOST_ID,
                        "hostName": "unifi.example.test",
                        "updatedAt": "2026-07-21T12:00:00Z",
                        "devices": [
                            {
                                "id": DEVICE_ID,
                                "mac": DEVICE_ID,
                                "ip": "192.0.2.10",
                                "name": "Core-Switch.Example.Test.",
                                "model": "UDM SE",
                                "shortname": "UDMPROSE",
                                "productLine": "network",
                                "status": "online",
                                "version": "4.1.13",
                                "firmwareStatus": "upToDate",
                                "isConsole": True,
                                "isManaged": True,
                                "startupTime": "2026-07-20T12:00:00Z",
                                "adoptionTime": None,
                                "note": "Main console",
                                "uidb": {"shape": "intentionally ignored"},
                            }
                        ],
                    }
                ],
                "httpStatusCode": 200,
                "traceId": "trace-one",
                "nextToken": "page two/+==",
            },
            {},
        )

    api_key = "unifi-api-key-never-returned"
    connector = _connector(host_ids=[HOST_ID, SECOND_HOST_ID], page_size=2, record_limit=10)
    adapter = UnifiInventoryAdapter(sender=send)
    tested = await adapter.test(connector, api_key, source_data=None)
    assert tested == {
        "records_received": 2,
        "records_visible": 2,
        "devices_received": 2,
        "hosts_received": 2,
        "resource": "Site Manager devices",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(connector, api_key, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 2
    device = observations[0]
    assert device.source_record_id == f"unifi:device:{HOST_ID}:{DEVICE_ID}"
    assert device.identifiers == [
        {"type": "mac_address", "value": "f4:e2:c6:c2:3f:13"},
        {"type": "ip_address", "value": "192.0.2.10"},
        {"type": "fqdn", "value": "core-switch.example.test"},
        {"type": "smb_name", "value": "core-switch"},
    ]
    assert device.attributes == {
        "canonical_name": "core-switch.example.test",
        "asset_type": "network_device",
        "manufacturer": "Ubiquiti",
        "unifi_host_id": HOST_ID,
        "unifi_device_id": DEVICE_ID,
        "unifi_host_name": "unifi.example.test",
        "unifi_host_updated_at": "2026-07-21T12:00:00Z",
        "model": "UDM SE",
        "unifi_shortname": "UDMPROSE",
        "unifi_product_line": "network",
        "unifi_status": "online",
        "firmware_version": "4.1.13",
        "unifi_firmware_status": "upToDate",
        "unifi_startup_time": "2026-07-20T12:00:00Z",
        "unifi_note": "Main console",
        "unifi_is_console": True,
        "unifi_is_managed": True,
    }
    assert "uidb" not in json.dumps(device.attributes)
    first_page, second_page = calls[:2]
    assert first_page[0] == second_page[0] == "GET"
    assert first_page[1] == (
        "https://api.ui.com/v1/devices?hostIds%5B%5D=host-01%3Aregion%2Chost-02%3Aregion&pageSize=2"
    )
    assert second_page[1].endswith("&nextToken=page+two%2F%2B%3D%3D")
    for _, _, kwargs in calls:
        assert kwargs["headers"] == {"Accept": "application/json", "X-API-Key": api_key}
        assert kwargs["allow_private"] is False
        assert "json_body" not in kwargs and "form_body" not in kwargs
    assert api_key not in json.dumps(tested)
    assert api_key not in json.dumps(cursor)
    assert api_key not in str(observations)
    assert PassiveConnectorType.UNIFI in passive_inventory.ADAPTERS


async def test_unifi_uses_only_the_fixed_site_manager_endpoint() -> None:
    calls: list[str] = []

    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        calls.append(url)
        return JsonResponse(200, {"data": [], "httpStatusCode": 200}, {})

    await UnifiInventoryAdapter(sender=empty).test(_connector(), "api-key", source_data=None)
    assert calls == ["https://api.ui.com/v1/devices?pageSize=100"]

    connector = _connector()
    connector.base_url = "https://api.ui.com"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="does not accept"):
        await UnifiInventoryAdapter(sender=empty).test(connector, "api-key", source_data=None)


async def test_unifi_rejects_legacy_or_invalid_configuration() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, {"data": [], "httpStatusCode": 200}, {})

    adapter = UnifiInventoryAdapter(sender=empty)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), "api-key", cursor={"nextToken": "x"}, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="source data"):
        await adapter.test(_connector(), "api-key", source_data=b"not allowed")
    with pytest.raises(passive_inventory.InventoryConnectorError, match="API key is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="API key is required"):
        await adapter.test(_connector(), "api-key\r\ninjected", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(site_id="default"), "api-key", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="host_ids entry"):
        await adapter.test(_connector(host_ids=["host/../../devices"]), "api-key", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicates"):
        await adapter.test(_connector(host_ids=[HOST_ID, HOST_ID]), "api-key", source_data=None)


async def test_unifi_enforces_response_pagination_and_record_bounds() -> None:
    async def repeated(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {"data": [], "httpStatusCode": 200, "nextToken": "same-token"},
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="repeated"):
        await UnifiInventoryAdapter(sender=repeated).test(_connector(), "api-key", source_data=None)

    async def oversized(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {
                "data": [
                    {
                        "hostId": HOST_ID,
                        "devices": [{"id": f"device-{index}"} for index in range(3)],
                    }
                ],
                "httpStatusCode": 200,
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await UnifiInventoryAdapter(sender=oversized).test(
            _connector(record_limit=2), "api-key", source_data=None
        )

    async def invalid(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, {"data": [], "httpStatusCode": 201}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="response is invalid"):
        await UnifiInventoryAdapter(sender=invalid).test(_connector(), "api-key", source_data=None)


async def test_unifi_rejects_malformed_and_duplicate_devices() -> None:
    async def malformed(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {
                "data": [
                    {
                        "hostId": HOST_ID,
                        "devices": [{"id": DEVICE_ID, "mac": "not-a-mac"}],
                    }
                ],
                "httpStatusCode": 200,
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="MAC address"):
        await UnifiInventoryAdapter(sender=malformed).test(
            _connector(), "api-key", source_data=None
        )

    async def duplicates(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        device = {"id": DEVICE_ID, "mac": DEVICE_ID}
        return JsonResponse(
            200,
            {
                "data": [{"hostId": HOST_ID, "devices": [device, device]}],
                "httpStatusCode": 200,
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate device"):
        await UnifiInventoryAdapter(sender=duplicates).test(
            _connector(), "api-key", source_data=None
        )
