"""UniFi Network read-only importer contract and security coverage."""

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

SITE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DEVICE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
CLIENT_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="UniFi Network inventory",
        connector_type=PassiveConnectorType.UNIFI,
        base_url="https://unifi.internal.test/proxy/network/integration",
        config_json={"site_id": SITE_ID, **config},
    )


async def test_unifi_maps_paged_devices_and_connected_clients_read_only() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if "/devices?" in url:
            return JsonResponse(
                200,
                {
                    "offset": 0,
                    "limit": 2,
                    "count": 2,
                    "totalCount": 2,
                    "data": [
                        {
                            "id": DEVICE_ID,
                            "macAddress": "00:11:22:33:44:55",
                            "ipAddress": "192.0.2.10",
                            "name": "Core-Switch.Example.Test.",
                            "model": "USW-Pro-24-PoE",
                            "state": "ONLINE",
                            "supported": True,
                            "firmwareVersion": "7.2.123",
                            "firmwareUpdatable": False,
                            "features": ["switching"],
                            "interfaces": ["ports"],
                        },
                        {
                            "id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                            "macAddress": "00-11-22-33-44-66",
                            "ipAddress": "2001:db8::10",
                            "name": "Lobby AP",
                            "model": "U7-Pro",
                            "state": "OFFLINE",
                        },
                    ],
                },
                {},
            )
        if "offset=2" in url:
            return JsonResponse(
                200,
                {
                    "offset": 2,
                    "limit": 2,
                    "count": 1,
                    "totalCount": 3,
                    "data": [
                        {
                            "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                            "name": "Unidentified mobile device",
                            "type": "WIRELESS",
                            "access": None,
                        }
                    ],
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "offset": 0,
                "limit": 2,
                "count": 2,
                "totalCount": 3,
                "data": [
                    {
                        "id": CLIENT_ID,
                        "macAddress": "AA:BB:CC:DD:EE:FF",
                        "ipAddress": "192.0.2.25",
                        "name": "Laptop-01",
                        "type": "WIRELESS",
                        "connectedAt": "2026-07-13T12:00:00Z",
                        "uplinkDeviceId": DEVICE_ID,
                        "access": {"type": "DEFAULT", "authorized": True},
                    },
                    {
                        "id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                        "ipAddress": "198.51.100.20",
                        "name": "remote-vpn",
                        "type": "VPN",
                        "access": {"type": "DEFAULT"},
                    },
                ],
            },
            {},
        )

    api_key = "unifi-api-key-never-returned"
    connector = _connector(allow_private=True, page_size=2, record_limit=10)
    adapter = UnifiInventoryAdapter(sender=send)
    tested = await adapter.test(connector, api_key, source_data=None)
    assert tested == {
        "records_received": 5,
        "records_visible": 4,
        "devices_received": 2,
        "connected_clients_received": 3,
        "resources": ["adopted devices", "connected clients"],
        "read_only": True,
    }
    observations, cursor = await adapter.collect(connector, api_key, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 4
    device = observations[0]
    assert device.source_record_id == f"unifi:device:{SITE_ID}:{DEVICE_ID}"
    assert device.identifiers == [
        {"type": "mac_address", "value": "00:11:22:33:44:55"},
        {"type": "ip_address", "value": "192.0.2.10"},
        {"type": "fqdn", "value": "core-switch.example.test"},
        {"type": "smb_name", "value": "core-switch"},
    ]
    assert device.attributes == {
        "canonical_name": "core-switch.example.test",
        "asset_type": "network_device",
        "manufacturer": "Ubiquiti",
        "unifi_site_id": SITE_ID,
        "unifi_device_id": DEVICE_ID,
        "model": "USW-Pro-24-PoE",
        "unifi_state": "ONLINE",
        "firmware_version": "7.2.123",
        "unifi_supported": True,
        "firmware_updatable": False,
        "unifi_features": ["switching"],
        "unifi_interfaces": ["ports"],
    }
    client = observations[2]
    assert client.source_record_id == f"unifi:client:{SITE_ID}:{CLIENT_ID}"
    assert client.identifiers == [
        {"type": "mac_address", "value": "aa:bb:cc:dd:ee:ff"},
        {"type": "ip_address", "value": "192.0.2.25"},
        {"type": "hostname", "value": "laptop-01"},
    ]
    assert client.attributes == {
        "canonical_name": "laptop-01",
        "unifi_site_id": SITE_ID,
        "unifi_client_id": CLIENT_ID,
        "unifi_client_type": "WIRELESS",
        "unifi_connected_at": "2026-07-13T12:00:00Z",
        "unifi_uplink_device_id": DEVICE_ID,
        "unifi_access_type": "DEFAULT",
        "unifi_access_authorized": True,
    }
    first_device, first_client, next_client = calls[:3]
    assert first_device[0] == first_client[0] == next_client[0] == "GET"
    assert first_device[1] == (
        "https://unifi.internal.test/proxy/network/integration/"
        f"v1/sites/{SITE_ID}/devices?offset=0&limit=2"
    )
    assert first_client[1].endswith(f"/v1/sites/{SITE_ID}/clients?offset=0&limit=2")
    assert next_client[1].endswith(f"/v1/sites/{SITE_ID}/clients?offset=2&limit=2")
    for _, _, kwargs in calls:
        assert kwargs["headers"] == {"Accept": "application/json", "X-API-Key": api_key}
        assert kwargs["allow_private"] is True
        assert "json_body" not in kwargs and "form_body" not in kwargs
    assert api_key not in json.dumps(tested)
    assert api_key not in json.dumps(cursor)
    assert api_key not in str(observations)
    assert PassiveConnectorType.UNIFI in passive_inventory.ADAPTERS


async def test_unifi_accepts_only_official_local_or_cloud_integration_roots() -> None:
    calls: list[str] = []

    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        calls.append(url)
        return JsonResponse(
            200,
            {"offset": 0, "limit": 100, "count": 0, "totalCount": 0, "data": []},
            {},
        )

    cloud = _connector(include_clients=False)
    cloud.base_url = (
        "https://api.ui.com/v1/connector/consoles/console_01:region/proxy/network/integration"
    )
    await UnifiInventoryAdapter(sender=empty).test(cloud, "api-key", source_data=None)
    assert calls == [
        "https://api.ui.com/v1/connector/consoles/console_01:region/"
        f"proxy/network/integration/v1/sites/{SITE_ID}/devices?offset=0&limit=100"
    ]

    for root in (
        "https://unifi.internal.test",
        "https://unifi.internal.test/admin/proxy/network/integration",
        "https://unifi.internal.test/proxy/network/integration?path=/admin",
        "https://evil.example/v1/connector/consoles/console-1/proxy/network/integration",
        "http://unifi.internal.test/proxy/network/integration",
    ):
        connector = _connector()
        connector.base_url = root
        with pytest.raises(passive_inventory.InventoryConnectorError, match="API root"):
            await UnifiInventoryAdapter(sender=empty).test(connector, "api-key", source_data=None)


async def test_unifi_rejects_mutation_surfaces_bad_config_and_unbounded_pages() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {"offset": 0, "limit": 100, "count": 0, "totalCount": 0, "data": []},
            {},
        )

    adapter = UnifiInventoryAdapter(sender=empty)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), "api-key", cursor={"offset": 100}, source_data=None)
    connector = _connector()
    connector.base_url = None
    with pytest.raises(passive_inventory.InventoryConnectorError, match="requires"):
        await adapter.test(connector, "api-key", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="API key is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="site_id must be a UUID"):
        await adapter.test(_connector(site_id="default"), "api-key", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(action="ADOPT"), "api-key", source_data=None)
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="include devices or clients"
    ):
        await adapter.test(
            _connector(include_devices=False, include_clients=False),
            "api-key",
            source_data=None,
        )

    async def oversized(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {"offset": 0, "limit": 100, "count": 0, "totalCount": 10_001, "data": []},
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="combined record limit"):
        await UnifiInventoryAdapter(sender=oversized).test(
            _connector(), "api-key", source_data=None
        )

    async def inconsistent(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {"offset": 0, "limit": 100, "count": 2, "totalCount": 1, "data": []},
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="metadata is invalid"):
        await UnifiInventoryAdapter(sender=inconsistent).test(
            _connector(), "api-key", source_data=None
        )

    async def bad_uplink(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        data = (
            [
                {
                    "id": CLIENT_ID,
                    "macAddress": "00:11:22:33:44:55",
                    "uplinkDeviceId": "not-a-uuid",
                }
            ]
            if "/clients?" in url
            else []
        )
        return JsonResponse(
            200,
            {
                "offset": 0,
                "limit": 100,
                "count": len(data),
                "totalCount": len(data),
                "data": data,
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="uplinkDeviceId"):
        await UnifiInventoryAdapter(sender=bad_uplink).test(
            _connector(), "api-key", source_data=None
        )
