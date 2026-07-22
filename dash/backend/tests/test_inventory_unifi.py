"""UniFi site discovery and site-scoped Network inventory coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_unifi import UnifiInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse
from httpx import AsyncClient

pytestmark = pytest.mark.release_gate

HOST_ID = "host-01:region"
SITE_ID = "7d80b1f5-48e0-4bde-b476-2a8f288130a2"
SECOND_SITE_ID = "b69298f7-d2f5-4c47-bd91-5115f0d02fdd"
DEVICE_ID = "b25d9489-b9de-4218-991d-97c44ee3b26f"
CLIENT_ID = "276a9dc0-6ad6-4c90-bbea-25c6751e6a01"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="UniFi Network inventory",
        connector_type=PassiveConnectorType.UNIFI,
        base_url=None,
        config_json={"host_id": HOST_ID, "site_id": SITE_ID, **config},
    )


def _page(
    items: list[dict[str, Any]], *, offset: int = 0, total: int | None = None
) -> dict[str, Any]:
    return {
        "offset": offset,
        "limit": 100,
        "count": len(items),
        "totalCount": len(items) if total is None else total,
        "data": items,
    }


async def test_unifi_discovers_paged_site_manager_sites_read_only() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if "nextToken=" in url:
            return JsonResponse(
                200,
                {
                    "data": [
                        {
                            "hostId": HOST_ID,
                            "siteId": SECOND_SITE_ID,
                            "meta": {"name": "Branch"},
                        }
                    ],
                    "httpStatusCode": 200,
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "data": [{"hostId": HOST_ID, "siteId": SITE_ID, "meta": {"name": "Headquarters"}}],
                "httpStatusCode": 200,
                "nextToken": "page two/+==",
            },
            {},
        )

    api_key = "unifi-api-key-never-returned"
    sites = await UnifiInventoryAdapter(sender=send).discover_sites(api_key)
    assert sites == [
        {"host_id": HOST_ID, "site_id": SECOND_SITE_ID, "name": "Branch"},
        {"host_id": HOST_ID, "site_id": SITE_ID, "name": "Headquarters"},
    ]
    assert calls[0][1] == "https://api.ui.com/v1/sites?pageSize=200"
    assert calls[1][1].endswith("&nextToken=page+two%2F%2B%3D%3D")
    for method, _, kwargs in calls:
        assert method == "GET"
        assert kwargs["headers"] == {"Accept": "application/json", "X-API-Key": api_key}
        assert kwargs["allow_private"] is False
        assert "json_body" not in kwargs and "form_body" not in kwargs
    assert api_key not in json.dumps(sites)


async def test_unifi_site_discovery_api_is_authorized_and_one_way(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def discover(_adapter: UnifiInventoryAdapter, secret: str | None) -> list[dict[str, str]]:
        assert secret == "transient-api-key"
        return [{"host_id": HOST_ID, "site_id": SITE_ID, "name": "Headquarters"}]

    monkeypatch.setattr(UnifiInventoryAdapter, "discover_sites", discover)
    forbidden = await client.post(
        "/api/v1/inventory/unifi/sites",
        headers=viewer_headers,
        json={"api_key": "transient-api-key"},
    )
    assert forbidden.status_code == 403
    response = await client.post(
        "/api/v1/inventory/unifi/sites",
        headers=admin_headers,
        json={"api_key": "transient-api-key"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == [{"host_id": HOST_ID, "site_id": SITE_ID, "name": "Headquarters"}]
    assert "transient-api-key" not in response.text


async def test_unifi_maps_only_selected_site_devices_and_clients() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if url.endswith("/devices?offset=0&limit=100"):
            return JsonResponse(
                200,
                _page(
                    [
                        {
                            "id": DEVICE_ID,
                            "macAddress": "f4-e2-c6-c2-3f-13",
                            "ipAddress": "192.0.2.10",
                            "name": "Core-Switch.Example.Test.",
                            "model": "USW Pro Max 24",
                            "state": "ONLINE",
                            "supported": True,
                            "firmwareVersion": "7.2.120",
                            "firmwareUpdatable": False,
                            "features": ["switching"],
                            "interfaces": ["ports"],
                        }
                    ]
                ),
                {},
            )
        if url.endswith("/clients?offset=0&limit=100"):
            return JsonResponse(
                200,
                _page(
                    [
                        {
                            "type": "WIRELESS",
                            "id": CLIENT_ID,
                            "name": "Jack-Laptop",
                            "connectedAt": "2026-07-22T12:00:00Z",
                            "ipAddress": "192.0.2.55",
                            "macAddress": "00:11:22:33:44:55",
                            "uplinkDeviceId": DEVICE_ID,
                            "access": {"type": "DEFAULT", "authorized": True},
                        }
                    ]
                ),
                {},
            )
        raise AssertionError(f"unexpected URL {url}")

    api_key = "unifi-api-key-never-returned"
    adapter = UnifiInventoryAdapter(sender=send)
    tested = await adapter.test(_connector(), api_key, source_data=None)
    assert tested == {
        "records_received": 2,
        "records_visible": 2,
        "devices_received": 1,
        "clients_received": 1,
        "sites_received": 1,
        "resource": "UniFi Network site devices and connected clients",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(_connector(), api_key, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 2
    device, client = observations
    assert device.source_record_id == f"unifi:device:{HOST_ID}:{SITE_ID}:{DEVICE_ID}"
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
        "unifi_site_id": SITE_ID,
        "unifi_device_id": DEVICE_ID,
        "model": "USW Pro Max 24",
        "unifi_status": "ONLINE",
        "firmware_version": "7.2.120",
        "unifi_supported": True,
        "unifi_firmware_updatable": False,
        "unifi_features": ["switching"],
        "unifi_interfaces": ["ports"],
    }
    assert client.source_record_id == f"unifi:client:{HOST_ID}:{SITE_ID}:{CLIENT_ID}"
    assert client.identifiers[:2] == [
        {"type": "mac_address", "value": "00:11:22:33:44:55"},
        {"type": "ip_address", "value": "192.0.2.55"},
    ]
    assert client.attributes == {
        "canonical_name": "jack-laptop",
        "asset_type": "unknown",
        "unifi_host_id": HOST_ID,
        "unifi_site_id": SITE_ID,
        "unifi_client_id": CLIENT_ID,
        "unifi_client_type": "WIRELESS",
        "unifi_connected_at": "2026-07-22T12:00:00Z",
        "unifi_uplink_device_id": DEVICE_ID,
        "unifi_access_type": "DEFAULT",
        "unifi_access_authorized": True,
    }
    expected_root = (
        f"https://api.ui.com/v1/connector/consoles/host-01%3Aregion/"
        f"proxy/network/integration/v1/sites/{SITE_ID}"
    )
    assert [url for _, url, _ in calls] == [
        f"{expected_root}/devices?offset=0&limit=100",
        f"{expected_root}/clients?offset=0&limit=100",
    ] * 2
    assert all(method == "GET" for method, _, _ in calls)
    assert all(kwargs["allow_private"] is False for _, _, kwargs in calls)
    assert api_key not in json.dumps(tested)
    assert api_key not in str(observations)
    assert PassiveConnectorType.UNIFI in passive_inventory.ADAPTERS


async def test_unifi_requires_explicit_one_to_one_site_mapping() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, _page([]), {})

    adapter = UnifiInventoryAdapter(sender=empty)
    for config in ({}, {"host_id": HOST_ID}, {"site_id": SITE_ID}):
        with pytest.raises(passive_inventory.InventoryConnectorError, match="required or invalid"):
            await adapter.test(
                InventoryConnector(
                    name="bad", connector_type=PassiveConnectorType.UNIFI, config_json=config
                ),
                "api-key",
                source_data=None,
            )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(
            InventoryConnector(
                name="legacy",
                connector_type=PassiveConnectorType.UNIFI,
                config_json={"host_ids": [HOST_ID]},
            ),
            "api-key",
            source_data=None,
        )


async def test_unifi_rejects_invalid_configuration_and_responses() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, _page([]), {})

    adapter = UnifiInventoryAdapter(sender=empty)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), "api-key", cursor={"offset": 1}, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="source data"):
        await adapter.test(_connector(), "api-key", source_data=b"not allowed")
    with pytest.raises(passive_inventory.InventoryConnectorError, match="API key is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="API key is required"):
        await adapter.test(_connector(), "api-key\r\ninjected", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="required or invalid"):
        await adapter.test(_connector(site_id="../../clients"), "api-key", source_data=None)
    connector = _connector()
    connector.base_url = "https://attacker.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="does not accept"):
        await adapter.test(connector, "api-key", source_data=None)

    async def malformed(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {"offset": 0, "limit": 100, "count": 1, "totalCount": 1, "data": []},
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="page is invalid"):
        await UnifiInventoryAdapter(sender=malformed).test(
            _connector(), "api-key", source_data=None
        )


async def test_unifi_enforces_combined_record_limit_and_duplicate_ids() -> None:
    device = {"id": DEVICE_ID, "macAddress": "00:11:22:33:44:55"}

    async def oversized(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if "/devices?" in url:
            return JsonResponse(200, _page([device, {"id": CLIENT_ID}]), {})
        return JsonResponse(200, _page([]), {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await UnifiInventoryAdapter(sender=oversized).test(
            _connector(record_limit=1), "api-key", source_data=None
        )

    async def duplicates(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if "/devices?" in url:
            return JsonResponse(200, _page([device, device]), {})
        return JsonResponse(200, _page([]), {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate inventory"):
        await UnifiInventoryAdapter(sender=duplicates).test(
            _connector(), "api-key", source_data=None
        )
