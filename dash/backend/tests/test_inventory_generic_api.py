"""Generic read-only JSON inventory importer contract."""

from __future__ import annotations

from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_generic_api import GenericApiInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse

pytestmark = pytest.mark.release_gate


async def test_generic_api_maps_bounded_items_and_cursor_without_writes() -> None:
    calls: list[dict[str, Any]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append({"method": method, "url": url, **kwargs})
        return JsonResponse(
            status_code=200,
            data={
                "devices": [
                    {
                        "device_id": "device-1",
                        "identity": {"fqdn": "server.example.test"},
                        "name": "Server 1",
                        "os": "Linux",
                    }
                ],
                "paging": {"next": "page-2"},
            },
            headers={},
        )

    connector = InventoryConnector(
        name="Generic source",
        connector_type=PassiveConnectorType.GENERIC_API,
        base_url="https://inventory.example.test/api",
        config_json={
            "path": "/devices",
            "items_field": "devices",
            "source_id_field": "device_id",
            "identifier_fields": ["fqdn=identity.fqdn"],
            "attribute_fields": ["name", "os"],
            "next_cursor_field": "paging.next",
            "cursor_parameter": "after",
            "page_size_parameter": "page_size",
            "page_size": 250,
        },
    )
    adapter = GenericApiInventoryAdapter(sender=send)
    tested = await adapter.test(connector, "one-way-secret", source_data=None)
    assert tested == {"status_code": 200, "records_visible": 1, "read_only": True}

    observations, cursor = await adapter.collect(
        connector,
        "one-way-secret",
        cursor={"value": "page-1"},
        source_data=None,
    )
    assert len(observations) == 1
    assert observations[0].source_record_id == "device-1"
    assert observations[0].identifiers == [{"type": "fqdn", "value": "server.example.test"}]
    assert observations[0].attributes == {"name": "Server 1", "os": "Linux"}
    assert cursor == {"value": "page-2"}
    assert calls[-1]["method"] == "GET"
    assert calls[-1]["url"].endswith("/api/devices?after=page-1&page_size=250")
    assert calls[-1]["headers"]["Authorization"] == "Bearer one-way-secret"
    assert "json_body" not in calls[-1]
    assert PassiveConnectorType.GENERIC_API in passive_inventory.ADAPTERS


async def test_generic_api_rejects_executable_paths_and_unmapped_identity() -> None:
    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        return JsonResponse(status_code=200, data={"items": [{"id": "one"}]}, headers={})

    connector = InventoryConnector(
        name="Unsafe source",
        connector_type=PassiveConnectorType.GENERIC_API,
        base_url="https://inventory.example.test",
        config_json={"path": "/../admin", "identifier_fields": ["fqdn=fqdn"]},
    )
    adapter = GenericApiInventoryAdapter(sender=send)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="without traversal"):
        await adapter.collect(connector, None, cursor={}, source_data=None)

    connector.config_json = {"identifier_fields": ["fqdn=fqdn"]}
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="no configured identifiers"
    ):
        await adapter.collect(connector, None, cursor={}, source_data=None)
