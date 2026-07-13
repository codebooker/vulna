"""Proxmox VE read-only inventory adapter contract and security coverage."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_proxmox import ProxmoxInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError

pytestmark = pytest.mark.release_gate

CONNECTOR_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
API_IDENTITY = "vulna@pve!inventory"
API_SECRET = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        id=CONNECTOR_ID,
        name="Proxmox inventory",
        connector_type=PassiveConnectorType.PROXMOX,
        base_url="https://pve.internal.test:8006",
        config_json={"api_identity": API_IDENTITY, **config},
    )


async def test_proxmox_maps_nodes_and_guests_with_api_token() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if url.endswith("type=node"):
            return JsonResponse(
                200,
                {
                    "data": [
                        {
                            "type": "node",
                            "id": "node/pve01.example.test",
                            "node": "pve01.example.test",
                            "status": "online",
                            "host-arch": "x86_64",
                            "maxcpu": 16,
                            "cpu": 0.25,
                            "mem": 8_589_934_592,
                            "maxmem": 34_359_738_368,
                            "uptime": 86_400,
                        }
                    ]
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "data": [
                    {
                        "type": "qemu",
                        "id": "qemu/101",
                        "vmid": 101,
                        "node": "pve01.example.test",
                        "name": "app01.example.test",
                        "status": "running",
                        "maxcpu": 4,
                        "mem": 2_147_483_648,
                        "maxmem": 4_294_967_296,
                        "disk": 10_737_418_240,
                        "maxdisk": 21_474_836_480,
                        "pool": "production",
                        "tags": "linux;production",
                        "template": False,
                    },
                    {
                        "type": "lxc",
                        "id": "lxc/102",
                        "vmid": 102,
                        "node": "pve01.example.test",
                        "name": "192.0.2.42",
                        "status": "stopped",
                    },
                    {
                        "type": "qemu",
                        "id": "qemu/9000",
                        "vmid": 9000,
                        "node": "pve01.example.test",
                        "name": "debian-template",
                        "template": True,
                    },
                ]
            },
            {},
        )

    adapter = ProxmoxInventoryAdapter(sender=send)
    connector = _connector(allow_private=True)
    tested = await adapter.test(connector, API_SECRET, source_data=None)
    assert tested == {
        "records_received": 4,
        "records_visible": 3,
        "nodes_received": 1,
        "guests_received": 3,
        "resources": ["nodes", "virtual machines and containers"],
        "read_only": True,
    }
    assert API_SECRET not in json.dumps(tested)
    assert API_IDENTITY not in json.dumps(tested)

    calls.clear()
    observations, cursor = await adapter.collect(connector, API_SECRET, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 3
    node = observations[0]
    assert node.source_record_id == "proxmox:node:pve01.example.test"
    assert node.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"proxmox:{CONNECTOR_ID}:node:pve01.example.test",
        },
        {"type": "fqdn", "value": "pve01.example.test"},
        {"type": "smb_name", "value": "pve01"},
    ]
    assert node.attributes == {
        "canonical_name": "pve01.example.test",
        "asset_type": "hypervisor",
        "manufacturer": "Proxmox",
        "operating_system": "Proxmox VE",
        "proxmox_resource_type": "node",
        "proxmox_node": "pve01.example.test",
        "proxmox_status": "online",
        "architecture": "x86_64",
        "cpu_count": 16,
        "proxmox_cpu_utilization": 0.25,
        "memory_usage_bytes": 8_589_934_592,
        "memory_size_bytes": 34_359_738_368,
        "uptime_seconds": 86_400,
    }
    vm = observations[1]
    assert vm.source_record_id == "proxmox:qemu:101"
    assert vm.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"proxmox:{CONNECTOR_ID}:qemu:101",
        },
        {"type": "fqdn", "value": "app01.example.test"},
        {"type": "smb_name", "value": "app01"},
    ]
    assert vm.attributes["virtualization_kind"] == "full_virtualization"
    assert vm.attributes["tags"] == ["linux", "production"]
    assert observations[2].identifiers[-1] == {
        "type": "ip_address",
        "value": "192.0.2.42",
    }
    assert observations[2].attributes["virtualization_kind"] == "container"
    assert all("9000" not in item.source_record_id for item in observations)

    assert [call[:2] for call in calls] == [
        (
            "GET",
            "https://pve.internal.test:8006/api2/json/cluster/resources?type=node",
        ),
        (
            "GET",
            "https://pve.internal.test:8006/api2/json/cluster/resources?type=vm",
        ),
    ]
    expected_headers = {
        "Accept": "application/json",
        "Authorization": f"PVEAPIToken={API_IDENTITY}={API_SECRET}",
    }
    for method, _, kwargs in calls:
        assert method == "GET"
        assert kwargs["headers"] == expected_headers
        assert kwargs["allow_private"] is True
        assert "json_body" not in kwargs and "form_body" not in kwargs
    assert API_SECRET not in str(observations)
    assert API_IDENTITY not in str(observations)
    assert PassiveConnectorType.PROXMOX in passive_inventory.ADAPTERS


async def test_proxmox_restricts_origin_config_and_resources() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, {"data": []}, {})

    adapter = ProxmoxInventoryAdapter(sender=empty)
    for root in (
        "http://pve.internal.test:8006",
        "https://pve.internal.test:22",
        "https://user:pass@pve.internal.test:8006",
        "https://pve.internal.test:8006/api2/json",
        "https://pve.internal.test:8006/?type=node",
        "https://pve.internal.test:8006/#fragment",
    ):
        connector = _connector()
        connector.base_url = root
        with pytest.raises(passive_inventory.InventoryConnectorError, match="API origin"):
            await adapter.test(connector, API_SECRET, source_data=None)

    result = await adapter.test(_connector(include_nodes=False), API_SECRET, source_data=None)
    assert result["resources"] == ["virtual machines and containers"]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), API_SECRET, cursor={"page": 2}, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(operation="shutdown"), API_SECRET, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="include nodes"):
        await adapter.test(
            _connector(include_nodes=False, include_guests=False),
            API_SECRET,
            source_data=None,
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="USER@REALM"):
        await adapter.test(_connector(api_identity="root@pam"), API_SECRET, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="secret is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="secret must be a UUID"):
        await adapter.test(_connector(), "not-a-token", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record_limit"):
        await adapter.test(_connector(record_limit=10_001), API_SECRET, source_data=None)


async def test_proxmox_rejects_invalid_duplicate_or_unbounded_payloads() -> None:
    responses: list[Any] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, responses.pop(0), {})

    adapter = ProxmoxInventoryAdapter(sender=send)
    responses[:] = [{"value": []}]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="envelope is invalid"):
        await adapter.test(_connector(include_guests=False), API_SECRET, source_data=None)

    duplicate = {
        "type": "node",
        "id": "node/pve01",
        "node": "pve01",
    }
    responses[:] = [{"data": [duplicate, duplicate]}]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate resource IDs"):
        await adapter.test(_connector(include_guests=False), API_SECRET, source_data=None)

    responses[:] = [
        {"data": [duplicate]},
        {
            "data": [
                {
                    "type": "qemu",
                    "id": "qemu/101",
                    "vmid": 101,
                    "node": "pve01",
                }
            ]
        },
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="combined record limit"):
        await adapter.test(_connector(record_limit=1), API_SECRET, source_data=None)

    responses[:] = [
        {
            "data": [
                {
                    "type": "qemu",
                    "id": "qemu/other",
                    "vmid": 101,
                    "node": "pve01",
                }
            ]
        }
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="ID is inconsistent"):
        await adapter.test(_connector(include_nodes=False), API_SECRET, source_data=None)


async def test_proxmox_can_include_templates_explicitly() -> None:
    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            {
                "data": [
                    {
                        "type": "qemu",
                        "id": "qemu/9000",
                        "vmid": 9000,
                        "node": "pve01",
                        "name": "debian-template",
                        "template": True,
                    }
                ]
            },
            {},
        )

    observations, _ = await ProxmoxInventoryAdapter(sender=send).collect(
        _connector(include_nodes=False, include_templates=True),
        API_SECRET,
        cursor={},
        source_data=None,
    )
    assert len(observations) == 1
    assert observations[0].attributes["proxmox_template"] is True


async def test_proxmox_redacts_transport_errors_and_rejects_invalid_ca() -> None:
    async def leaking(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        raise TicketHttpError(f"ticket provider rejected {API_IDENTITY} {API_SECRET}")

    with pytest.raises(passive_inventory.InventoryConnectorError) as caught:
        await ProxmoxInventoryAdapter(sender=leaking).test(
            _connector(include_guests=False), API_SECRET, source_data=None
        )
    assert API_IDENTITY not in str(caught.value)
    assert API_SECRET not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)

    called = False

    async def unreachable(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        nonlocal called
        called = True
        return JsonResponse(200, {"data": []}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="valid CA certificate"):
        await ProxmoxInventoryAdapter(sender=unreachable).test(
            _connector(
                include_guests=False,
                trust_pem=(
                    "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----"
                ),
            ),
            API_SECRET,
            source_data=None,
        )
    assert called is False
