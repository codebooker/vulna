"""VMware vCenter read-only importer contract and security coverage."""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_vcenter import VcenterInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError

pytestmark = pytest.mark.release_gate

CONNECTOR_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
HOST_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        id=CONNECTOR_ID,
        name="vCenter inventory",
        connector_type=PassiveConnectorType.VCENTER,
        base_url="https://vcenter.internal.test",
        config_json={"username": "vulna-reader@vsphere.local", **config},
    )


async def test_vcenter_maps_hosts_and_vms_with_ephemeral_session() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if method == "POST":
            return JsonResponse(201, "session-token-never-returned", {})
        if url.endswith("/api/vcenter/host"):
            return JsonResponse(
                200,
                [
                    {
                        "host": "host-21",
                        "name": "esx01.example.test",
                        "connection_state": "CONNECTED",
                        "power_state": "POWERED_ON",
                        "host_uuid": HOST_UUID,
                    },
                    {
                        "host": "host-22",
                        "name": "192.0.2.20",
                        "connection_state": "DISCONNECTED",
                    },
                ],
                {},
            )
        if url.endswith("/api/vcenter/vm"):
            return JsonResponse(
                200,
                [
                    {
                        "vm": "vm-42",
                        "name": "app01.example.test",
                        "power_state": "POWERED_ON",
                        "cpu_count": 4,
                        "memory_size_mib": 8192,
                    },
                    {
                        "vm": "vm-43",
                        "name": "Finance Database (Replica)",
                        "power_state": "POWERED_OFF",
                    },
                ],
                {},
            )
        return JsonResponse(204, {}, {})

    password = "vcenter-password-never-returned"
    adapter = VcenterInventoryAdapter(sender=send)
    connector = _connector(allow_private=True)
    tested = await adapter.test(connector, password, source_data=None)
    assert tested == {
        "records_received": 4,
        "records_visible": 4,
        "hosts_received": 2,
        "virtual_machines_received": 2,
        "resources": ["hosts", "virtual machines"],
        "read_only": True,
    }
    assert password not in json.dumps(tested)
    assert "session-token-never-returned" not in json.dumps(tested)

    calls.clear()
    observations, cursor = await adapter.collect(connector, password, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 4
    host = observations[0]
    assert host.source_record_id == "vcenter:host:host-21"
    assert host.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"vcenter:{CONNECTOR_ID}:host:host-21",
        },
        {"type": "cloud_instance_id", "value": f"vmware-host:{HOST_UUID}"},
        {"type": "fqdn", "value": "esx01.example.test"},
        {"type": "smb_name", "value": "esx01"},
    ]
    assert host.attributes == {
        "canonical_name": "esx01.example.test",
        "asset_type": "hypervisor",
        "manufacturer": "VMware",
        "operating_system": "VMware ESXi",
        "vcenter_object_id": "host-21",
        "vcenter_object_type": "host",
        "vcenter_host_uuid": HOST_UUID,
        "vcenter_connection_state": "CONNECTED",
        "vcenter_power_state": "POWERED_ON",
    }
    assert observations[1].identifiers[-1] == {
        "type": "ip_address",
        "value": "192.0.2.20",
    }
    vm = observations[2]
    assert vm.source_record_id == "vcenter:vm:vm-42"
    assert vm.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"vcenter:{CONNECTOR_ID}:vm:vm-42",
        },
        {"type": "fqdn", "value": "app01.example.test"},
        {"type": "smb_name", "value": "app01"},
    ]
    assert vm.attributes == {
        "canonical_name": "app01.example.test",
        "asset_type": "virtual_machine",
        "manufacturer": "VMware",
        "vcenter_object_id": "vm-42",
        "vcenter_object_type": "virtual_machine",
        "vcenter_power_state": "POWERED_ON",
        "cpu_count": 4,
        "memory_size_mib": 8192,
    }
    assert observations[3].attributes["canonical_name"] == "Finance Database (Replica)"

    assert [call[:2] for call in calls] == [
        ("POST", "https://vcenter.internal.test/api/session"),
        ("GET", "https://vcenter.internal.test/api/vcenter/host"),
        ("GET", "https://vcenter.internal.test/api/vcenter/vm"),
        ("DELETE", "https://vcenter.internal.test/api/session"),
    ]
    expected_basic = base64.b64encode(f"vulna-reader@vsphere.local:{password}".encode()).decode()
    assert calls[0][2]["headers"] == {
        "Accept": "application/json",
        "Authorization": f"Basic {expected_basic}",
    }
    for method, _, kwargs in calls[1:]:
        assert kwargs["headers"] == {
            "Accept": "application/json",
            "vmware-api-session-id": "session-token-never-returned",
        }
        assert kwargs["allow_private"] is True
        assert "json_body" not in kwargs and "form_body" not in kwargs
        if method == "GET":
            assert "Authorization" not in kwargs["headers"]
    assert password not in str(observations)
    assert "session-token-never-returned" not in str(observations)
    assert PassiveConnectorType.VCENTER in passive_inventory.ADAPTERS


async def test_vcenter_restricts_origin_config_and_resources() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del kwargs
        if method == "POST":
            return JsonResponse(201, "session-token", {})
        if method == "GET":
            return JsonResponse(200, [], {})
        assert url.endswith("/api/session")
        return JsonResponse(204, {}, {})

    adapter = VcenterInventoryAdapter(sender=empty)
    for root in (
        "http://vcenter.internal.test",
        "https://vcenter.internal.test:8443",
        "https://user:pass@vcenter.internal.test",
        "https://vcenter.internal.test/sdk",
        "https://vcenter.internal.test/?operation=delete",
        "https://vcenter.internal.test/#fragment",
    ):
        connector = _connector()
        connector.base_url = root
        with pytest.raises(passive_inventory.InventoryConnectorError, match="vCenter URL"):
            await adapter.test(connector, "password", source_data=None)

    connector = _connector(include_hosts=False)
    result = await adapter.test(connector, "password", source_data=None)
    assert result["resources"] == ["virtual machines"]

    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), "password", cursor={"page": 2}, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(operation="power_on"), "password", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="include hosts"):
        await adapter.test(
            _connector(include_hosts=False, include_vms=False),
            "password",
            source_data=None,
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="password is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="colon"):
        await adapter.test(_connector(username="reader:other"), "password", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record_limit"):
        await adapter.test(_connector(record_limit=6501), "password", source_data=None)


async def test_vcenter_invalidates_session_on_provider_or_payload_failure() -> None:
    methods: list[str] = []

    async def invalid_payload(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        methods.append(method)
        if method == "POST":
            return JsonResponse(201, "temporary-session", {})
        if method == "GET":
            return JsonResponse(200, {"value": []}, {})
        return JsonResponse(204, {}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="response is invalid"):
        await VcenterInventoryAdapter(sender=invalid_payload).test(
            _connector(include_vms=False), "password", source_data=None
        )
    assert methods == ["POST", "GET", "DELETE"]

    methods.clear()

    async def provider_failure(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        methods.append(method)
        if method == "POST":
            return JsonResponse(201, "temporary-session", {})
        if method == "GET":
            raise TicketHttpError("ticket provider returned HTTP 503")
        return JsonResponse(204, {}, {})

    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="vCenter provider returned HTTP 503"
    ):
        await VcenterInventoryAdapter(sender=provider_failure).test(
            _connector(include_vms=False), "password", source_data=None
        )
    assert methods == ["POST", "GET", "DELETE"]


async def test_vcenter_rejects_unbounded_invalid_or_duplicate_inventory() -> None:
    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del kwargs
        if method == "POST":
            return JsonResponse(201, "session-token", {})
        if method == "DELETE":
            return JsonResponse(204, {}, {})
        if url.endswith("/host"):
            return JsonResponse(
                200,
                [
                    {"host": "host-1", "name": "esx01.example.test"},
                    {"host": "host-1", "name": "esx01-duplicate.example.test"},
                ],
                {},
            )
        return JsonResponse(200, [], {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate object IDs"):
        await VcenterInventoryAdapter(sender=send).test(
            _connector(include_vms=False), "password", source_data=None
        )

    async def over_limit(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        if method == "POST":
            return JsonResponse(201, "session-token", {})
        if method == "DELETE":
            return JsonResponse(204, {}, {})
        return JsonResponse(200, [{"host": "host-1", "name": "esx"}], {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="combined record limit"):
        await VcenterInventoryAdapter(sender=over_limit).test(
            _connector(record_limit=1), "password", source_data=None
        )


async def test_vcenter_rejects_invalid_custom_ca_before_authentication() -> None:
    called = False

    async def unreachable(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        nonlocal called
        called = True
        return JsonResponse(201, "session-token", {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="valid CA certificate"):
        await VcenterInventoryAdapter(sender=unreachable).test(
            _connector(
                trust_pem=(
                    "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----"
                )
            ),
            "password",
            source_data=None,
        )
    assert called is False
