"""XCP-ng/Xen Orchestra read-only inventory adapter security coverage."""

from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_xcpng import XcpNgInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError

pytestmark = pytest.mark.release_gate

CONNECTOR_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
HOST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
VM_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
POOL_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
TOKEN = "XenOrchestraToken_0123456789abcdef"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        id=CONNECTOR_ID,
        name="XCP-ng inventory",
        connector_type=PassiveConnectorType.XCP_NG,
        base_url="https://xo.internal.test",
        config_json=config,
    )


async def test_xcpng_maps_hosts_and_vms_with_token_cookie() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if urlsplit(url).path.endswith("/hosts"):
            return JsonResponse(
                200,
                [
                    {
                        "id": HOST_ID,
                        "uuid": HOST_ID,
                        "name_label": "Primary hypervisor",
                        "hostname": "xcp01.example.test",
                        "address": "192.0.2.10",
                        "power_state": "Running",
                        "enabled": True,
                        "version": "8.3.0",
                        "build": "release/ely8.3-1.0",
                        "productBrand": "XCP-ng",
                        "cpus": {"cores": 16, "sockets": 2},
                        "memory": {"size": 68_719_476_736, "usage": 8_589_934_592},
                        "tags": ["production", "east"],
                        "$pool": POOL_ID,
                        "href": f"/rest/v0/hosts/{HOST_ID}",
                    }
                ],
                {},
            )
        return JsonResponse(
            200,
            [
                {
                    "id": VM_ID,
                    "uuid": VM_ID,
                    "name_label": "app01.example.test",
                    "power_state": "Running",
                    "addresses": {
                        "0/ipv4/0": "192.0.2.50",
                        "0/ipv6/0": "2001:db8::50",
                    },
                    "mainIpAddress": "192.0.2.50",
                    "CPUs": {"number": 4},
                    "memory": {"size": 8_589_934_592},
                    "os_version": {"name": "Debian GNU/Linux 12"},
                    "tags": ["linux", "production"],
                    "virtualizationMode": "hvm",
                    "$container": HOST_ID,
                    "$pool": POOL_ID,
                    "startTime": 1_752_422_400,
                    "href": f"/rest/v0/vms/{VM_ID}",
                }
            ],
            {},
        )

    adapter = XcpNgInventoryAdapter(sender=send)
    connector = _connector(allow_private=True)
    tested = await adapter.test(connector, TOKEN, source_data=None)
    assert tested == {
        "records_received": 2,
        "records_visible": 2,
        "hosts_received": 1,
        "virtual_machines_received": 1,
        "resources": ["hosts", "virtual machines"],
        "read_only": True,
    }
    assert TOKEN not in json.dumps(tested)

    calls.clear()
    observations, cursor = await adapter.collect(connector, TOKEN, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 2
    host = observations[0]
    assert host.source_record_id == f"xcp_ng:host:{HOST_ID}"
    assert host.identifiers == [
        {"type": "cloud_instance_id", "value": f"xcp-ng-host:{HOST_ID}"},
        {
            "type": "cloud_instance_id",
            "value": f"xen-orchestra:{CONNECTOR_ID}:host:{HOST_ID}",
        },
        {"type": "fqdn", "value": "xcp01.example.test"},
        {"type": "smb_name", "value": "xcp01"},
        {"type": "ip_address", "value": "192.0.2.10"},
    ]
    assert host.attributes == {
        "canonical_name": "xcp01.example.test",
        "asset_type": "hypervisor",
        "operating_system": "XCP-ng",
        "xcp_ng_object_type": "host",
        "xcp_ng_uuid": HOST_ID,
        "xcp_ng_power_state": "Running",
        "xcp_ng_version": "8.3.0",
        "xcp_ng_build": "release/ely8.3-1.0",
        "xcp_ng_product_brand": "XCP-ng",
        "xcp_ng_enabled": True,
        "xcp_ng_pool_id": POOL_ID,
        "cpu_count": 16,
        "cpu_socket_count": 2,
        "memory_size_bytes": 68_719_476_736,
        "memory_usage_bytes": 8_589_934_592,
        "tags": ["production", "east"],
    }
    vm = observations[1]
    assert vm.source_record_id == f"xcp_ng:vm:{VM_ID}"
    assert vm.identifiers == [
        {"type": "cloud_instance_id", "value": f"xcp-ng-vm:{VM_ID}"},
        {
            "type": "cloud_instance_id",
            "value": f"xen-orchestra:{CONNECTOR_ID}:vm:{VM_ID}",
        },
        {"type": "fqdn", "value": "app01.example.test"},
        {"type": "smb_name", "value": "app01"},
        {"type": "ip_address", "value": "192.0.2.50"},
        {"type": "ip_address", "value": "2001:db8::50"},
    ]
    assert vm.attributes == {
        "canonical_name": "app01.example.test",
        "asset_type": "virtual_machine",
        "xcp_ng_object_type": "virtual_machine",
        "xcp_ng_uuid": VM_ID,
        "xcp_ng_power_state": "Running",
        "virtualization_mode": "hvm",
        "xcp_ng_pool_id": POOL_ID,
        "xcp_ng_host_id": HOST_ID,
        "cpu_count": 4,
        "memory_size_bytes": 8_589_934_592,
        "operating_system": "Debian GNU/Linux 12",
        "start_time": 1_752_422_400,
        "tags": ["linux", "production"],
    }

    assert len(calls) == 2
    expected_fields = {
        "hosts": {
            "id",
            "uuid",
            "name_label",
            "hostname",
            "address",
            "power_state",
            "enabled",
            "version",
            "build",
            "productBrand",
            "cpus",
            "memory",
            "tags",
            "$pool",
        },
        "vms": {
            "id",
            "uuid",
            "name_label",
            "power_state",
            "addresses",
            "mainIpAddress",
            "CPUs",
            "memory",
            "os_version",
            "tags",
            "virtualizationMode",
            "$container",
            "$pool",
            "startTime",
        },
    }
    for method, url, kwargs in calls:
        parts = urlsplit(url)
        collection = parts.path.rsplit("/", 1)[-1]
        query = parse_qs(parts.query)
        assert method == "GET"
        assert parts.scheme == "https" and parts.netloc == "xo.internal.test"
        assert parts.path == f"/rest/v0/{collection}"
        assert set(query["fields"][0].split(",")) == expected_fields[collection]
        assert query["limit"] == ["10001"]
        assert kwargs["headers"] == {
            "Accept": "application/json",
            "Cookie": f"authenticationToken={TOKEN}",
        }
        assert kwargs["allow_private"] is True
        assert "json_body" not in kwargs and "form_body" not in kwargs
    assert TOKEN not in str(observations)
    assert PassiveConnectorType.XCP_NG in passive_inventory.ADAPTERS


async def test_xcpng_restricts_origin_config_and_resources() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, [], {})

    adapter = XcpNgInventoryAdapter(sender=empty)
    for root in (
        "http://xo.internal.test",
        "https://xo.internal.test:8443",
        "https://user:pass@xo.internal.test",
        "https://xo.internal.test/rest/v0",
        "https://xo.internal.test/?fields=id",
        "https://xo.internal.test/#fragment",
    ):
        connector = _connector()
        connector.base_url = root
        with pytest.raises(passive_inventory.InventoryConnectorError, match="Xen Orchestra URL"):
            await adapter.test(connector, TOKEN, source_data=None)

    result = await adapter.test(_connector(include_hosts=False), TOKEN, source_data=None)
    assert result["resources"] == ["virtual machines"]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), TOKEN, cursor={"page": 2}, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(operation="start"), TOKEN, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="include hosts"):
        await adapter.test(
            _connector(include_hosts=False, include_vms=False), TOKEN, source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="token is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="token is required"):
        await adapter.test(_connector(), "bad;token", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record_limit"):
        await adapter.test(_connector(record_limit=10_001), TOKEN, source_data=None)


async def test_xcpng_rejects_invalid_duplicate_or_unbounded_payloads() -> None:
    responses: list[Any] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(200, responses.pop(0), {})

    adapter = XcpNgInventoryAdapter(sender=send)
    responses[:] = [{"data": []}]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="response is invalid"):
        await adapter.test(_connector(include_vms=False), TOKEN, source_data=None)

    host = {
        "id": HOST_ID,
        "uuid": HOST_ID,
        "name_label": "xcp01",
    }
    responses[:] = [[host, host]]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate object IDs"):
        await adapter.test(_connector(include_vms=False), TOKEN, source_data=None)

    responses[:] = [
        [host],
        [
            {
                "id": VM_ID,
                "uuid": VM_ID,
                "name_label": "vm01",
            }
        ],
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="combined record limit"):
        await adapter.test(_connector(record_limit=1), TOKEN, source_data=None)

    responses[:] = [
        [
            {
                "id": HOST_ID,
                "uuid": VM_ID,
                "name_label": "xcp01",
            }
        ]
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="inconsistent"):
        await adapter.test(_connector(include_vms=False), TOKEN, source_data=None)

    responses[:] = [
        [
            {
                "id": VM_ID,
                "uuid": VM_ID,
                "name_label": "vm01",
                "addresses": {"0/ipv4/0": "not-an-address"},
            }
        ]
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="not an IP address"):
        await adapter.test(_connector(include_hosts=False), TOKEN, source_data=None)

    responses[:] = [
        [
            {
                "id": VM_ID,
                "uuid": VM_ID,
                "name_label": "vm01",
                "addresses": {f"0/ipv6/{index}": f"2001:db8::{index + 1}" for index in range(47)},
            }
        ]
    ]
    with pytest.raises(passive_inventory.InventoryConnectorError, match="network identifiers"):
        await adapter.test(_connector(include_hosts=False), TOKEN, source_data=None)


async def test_xcpng_sentinel_limit_detects_truncated_collection() -> None:
    host = {"id": HOST_ID, "uuid": HOST_ID, "name_label": "xcp01"}
    other_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        return JsonResponse(
            200,
            [host, {"id": other_id, "uuid": other_id, "name_label": "xcp02"}],
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="combined record limit"):
        await XcpNgInventoryAdapter(sender=send).test(
            _connector(include_vms=False, record_limit=1), TOKEN, source_data=None
        )


async def test_xcpng_redacts_transport_errors_and_rejects_invalid_ca() -> None:
    async def leaking(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        raise TicketHttpError(f"ticket provider rejected {TOKEN}")

    with pytest.raises(passive_inventory.InventoryConnectorError) as caught:
        await XcpNgInventoryAdapter(sender=leaking).test(
            _connector(include_vms=False), TOKEN, source_data=None
        )
    assert TOKEN not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)

    called = False

    async def unreachable(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        nonlocal called
        called = True
        return JsonResponse(200, [], {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="valid CA certificate"):
        await XcpNgInventoryAdapter(sender=unreachable).test(
            _connector(
                include_vms=False,
                trust_pem=(
                    "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----"
                ),
            ),
            TOKEN,
            source_data=None,
        )
    assert called is False
