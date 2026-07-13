"""Microsoft Azure read-only importer contract and security coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_azure import AzureInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError

pytestmark = pytest.mark.release_gate

TENANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
CLIENT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SUBSCRIPTION_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
VM_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
VM_ID_TWO = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
VMSS_VM_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="Azure virtual machines",
        connector_type=PassiveConnectorType.AZURE,
        config_json={
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "subscription_ids": [SUBSCRIPTION_ID],
            **config,
        },
    )


def _vm(vm_id: str = VM_ID, *, name: str = "app-01") -> dict[str, Any]:
    return {
        "id": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/Production/"
            f"providers/Microsoft.Compute/virtualMachines/{name}"
        ),
        "name": name,
        "subscriptionId": SUBSCRIPTION_ID,
        "resourceGroup": "Production",
        "location": "eastus",
        "vmId": vm_id,
        "computerName": f"{name}.example.test",
        "osType": "Linux",
        "vmSize": "Standard_D2s_v5",
        "provisioningState": "Succeeded",
        "powerState": "PowerState/running",
    }


async def test_azure_maps_paged_vms_and_scale_set_instances_without_secrets() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if "/oauth2/v2.0/token" in url:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "arm-token"}, {})
        body = kwargs["json_body"]
        if body["query"].startswith("Resources\n"):
            if "$skipToken" not in body["options"]:
                return JsonResponse(
                    200,
                    {
                        "count": 1,
                        "data": [_vm()],
                        "$skipToken": "next-vm-page",
                        "resultTruncated": "true",
                    },
                    {},
                )
            assert body["options"]["$skipToken"] == "next-vm-page"
            return JsonResponse(
                200,
                {
                    "count": 1,
                    "data": [_vm(VM_ID_TWO, name="db-01")],
                    "resultTruncated": "false",
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "count": 1,
                "data": [
                    {
                        "id": (
                            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/Production/"
                            "providers/Microsoft.Compute/virtualMachineScaleSets/workers/"
                            "virtualMachines/3"
                        ),
                        "name": "workers_3",
                        "subscriptionId": SUBSCRIPTION_ID,
                        "resourceGroup": "Production",
                        "location": "eastus2",
                        "vmId": VMSS_VM_ID,
                        "computerName": "worker-03",
                        "osType": "Linux",
                        "vmSize": "Standard_D4s_v5",
                        "provisioningState": "Succeeded",
                        "powerState": "PowerState/running",
                    }
                ],
                "resultTruncated": False,
            },
            {},
        )

    client_secret = "azure-client-secret-never-returned"
    adapter = AzureInventoryAdapter(sender=send)
    tested = await adapter.test(_connector(page_size=2), client_secret, source_data=None)
    assert tested == {
        "records_received": 3,
        "records_visible": 3,
        "subscriptions": 1,
        "cloud": "global",
        "resources": ["virtual machines", "scale set virtual machines"],
        "permission": "Microsoft.ResourceGraph/resources/read",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(
        _connector(page_size=2), client_secret, cursor={}, source_data=None
    )
    assert cursor == {}
    assert len(observations) == 3
    first = observations[0]
    assert first.source_record_id == f"azure:vm:{SUBSCRIPTION_ID}:{VM_ID}"
    assert first.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"azure:{TENANT_ID}:{SUBSCRIPTION_ID}:{VM_ID}",
        },
        {"type": "fqdn", "value": "app-01.example.test"},
        {"type": "smb_name", "value": "app-01"},
    ]
    assert first.attributes == {
        "canonical_name": "app-01.example.test",
        "asset_type": "virtual_machine",
        "manufacturer": "Microsoft",
        "azure_tenant_id": TENANT_ID,
        "azure_subscription_id": SUBSCRIPTION_ID,
        "azure_vm_id": VM_ID,
        "azure_resource_id": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/Production/"
            "providers/Microsoft.Compute/virtualMachines/app-01"
        ),
        "azure_resource_kind": "vm",
        "azure_resource_group": "Production",
        "azure_location": "eastus",
        "operating_system": "Linux",
        "azure_vm_size": "Standard_D2s_v5",
        "azure_provisioning_state": "Succeeded",
        "azure_power_state": "PowerState/running",
    }
    assert observations[2].source_record_id == (f"azure:vmss-vm:{SUBSCRIPTION_ID}:{VMSS_VM_ID}")
    token_call = calls[0]
    assert token_call[0:2] == (
        "POST",
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
    )
    assert token_call[2]["form_body"] == {
        "client_id": CLIENT_ID,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
    }
    query_calls = [call for call in calls if "Microsoft.ResourceGraph/resources" in call[1]]
    assert all(call[0] == "POST" for call in query_calls)
    assert all(call[1].endswith("?api-version=2024-04-01") for call in query_calls)
    assert all(call[2]["allow_private"] is False for call in calls)
    assert all(
        call[2]["headers"].get("Authorization") == "Bearer arm-token" for call in query_calls
    )
    for call in query_calls:
        body = call[2]["json_body"]
        assert body["subscriptions"] == [SUBSCRIPTION_ID]
        assert body["options"]["resultFormat"] == "objectArray"
        assert "project id=tostring(id)" in body["query"]
        assert "customData" not in body["query"]
        assert "tags" not in body["query"]
    serialized = json.dumps([tested, cursor, [item.__dict__ for item in observations]], default=str)
    assert client_secret not in serialized
    assert "arm-token" not in serialized


@pytest.mark.parametrize(
    ("cloud", "authority", "manager", "scope"),
    [
        (
            "global",
            "login.microsoftonline.com",
            "management.azure.com",
            "https://management.azure.com/.default",
        ),
        (
            "us_government",
            "login.microsoftonline.us",
            "management.usgovcloudapi.net",
            "https://management.usgovcloudapi.net/.default",
        ),
        (
            "china",
            "login.chinacloudapi.cn",
            "management.chinacloudapi.cn",
            "https://management.chinacloudapi.cn/.default",
        ),
    ],
)
async def test_azure_cloud_endpoints_are_code_defined(
    cloud: str, authority: str, manager: str, scope: str
) -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if "/oauth2/v2.0/token" in url:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(200, {"count": 0, "data": [], "resultTruncated": False}, {})

    result = await AzureInventoryAdapter(sender=send).test(
        _connector(cloud=cloud, include_scale_set_instances=False),
        "one-way-secret",
        source_data=None,
    )
    assert result["cloud"] == cloud
    assert calls[0][1] == f"https://{authority}/{TENANT_ID}/oauth2/v2.0/token"
    assert calls[0][2]["form_body"]["scope"] == scope
    assert calls[1][1].startswith(f"https://{manager}/providers/")


async def test_azure_rejects_mutable_endpoints_and_unbounded_config() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        raise AssertionError("unexpected method")

    adapter = AzureInventoryAdapter(sender=empty)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(_connector(), "secret", cursor={"next": "state"}, source_data=None)
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="client secret is required"
    ):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="tenant_id must be a UUID"):
        await adapter.test(_connector(tenant_id="common"), "secret", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cloud must be"):
        await adapter.test(_connector(cloud="https://attacker.test"), "secret", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(query="Resources | take 1"), "secret", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicates"):
        await adapter.test(
            _connector(subscription_ids=[SUBSCRIPTION_ID, SUBSCRIPTION_ID]),
            "secret",
            source_data=None,
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record_limit"):
        await adapter.test(_connector(record_limit=10_001), "secret", source_data=None)
    connector = _connector()
    connector.base_url = "https://management.attacker.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="base URL"):
        await adapter.test(connector, "secret", source_data=None)


@pytest.mark.parametrize(
    "response",
    [
        {"count": 0, "data": [], "resultTruncated": True},
        {"count": 2, "data": [], "resultTruncated": False},
        {"count": 0, "data": [], "$skipToken": "", "resultTruncated": True},
    ],
)
async def test_azure_fails_closed_on_invalid_or_truncated_pages(response: dict[str, Any]) -> None:
    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del kwargs
        if "/oauth2/v2.0/token" in url:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        assert method == "POST"
        return JsonResponse(200, response, {})

    with pytest.raises(passive_inventory.InventoryConnectorError):
        await AzureInventoryAdapter(sender=send).test(
            _connector(include_scale_set_instances=False), "secret", source_data=None
        )


async def test_azure_rejects_repeated_tokens_and_cross_subscription_records() -> None:
    calls = 0

    async def repeated(method: str, url: str, **kwargs: Any) -> JsonResponse:
        nonlocal calls
        del method, kwargs
        if "/oauth2/v2.0/token" in url:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        calls += 1
        return JsonResponse(
            200,
            {
                "count": 0,
                "data": [],
                "$skipToken": "same-token",
                "resultTruncated": True,
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="repeated"):
        await AzureInventoryAdapter(sender=repeated).test(
            _connector(include_scale_set_instances=False), "secret", source_data=None
        )
    assert calls == 2

    async def crossed(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if "/oauth2/v2.0/token" in url:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        item = _vm()
        item["subscriptionId"] = "11111111-1111-4111-8111-111111111111"
        return JsonResponse(200, {"count": 1, "data": [item], "resultTruncated": False}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="crossed subscriptions"):
        await AzureInventoryAdapter(sender=crossed).test(
            _connector(include_scale_set_instances=False), "secret", source_data=None
        )


async def test_azure_provider_errors_are_bounded_and_do_not_echo_credentials() -> None:
    async def fail(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        raise TicketHttpError("ticket provider returned HTTP 403")

    secret = "credential-that-must-not-return"
    with pytest.raises(passive_inventory.InventoryConnectorError) as raised:
        await AzureInventoryAdapter(sender=fail).test(_connector(), secret, source_data=None)
    assert "Azure authentication failed" in str(raised.value)
    assert secret not in str(raised.value)
