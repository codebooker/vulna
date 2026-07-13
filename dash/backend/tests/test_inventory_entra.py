"""Microsoft Entra read-only importer contract and security coverage."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import notifications, passive_inventory
from app.services.inventory_entra import EntraInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

pytestmark = pytest.mark.release_gate

TENANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
CLIENT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
DEVICE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
OBJECT_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="Microsoft Entra devices",
        connector_type=PassiveConnectorType.ENTRA,
        config_json={"tenant_id": TENANT_ID, "client_id": CLIENT_ID, **config},
    )


async def test_entra_maps_bounded_paged_devices_and_excludes_disabled() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "graph-token"}, {})
        if "$skiptoken=" in url:
            return JsonResponse(
                200,
                {
                    "value": [
                        {
                            "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                            "deviceId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                            "accountEnabled": True,
                            "displayName": "Linux-01",
                            "operatingSystem": "Linux",
                        }
                    ]
                },
                {},
            )
        return JsonResponse(
            200,
            {
                "value": [
                    {
                        "id": OBJECT_ID,
                        "deviceId": DEVICE_ID,
                        "accountEnabled": True,
                        "displayName": "APP-01.Example.Test.",
                        "approximateLastSignInDateTime": "2026-07-12T20:30:00Z",
                        "deviceOwnership": "company",
                        "isCompliant": True,
                        "isManaged": True,
                        "manufacturer": "Contoso",
                        "model": "Virtual Machine",
                        "operatingSystem": "Windows",
                        "operatingSystemVersion": "10.0.26100",
                        "registrationDateTime": "2026-01-02T03:04:05Z",
                        "systemLabels": ["M365Managed"],
                        "trustType": "AzureAd",
                    },
                    {
                        "id": "11111111-1111-4111-8111-111111111111",
                        "deviceId": "22222222-2222-4222-8222-222222222222",
                        "accountEnabled": False,
                        "displayName": "OLD-01",
                    },
                ],
                "@odata.nextLink": (
                    "https://graph.microsoft.com/v1.0/devices?$skiptoken=next-page"
                ),
            },
            {},
        )

    connector = _connector(page_size=2, record_limit=10)
    client_secret = "client-secret-never-returned"
    adapter = EntraInventoryAdapter(sender=send)
    tested = await adapter.test(connector, client_secret, source_data=None)
    assert tested == {
        "records_received": 3,
        "records_visible": 2,
        "cloud": "global",
        "permission": "Device.Read.All",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(
        connector, client_secret, cursor={}, source_data=None
    )
    assert cursor == {}
    assert len(observations) == 2
    windows = observations[0]
    assert windows.source_record_id == f"entra:{OBJECT_ID}"
    assert windows.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"entra:{TENANT_ID}:{DEVICE_ID}",
        },
        {"type": "fqdn", "value": "app-01.example.test"},
        {"type": "smb_name", "value": "app-01"},
    ]
    assert windows.attributes == {
        "canonical_name": "app-01.example.test",
        "entra_object_id": OBJECT_ID,
        "entra_tenant_id": TENANT_ID,
        "entra_account_enabled": True,
        "entra_device_id": DEVICE_ID,
        "entra_approximate_last_sign_in_at": "2026-07-12T20:30:00Z",
        "entra_device_ownership": "company",
        "manufacturer": "Contoso",
        "model": "Virtual Machine",
        "operating_system": "Windows",
        "operating_system_version": "10.0.26100",
        "entra_registration_at": "2026-01-02T03:04:05Z",
        "entra_trust_type": "AzureAd",
        "entra_is_compliant": True,
        "entra_is_managed": True,
        "entra_system_labels": ["M365Managed"],
    }
    token_call, first_page_call, next_page_call = calls[:3]
    assert token_call[0:2] == (
        "POST",
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
    )
    assert token_call[2]["form_body"] == {
        "client_id": CLIENT_ID,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    assert first_page_call[0] == "GET"
    assert first_page_call[1].startswith("https://graph.microsoft.com/v1.0/devices?")
    first_query = parse_qs(first_page_call[1].split("?", 1)[1])
    assert set(first_query) == {"$select", "$top"}
    assert first_query["$top"] == ["2"]
    assert "id" in first_query["$select"][0].split(",")
    assert first_page_call[2]["headers"]["Authorization"] == "Bearer graph-token"
    assert next_page_call[1].endswith("?$skiptoken=next-page")
    assert client_secret not in json.dumps(tested)
    assert client_secret not in json.dumps(cursor)
    assert client_secret not in str(observations)
    assert PassiveConnectorType.ENTRA in passive_inventory.ADAPTERS


@pytest.mark.parametrize(
    ("cloud", "authority", "graph"),
    [
        ("global", "login.microsoftonline.com", "graph.microsoft.com"),
        ("us_government", "login.microsoftonline.us", "graph.microsoft.us"),
        ("us_government_dod", "login.microsoftonline.us", "dod-graph.microsoft.us"),
        ("china", "login.chinacloudapi.cn", "microsoftgraph.chinacloudapi.cn"),
    ],
)
async def test_entra_cloud_endpoints_are_code_defined(
    cloud: str, authority: str, graph: str
) -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(200, {"value": []}, {})

    result = await EntraInventoryAdapter(sender=send).test(
        _connector(cloud=cloud), "one-way-client-secret", source_data=None
    )
    assert result["cloud"] == cloud
    assert calls[0][1] == f"https://{authority}/{TENANT_ID}/oauth2/v2.0/token"
    assert calls[0][2]["form_body"]["scope"] == f"https://{graph}/.default"
    assert calls[1][1].startswith(f"https://{graph}/v1.0/devices?")
    assert calls[0][2]["allow_private"] is False
    assert calls[1][2]["allow_private"] is False


async def test_entra_rejects_mutable_authority_query_and_unbounded_state() -> None:
    async def empty(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(200, {"value": []}, {})

    adapter = EntraInventoryAdapter(sender=empty)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(
            _connector(), "secret", cursor={"next": "provider-state"}, source_data=None
        )
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="client secret is required"
    ):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="tenant_id must be a UUID"):
        await adapter.test(_connector(tenant_id="common"), "secret", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cloud must be"):
        await adapter.test(
            _connector(cloud="https://graph.attacker.test"), "secret", source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(_connector(graph_host="graph.attacker.test"), "secret", source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record_limit"):
        await adapter.test(_connector(record_limit=10_001), "secret", source_data=None)
    connector = _connector()
    connector.base_url = "https://graph.attacker.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="base URL"):
        await adapter.test(connector, "secret", source_data=None)

    async def malicious_next(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(
            200,
            {
                "value": [],
                "@odata.nextLink": "https://graph.attacker.test/v1.0/devices?$skiptoken=stolen",
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="fixed endpoint"):
        await EntraInventoryAdapter(sender=malicious_next).test(
            _connector(), "secret", source_data=None
        )

    async def injected_query(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del url, kwargs
        if method == "POST":
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(
            200,
            {
                "value": [],
                "@odata.nextLink": (
                    "https://graph.microsoft.com/v1.0/devices?$filter=accountEnabled+eq+true"
                ),
            },
            {},
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="query is not allowed"):
        await EntraInventoryAdapter(sender=injected_query).test(
            _connector(), "secret", source_data=None
        )


async def test_form_transport_is_pinned_and_rejects_ambiguous_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers["host"]
        seen["content_type"] = request.headers["content-type"]
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, **_kwargs: ("login.microsoftonline.com", "203.0.113.10"),
    )
    response = await request_json(
        "POST",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        headers={"Accept": "application/json"},
        form_body={"grant_type": "client_credentials", "scope": "graph/.default"},
        transport=httpx.MockTransport(handler),
    )
    assert response.data == {"ok": True}
    assert seen == {
        "url": "https://203.0.113.10/tenant/oauth2/v2.0/token",
        "host": "login.microsoftonline.com",
        "content_type": "application/x-www-form-urlencoded",
        "body": "grant_type=client_credentials&scope=graph%2F.default",
    }
    with pytest.raises(TicketHttpError, match="both JSON and form"):
        await request_json(
            "POST",
            "https://login.microsoftonline.com/token",
            headers={},
            json_body={"one": "body"},
            form_body={"two": "bodies"},
        )
