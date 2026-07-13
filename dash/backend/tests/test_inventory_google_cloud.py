"""Google Cloud read-only importer contract and security coverage."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import passive_inventory
from app.services.inventory_google_cloud import GoogleCloudInventoryAdapter
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

pytestmark = pytest.mark.release_gate

PROJECT_ID = "vulna-prod-01"
SECOND_PROJECT_ID = "vulna-lab-02"
TOKEN_URI = "https://oauth2.googleapis.com/token"
COMPUTE_SCOPE = "https://www.googleapis.com/auth/compute.readonly"
SERVICE_EMAIL = f"vulna-reader@{PROJECT_ID}.iam.gserviceaccount.com"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
PRIVATE_KEY_PEM = PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def _credential(**overrides: Any) -> str:
    value = {
        "type": "service_account",
        "project_id": PROJECT_ID,
        "private_key_id": "abcdef0123456789abcdef0123456789abcdef01",
        "private_key": PRIVATE_KEY_PEM,
        "client_email": SERVICE_EMAIL,
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": TOKEN_URI,
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": (
            "https://www.googleapis.com/robot/v1/metadata/x509/"
            "vulna-reader%40vulna-prod-01.iam.gserviceaccount.com"
        ),
        "universe_domain": "googleapis.com",
        **overrides,
    }
    return json.dumps(value)


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="Google Cloud instances",
        connector_type=PassiveConnectorType.GOOGLE_CLOUD,
        config_json=config,
    )


def _instance(instance_id: str = "1234567890123456789", *, name: str = "app-01") -> dict[str, Any]:
    return {
        "id": instance_id,
        "name": name,
        "hostname": f"{name}.example.test",
        "zone": f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/zones/us-central1-a",
        "status": "RUNNING",
        "creationTimestamp": "2026-07-01T12:00:00.000-04:00",
        "machineType": (
            f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/zones/"
            "us-central1-a/machineTypes/e2-standard-4"
        ),
        "cpuPlatform": "Intel Cascade Lake",
        "canIpForward": False,
        "deletionProtection": True,
        "lastStartTimestamp": "2026-07-13T10:30:00.000-04:00",
        "networkInterfaces": [
            {
                "network": (
                    f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/global/"
                    "networks/production"
                ),
                "subnetwork": (
                    f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/regions/"
                    "us-central1/subnetworks/application"
                ),
                "networkIP": "10.10.0.4",
                "ipv6Address": "2001:db8::4",
                "accessConfigs": [{"natIP": "198.51.100.4"}],
            }
        ],
    }


async def test_google_cloud_signs_assertion_and_maps_bounded_paged_instances() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        calls.append((method, url, kwargs))
        if url == TOKEN_URI:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "gcp-token"}, {})
        query = parse_qs(urlsplit(url).query)
        if "pageToken" not in query:
            return JsonResponse(
                200,
                {
                    "items": {"zones/us-central1-a": {"instances": [_instance()]}},
                    "nextPageToken": "next-instance-page",
                },
                {},
            )
        assert query["pageToken"] == ["next-instance-page"]
        return JsonResponse(
            200,
            {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [_instance("2234567890123456789", name="db-01")]
                    }
                }
            },
            {},
        )

    secret = _credential()
    adapter = GoogleCloudInventoryAdapter(sender=send)
    tested = await adapter.test(_connector(page_size=2), secret, source_data=None)
    assert tested == {
        "records_received": 2,
        "records_visible": 2,
        "projects": 1,
        "permission": "compute.instances.list",
        "oauth_scope": COMPUTE_SCOPE,
        "read_only": True,
    }
    observations, cursor = await adapter.collect(
        _connector(page_size=2), secret, cursor={}, source_data=None
    )
    assert cursor == {}
    assert len(observations) == 2
    first = observations[0]
    assert first.source_record_id == f"gcp:instance:{PROJECT_ID}:1234567890123456789"
    assert first.identifiers == [
        {
            "type": "cloud_instance_id",
            "value": f"gcp:{PROJECT_ID}:1234567890123456789",
        },
        {"type": "fqdn", "value": "app-01.example.test"},
        {"type": "smb_name", "value": "app-01"},
        {"type": "ip_address", "value": "10.10.0.4"},
        {"type": "ip_address", "value": "2001:db8::4"},
        {"type": "ip_address", "value": "198.51.100.4"},
    ]
    assert first.attributes == {
        "canonical_name": "app-01.example.test",
        "asset_type": "virtual_machine",
        "manufacturer": "Google",
        "gcp_project_id": PROJECT_ID,
        "gcp_instance_id": "1234567890123456789",
        "gcp_instance_name": "app-01",
        "gcp_zone": "us-central1-a",
        "gcp_status": "RUNNING",
        "gcp_created_at": "2026-07-01T12:00:00.000-04:00",
        "gcp_cpu_platform": "Intel Cascade Lake",
        "gcp_last_started_at": "2026-07-13T10:30:00.000-04:00",
        "gcp_machine_type": "e2-standard-4",
        "gcp_can_ip_forward": False,
        "gcp_deletion_protection": True,
        "gcp_networks": ["production"],
    }
    token_call = calls[0]
    assert token_call[0:2] == ("POST", TOKEN_URI)
    token_body = token_call[2]["form_body"]
    assert token_body["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assertion = token_body["assertion"]
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "RS256"
    assert header["kid"] == "abcdef0123456789abcdef0123456789abcdef01"
    claims = jwt.decode(assertion, PUBLIC_KEY, algorithms=["RS256"], audience=TOKEN_URI)
    assert claims["iss"] == SERVICE_EMAIL
    assert claims["scope"] == COMPUTE_SCOPE
    assert 3_200 <= claims["exp"] - claims["iat"] <= 3_300
    compute_calls = [call for call in calls if call[1].startswith("https://compute.googleapis.com")]
    for call in compute_calls:
        assert call[0] == "GET"
        assert call[2]["headers"]["Authorization"] == "Bearer gcp-token"
        assert call[2]["allow_private"] is False
        parts = urlsplit(call[1])
        assert parts.path == f"/compute/v1/projects/{PROJECT_ID}/aggregated/instances"
        query = parse_qs(parts.query)
        assert query["maxResults"] == ["2"]
        assert query["returnPartialSuccess"] == ["true"]
        fields = query["fields"][0]
        assert "networkInterfaces" in fields
        for excluded in ("metadata", "serviceAccounts", "disks", "encryption", "labels"):
            assert excluded not in fields
    serialized = json.dumps([tested, cursor, [item.__dict__ for item in observations]], default=str)
    assert secret not in serialized
    assert PRIVATE_KEY_PEM not in serialized
    assert assertion not in serialized
    assert "gcp-token" not in serialized


async def test_google_cloud_supports_explicit_multiple_projects_without_endpoint_control() -> None:
    paths: list[str] = []

    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if url == TOKEN_URI:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        paths.append(urlsplit(url).path)
        return JsonResponse(200, {"items": {}}, {})

    result = await GoogleCloudInventoryAdapter(sender=send).test(
        _connector(project_ids=[PROJECT_ID, SECOND_PROJECT_ID]),
        _credential(),
        source_data=None,
    )
    assert result["projects"] == 2
    assert paths == [
        f"/compute/v1/projects/{PROJECT_ID}/aggregated/instances",
        f"/compute/v1/projects/{SECOND_PROJECT_ID}/aggregated/instances",
    ]


async def test_google_cloud_rejects_mutable_endpoints_and_invalid_credentials() -> None:
    async def unexpected(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        raise AssertionError("request must not be sent")

    adapter = GoogleCloudInventoryAdapter(sender=unexpected)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(
            _connector(), _credential(), cursor={"pageToken": "state"}, source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="JSON is required"):
        await adapter.test(_connector(), None, source_data=None)
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="supported service account"
    ):
        await adapter.test(
            _connector(), _credential(token_uri="https://attacker.test/token"), source_data=None
        )
    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="supported service account"
    ):
        await adapter.test(_connector(), _credential(type="external_account"), source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="universe"):
        await adapter.test(
            _connector(), _credential(universe_domain="attacker.test"), source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unsupported fields"):
        value = json.loads(_credential())
        value["credential_source"] = {"url": "http://169.254.169.254/"}
        await adapter.test(_connector(), json.dumps(value), source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="unknown fields"):
        await adapter.test(
            _connector(compute_host="attacker.test"), _credential(), source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicates"):
        await adapter.test(
            _connector(project_ids=[PROJECT_ID, PROJECT_ID]), _credential(), source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="page_size"):
        await adapter.test(_connector(page_size=501), _credential(), source_data=None)
    connector = _connector()
    connector.base_url = "https://compute.attacker.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="base URL"):
        await adapter.test(connector, _credential(), source_data=None)


async def test_google_cloud_requires_a_strong_rsa_key() -> None:
    weak_key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=1_024,  # noqa: S505 - rejection fixture
    )
    weak_pem = weak_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(passive_inventory.InventoryConnectorError, match="at least 2048"):
        await GoogleCloudInventoryAdapter().test(
            _connector(), _credential(private_key=weak_pem), source_data=None
        )


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({"items": {}, "unreachables": ["zones/us-central1-b"]}, "unreachable"),
        (
            {"items": {"zones/us-central1-a": {"warning": {"code": "PARTIAL_FAILURE"}}}},
            "partial scope",
        ),
        ({"items": [], "nextPageToken": None}, "scoped results"),
        ({"items": {}, "nextPageToken": ""}, "continuation token"),
    ],
)
async def test_google_cloud_fails_closed_on_partial_or_invalid_pages(
    response: dict[str, Any], message: str
) -> None:
    async def send(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if url == TOKEN_URI:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        return JsonResponse(200, response, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match=message):
        await GoogleCloudInventoryAdapter(sender=send).test(
            _connector(), _credential(), source_data=None
        )


async def test_google_cloud_rejects_repeated_tokens_and_cross_scope_instances() -> None:
    calls = 0

    async def repeated(method: str, url: str, **kwargs: Any) -> JsonResponse:
        nonlocal calls
        del method, kwargs
        if url == TOKEN_URI:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        calls += 1
        return JsonResponse(200, {"items": {}, "nextPageToken": "same-token"}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="repeated"):
        await GoogleCloudInventoryAdapter(sender=repeated).test(
            _connector(), _credential(), source_data=None
        )
    assert calls == 2

    async def crossed(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, kwargs
        if url == TOKEN_URI:
            return JsonResponse(200, {"token_type": "Bearer", "access_token": "token"}, {})
        item = _instance()
        item["zone"] = (
            f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/zones/us-east1-b"
        )
        return JsonResponse(200, {"items": {"zones/us-central1-a": {"instances": [item]}}}, {})

    with pytest.raises(passive_inventory.InventoryConnectorError, match="crossed result scopes"):
        await GoogleCloudInventoryAdapter(sender=crossed).test(
            _connector(), _credential(), source_data=None
        )


async def test_google_cloud_provider_errors_do_not_echo_credentials() -> None:
    async def fail(method: str, url: str, **kwargs: Any) -> JsonResponse:
        del method, url, kwargs
        raise TicketHttpError("ticket provider returned HTTP 403")

    secret = _credential()
    with pytest.raises(passive_inventory.InventoryConnectorError) as raised:
        await GoogleCloudInventoryAdapter(sender=fail).test(_connector(), secret, source_data=None)
    assert "Google Cloud authentication failed" in str(raised.value)
    assert PRIVATE_KEY_PEM not in str(raised.value)
    assert secret not in str(raised.value)
