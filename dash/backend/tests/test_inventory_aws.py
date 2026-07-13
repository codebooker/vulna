"""AWS EC2 read-only importer contract and security coverage."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import notifications, passive_inventory
from app.services.inventory_aws import (
    AwsInventoryAdapter,
    _AwsResponse,
    _AwsTransportError,
    _post_xml,
)

pytestmark = pytest.mark.release_gate

ACCOUNT_ID = "123456789012"
ACCESS_KEY_ID = "ASIAIOSFODNN7EXAMPLE"
SECRET_ACCESS_KEY = "secret-access-key-never-returned-0123456789"
SESSION_TOKEN = "session-token-never-returned"


def _secret(
    *,
    access_key_id: str = ACCESS_KEY_ID,
    secret_access_key: str = SECRET_ACCESS_KEY,
    session_token: str | None = SESSION_TOKEN,
) -> str:
    value = {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        **({"session_token": session_token} if session_token is not None else {}),
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _connector(**config: Any) -> InventoryConnector:
    return InventoryConnector(
        name="AWS EC2 inventory",
        connector_type=PassiveConnectorType.AWS,
        config_json={"partition": "aws", "regions": ["us-east-1"], **config},
    )


def _identity_xml(*, partition: str = "aws", account_id: str = ACCOUNT_ID) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:{partition}:sts::{account_id}:assumed-role/VulnaInventory/session</Arn>
    <UserId>AROATEST:session</UserId>
    <Account>{account_id}</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>request-id</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>""".encode()


def _instance(
    instance_id: str,
    *,
    state: str = "running",
    name: str = "web-01",
    extra_tags: str = "",
) -> str:
    return f"""
<item>
  <instanceId>{instance_id}</instanceId>
  <imageId>ami-0123456789abcdef0</imageId>
  <instanceState><code>16</code><name>{state}</name></instanceState>
  <privateDnsName>ip-10-0-0-10.ec2.internal</privateDnsName>
  <dnsName>ec2-203-0-113-10.compute.amazonaws.com</dnsName>
  <instanceType>t3.small</instanceType>
  <launchTime>2026-07-13T12:00:00Z</launchTime>
  <placement><availabilityZone>us-east-1a</availabilityZone><tenancy>default</tenancy></placement>
  <subnetId>subnet-0123456789abcdef0</subnetId>
  <vpcId>vpc-0123456789abcdef0</vpcId>
  <privateIpAddress>10.0.0.10</privateIpAddress>
  <ipAddress>203.0.113.10</ipAddress>
  <architecture>x86_64</architecture>
  <virtualizationType>hvm</virtualizationType>
  <hypervisor>xen</hypervisor>
  <platformDetails>Linux/UNIX</platformDetails>
  <tagSet>
    <item><key>Name</key><value>{name}</value></item>
    <item><key>Owner</key><value>platform</value></item>
    {extra_tags}
  </tagSet>
</item>"""


def _instances_xml(
    *instances: str,
    owner_id: str = ACCOUNT_ID,
    next_token: str | None = None,
) -> bytes:
    reservation = (
        f"<item><ownerId>{owner_id}</ownerId><instancesSet>{''.join(instances)}</instancesSet></item>"
        if instances
        else ""
    )
    token = f"<nextToken>{next_token}</nextToken>" if next_token is not None else ""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>request-id</requestId>
  <reservationSet>{reservation}</reservationSet>
  {token}
</DescribeInstancesResponse>""".encode()


async def test_aws_maps_signed_paged_instances_and_never_returns_credentials() -> None:
    calls: list[tuple[str, dict[str, str], bytes, int]] = []

    async def send(
        url: str, *, headers: dict[str, str], body: bytes, timeout_seconds: int
    ) -> _AwsResponse:
        calls.append((url, headers, body, timeout_seconds))
        parameters = parse_qs(body.decode(), keep_blank_values=True)
        if parameters["Action"] == ["GetCallerIdentity"]:
            return _AwsResponse(200, _identity_xml())
        region = urlsplit(url).hostname.split(".")[1]  # type: ignore[union-attr]
        if region == "us-west-2":
            return _AwsResponse(200, _instances_xml())
        if "NextToken" in parameters:
            return _AwsResponse(
                200,
                _instances_xml(_instance("i-22222222222222222", name="worker-02")),
            )
        return _AwsResponse(
            200,
            _instances_xml(
                _instance(
                    "i-11111111111111111",
                    extra_tags=(
                        "<item><key>db-password</key>"
                        "<value>provider-secret-tag-value</value></item>"
                    ),
                ),
                _instance("i-33333333333333333", state="terminated", name="old-host"),
                next_token="next-page-token",
            ),
        )

    connector = _connector(regions=["us-east-1", "us-west-2"], page_size=25)
    adapter = AwsInventoryAdapter(sender=send)
    tested = await adapter.test(connector, _secret(), source_data=None)
    assert tested == {
        "records_received": 3,
        "records_visible": 2,
        "account_id": ACCOUNT_ID,
        "partition": "aws",
        "regions": ["us-east-1", "us-west-2"],
        "permission": "ec2:DescribeInstances",
        "read_only": True,
    }

    calls.clear()
    observations, cursor = await adapter.collect(connector, _secret(), cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 2
    first = observations[0]
    cloud_id = f"aws:ec2:aws:{ACCOUNT_ID}:us-east-1:i-11111111111111111"
    assert first.source_record_id == cloud_id
    assert first.identifiers == [
        {"type": "cloud_instance_id", "value": cloud_id},
        {"type": "ip_address", "value": "10.0.0.10"},
        {"type": "ip_address", "value": "203.0.113.10"},
        {"type": "fqdn", "value": "ip-10-0-0-10.ec2.internal"},
        {"type": "fqdn", "value": "ec2-203-0-113-10.compute.amazonaws.com"},
    ]
    assert first.attributes == {
        "canonical_name": "web-01",
        "asset_type": "virtual_machine",
        "manufacturer": "Amazon Web Services",
        "aws_account_id": ACCOUNT_ID,
        "aws_partition": "aws",
        "aws_region": "us-east-1",
        "aws_instance_id": "i-11111111111111111",
        "aws_instance_state": "running",
        "aws_image_id": "ami-0123456789abcdef0",
        "aws_instance_type": "t3.small",
        "architecture": "x86_64",
        "aws_virtualization_type": "hvm",
        "aws_hypervisor": "xen",
        "aws_vpc_id": "vpc-0123456789abcdef0",
        "aws_subnet_id": "subnet-0123456789abcdef0",
        "operating_system": "Linux/UNIX",
        "aws_availability_zone": "us-east-1a",
        "aws_tenancy": "default",
        "aws_launch_time": "2026-07-13T12:00:00Z",
        "aws_tags": {"Name": "web-01", "Owner": "platform"},
        "aws_tags_redacted": 1,
    }

    assert [call[0] for call in calls] == [
        "https://sts.us-east-1.amazonaws.com/",
        "https://ec2.us-east-1.amazonaws.com/",
        "https://ec2.us-east-1.amazonaws.com/",
        "https://ec2.us-west-2.amazonaws.com/",
    ]
    sts, first_page, next_page, west = calls
    for url, headers, body, timeout in calls:
        assert url.startswith("https://")
        assert timeout == 15
        assert headers["Host"] == urlsplit(url).hostname
        assert headers["X-Amz-Security-Token"] == SESSION_TOKEN
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
        assert SECRET_ACCESS_KEY not in headers["Authorization"]
        assert SESSION_TOKEN not in headers["Authorization"]
        assert body
    assert f"/{calls[0][1]['X-Amz-Date'][:8]}/us-east-1/sts/aws4_request" in sts[1]["Authorization"]
    assert "/us-east-1/ec2/aws4_request" in first_page[1]["Authorization"]
    assert parse_qs(first_page[2].decode()) == {
        "Action": ["DescribeInstances"],
        "MaxResults": ["25"],
        "Version": ["2016-11-15"],
    }
    assert parse_qs(next_page[2].decode())["NextToken"] == ["next-page-token"]
    assert "/us-west-2/ec2/aws4_request" in west[1]["Authorization"]

    outcomes = json.dumps(tested) + str(cursor) + str(observations)
    for credential in (ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, _secret()):
        assert credential not in outcomes
    assert "provider-secret-tag-value" not in outcomes


@pytest.mark.parametrize(
    ("partition", "region", "suffix"),
    [
        ("aws", "ap-east-2", "amazonaws.com"),
        ("aws-us-gov", "us-gov-west-1", "amazonaws.com"),
        ("aws-cn", "cn-northwest-1", "amazonaws.com.cn"),
    ],
)
async def test_aws_partition_endpoints_are_code_defined(
    partition: str, region: str, suffix: str
) -> None:
    calls: list[str] = []

    async def send(url: str, **kwargs: Any) -> _AwsResponse:
        calls.append(url)
        action = parse_qs(kwargs["body"].decode())["Action"]
        return (
            _AwsResponse(200, _identity_xml(partition=partition))
            if action == ["GetCallerIdentity"]
            else _AwsResponse(200, _instances_xml())
        )

    result = await AwsInventoryAdapter(sender=send).test(
        _connector(partition=partition, regions=[region]), _secret(), source_data=None
    )
    assert result["partition"] == partition
    assert calls == [f"https://sts.{region}.{suffix}/", f"https://ec2.{region}.{suffix}/"]


async def test_aws_rejects_mutable_endpoints_state_and_invalid_config() -> None:
    async def unreachable(url: str, **kwargs: Any) -> _AwsResponse:
        raise AssertionError(f"unexpected request to {url}: {kwargs}")

    adapter = AwsInventoryAdapter(sender=unreachable)
    connector = _connector()
    connector.base_url = "https://attacker.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="base URL"):
        await adapter.test(connector, _secret(), source_data=None)
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(
            _connector(), _secret(), cursor={"next": "provider-token"}, source_data=None
        )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="source data"):
        await adapter.test(_connector(), _secret(), source_data=b"not-supported")

    cases = [
        (_connector(endpoint="https://attacker.test"), _secret(), "unknown fields"),
        (_connector(partition="attacker"), _secret(), "partition must be"),
        (_connector(regions=[]), _secret(), "1-40 regions"),
        (_connector(regions=["us-east-1", "us-east-1"]), _secret(), "duplicates"),
        (_connector(regions=["cn-north-1"]), _secret(), "selected partition"),
        (_connector(expected_account_id="123"), _secret(), "12 digits"),
        (_connector(page_size=101), _secret(), "page_size"),
        (_connector(record_limit=10_001), _secret(), "record_limit"),
        (_connector(include_terminated="yes"), _secret(), "must be a boolean"),
        (_connector(), None, "credential envelope is required"),
        (_connector(), "not-json", "valid JSON"),
        (
            _connector(),
            json.dumps({"access_key_id": ACCESS_KEY_ID, "secret_access_key": "short"}),
            "secret access key is invalid",
        ),
        (
            _connector(),
            json.dumps(
                {
                    "access_key_id": ACCESS_KEY_ID,
                    "secret_access_key": SECRET_ACCESS_KEY,
                    "endpoint": "https://attacker.test",
                }
            ),
            "invalid fields",
        ),
        (
            _connector(),
            _secret(session_token=None),
            "temporary credentials require a session token",
        ),
    ]
    for source, secret, message in cases:
        with pytest.raises(passive_inventory.InventoryConnectorError, match=message):
            await adapter.test(source, secret, source_data=None)


async def test_aws_rejects_account_mismatch_repeated_tokens_and_record_overflow() -> None:
    async def wrong_account(url: str, **kwargs: Any) -> _AwsResponse:
        action = parse_qs(kwargs["body"].decode())["Action"]
        if action == ["GetCallerIdentity"]:
            return _AwsResponse(200, _identity_xml())
        return _AwsResponse(
            200,
            _instances_xml(_instance("i-11111111111111111"), owner_id="999999999999"),
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="owner does not match"):
        await AwsInventoryAdapter(sender=wrong_account).test(
            _connector(), _secret(), source_data=None
        )

    async def repeated(url: str, **kwargs: Any) -> _AwsResponse:
        action = parse_qs(kwargs["body"].decode())["Action"]
        return (
            _AwsResponse(200, _identity_xml())
            if action == ["GetCallerIdentity"]
            else _AwsResponse(200, _instances_xml(next_token="same-token"))
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="repeated a token"):
        await AwsInventoryAdapter(sender=repeated).test(_connector(), _secret(), source_data=None)

    async def two_records(url: str, **kwargs: Any) -> _AwsResponse:
        action = parse_qs(kwargs["body"].decode())["Action"]
        return (
            _AwsResponse(200, _identity_xml())
            if action == ["GetCallerIdentity"]
            else _AwsResponse(
                200,
                _instances_xml(
                    _instance("i-11111111111111111"),
                    _instance("i-22222222222222222"),
                ),
            )
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await AwsInventoryAdapter(sender=two_records).test(
            _connector(record_limit=1), _secret(), source_data=None
        )


async def test_aws_rejects_malformed_xxe_and_duplicate_provider_data() -> None:
    async def malformed(url: str, **kwargs: Any) -> _AwsResponse:
        del url, kwargs
        return _AwsResponse(200, b"<not-closed>")

    with pytest.raises(passive_inventory.InventoryConnectorError, match="invalid XML"):
        await AwsInventoryAdapter(sender=malformed).test(_connector(), _secret(), source_data=None)

    async def xxe(url: str, **kwargs: Any) -> _AwsResponse:
        del url, kwargs
        return _AwsResponse(
            200,
            b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="invalid XML"):
        await AwsInventoryAdapter(sender=xxe).test(_connector(), _secret(), source_data=None)

    calls = 0

    async def duplicate(url: str, **kwargs: Any) -> _AwsResponse:
        nonlocal calls
        calls += 1
        action = parse_qs(kwargs["body"].decode())["Action"]
        return (
            _AwsResponse(200, _identity_xml())
            if action == ["GetCallerIdentity"]
            else _AwsResponse(
                200,
                _instances_xml(
                    _instance("i-11111111111111111"),
                    _instance("i-11111111111111111"),
                ),
            )
        )

    with pytest.raises(passive_inventory.InventoryConnectorError, match="duplicate instance IDs"):
        await AwsInventoryAdapter(sender=duplicate).test(_connector(), _secret(), source_data=None)
    assert calls == 2


async def test_aws_provider_errors_are_bounded_and_credential_safe() -> None:
    raw_message = f"bad {ACCESS_KEY_ID} {SECRET_ACCESS_KEY} {SESSION_TOKEN}"

    async def denied(url: str, **kwargs: Any) -> _AwsResponse:
        del url, kwargs
        return _AwsResponse(
            403,
            (
                "<Response><Errors><Error><Code>InvalidClientTokenId</Code>"
                f"<Message>{raw_message}</Message></Error></Errors></Response>"
            ).encode(),
        )

    with pytest.raises(passive_inventory.InventoryConnectorError) as raised:
        await AwsInventoryAdapter(sender=denied).test(_connector(), _secret(), source_data=None)
    message = str(raised.value)
    assert message.endswith("HTTP 403 (InvalidClientTokenId)")
    assert raw_message not in message
    assert ACCESS_KEY_ID not in message
    assert SECRET_ACCESS_KEY not in message
    assert SESSION_TOKEN not in message


async def test_aws_transport_pins_dns_disables_redirects_and_caps_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers["host"]
        seen["body"] = request.content
        return httpx.Response(302, headers={"location": "https://attacker.test/stolen"})

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, **_kwargs: ("sts.us-east-1.amazonaws.com", "203.0.113.10"),
    )
    response = await _post_xml(
        "https://sts.us-east-1.amazonaws.com/",
        headers={
            "Host": "sts.us-east-1.amazonaws.com",
            "Authorization": "signed-header",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
        body=b"Action=GetCallerIdentity&Version=2011-06-15",
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )
    assert response.status_code == 302
    assert seen == {
        "url": "https://203.0.113.10/",
        "host": "sts.us-east-1.amazonaws.com",
        "body": b"Action=GetCallerIdentity&Version=2011-06-15",
    }

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, **_kwargs: (_ for _ in ()).throw(
            notifications.NotificationError("Webhook host resolves to a private address")
        ),
    )
    with pytest.raises(_AwsTransportError, match="AWS endpoint host.*private"):
        await _post_xml(
            "https://sts.us-east-1.amazonaws.com/",
            headers={"Host": "sts.us-east-1.amazonaws.com"},
            body=b"request",
            timeout_seconds=5,
        )

    monkeypatch.setattr(
        notifications,
        "resolve_validated",
        lambda _url, **_kwargs: ("sts.us-east-1.amazonaws.com", "203.0.113.10"),
    )

    def oversized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (1_048_576 + 1))

    with pytest.raises(_AwsTransportError, match="exceeded 1 MiB"):
        await _post_xml(
            "https://sts.us-east-1.amazonaws.com/",
            headers={"Host": "sts.us-east-1.amazonaws.com"},
            body=b"request",
            timeout_seconds=5,
            transport=httpx.MockTransport(oversized),
        )


def test_aws_adapter_is_registered() -> None:
    assert PassiveConnectorType.AWS in passive_inventory.ADAPTERS
    assert isinstance(passive_inventory.ADAPTERS[PassiveConnectorType.AWS], AwsInventoryAdapter)
