"""Read-only AWS EC2 inventory through fixed, bounded Query API calls."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode
from xml.etree import ElementTree

import httpx
from botocore.auth import SigV4Auth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]
from botocore.credentials import Credentials  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from app.models.passive_inventory import InventoryConnector
from app.services import notifications
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation

_MAX_RESPONSE_BYTES = 1_048_576
_MAX_RECORDS = 10_000
_MAX_REGIONS = 40
_MAX_PAGES = 1_100
_MAX_NEXT_TOKEN = 4_096
_MAX_TAGS = 50
_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,32}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_ACCESS_KEY_RE = re.compile(r"^[A-Z0-9]{16,128}$")
_STATE_RE = re.compile(r"^[a-z][a-z-]{0,31}$")
_ERROR_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SECRET_FRAGMENTS = {
    "authorization",
    "credential",
    "password",
    "private_key",
    "api_key",
    "secret",
    "token",
}
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "partition",
        "regions",
        "expected_account_id",
        "include_terminated",
        "timeout_seconds",
        "page_size",
        "record_limit",
    }
)


@dataclass(frozen=True)
class _Partition:
    dns_suffix: str
    regions: frozenset[str]


_PARTITIONS = {
    "aws": _Partition(
        "amazonaws.com",
        frozenset(
            {
                "af-south-1",
                "ap-east-1",
                "ap-east-2",
                "ap-northeast-1",
                "ap-northeast-2",
                "ap-northeast-3",
                "ap-south-1",
                "ap-south-2",
                "ap-southeast-1",
                "ap-southeast-2",
                "ap-southeast-3",
                "ap-southeast-4",
                "ap-southeast-5",
                "ap-southeast-6",
                "ap-southeast-7",
                "ca-central-1",
                "ca-west-1",
                "eu-central-1",
                "eu-central-2",
                "eu-north-1",
                "eu-south-1",
                "eu-south-2",
                "eu-west-1",
                "eu-west-2",
                "eu-west-3",
                "il-central-1",
                "me-central-1",
                "me-south-1",
                "mx-central-1",
                "sa-east-1",
                "us-east-1",
                "us-east-2",
                "us-west-1",
                "us-west-2",
            }
        ),
    ),
    "aws-us-gov": _Partition("amazonaws.com", frozenset({"us-gov-east-1", "us-gov-west-1"})),
    "aws-cn": _Partition("amazonaws.com.cn", frozenset({"cn-north-1", "cn-northwest-1"})),
}


@dataclass(frozen=True)
class _CredentialEnvelope:
    access_key_id: str
    secret_access_key: str
    session_token: str | None


@dataclass(frozen=True)
class _AwsResponse:
    status_code: int
    body: bytes


class _AwsTransportError(RuntimeError):
    """Safe transport failure that never contains credentials or provider bodies."""


SendXml = Callable[..., Awaitable[_AwsResponse]]


class AwsInventoryAdapter:
    """Collect EC2 instance summaries without an ambient AWS credential chain."""

    def __init__(self, sender: SendXml | None = None) -> None:
        self._sender = _post_xml if sender is None else sender

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        observations, received, account_id, partition, regions = await self._read(
            connector,
            secret,
            cursor={},
            source_data=source_data,
        )
        return {
            "records_received": received,
            "records_visible": len(observations),
            "account_id": account_id,
            "partition": partition,
            "regions": regions,
            "permission": "ec2:DescribeInstances",
            "read_only": True,
        }

    async def collect(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], dict[str, Any]]:
        observations, _, _, _, _ = await self._read(
            connector,
            secret,
            cursor=cursor,
            source_data=source_data,
        )
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], int, str, str, list[str]]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("AWS connector cursor must be empty")
        if source_data is not None:
            raise InventoryConnectorError("AWS connector does not accept source data")
        if connector.base_url:
            raise InventoryConnectorError("AWS connector does not accept a base URL")
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("AWS connector config contains unknown fields")
        partition_name, partition = _partition(config.get("partition", "aws"))
        regions = _regions(config.get("regions"), partition=partition)
        expected_account_id = _optional_account_id(config.get("expected_account_id"))
        include_terminated = _boolean(config, "include_terminated", default=False)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        page_size = _bounded_int(config.get("page_size", 100), "page_size", 10, 100)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        credentials = _credentials(secret)

        identity = await self._query(
            credentials,
            partition=partition,
            region=regions[0],
            service="sts",
            parameters={"Action": "GetCallerIdentity", "Version": "2011-06-15"},
            timeout_seconds=timeout_seconds,
            operation="identity validation",
        )
        account_id = _caller_account(
            identity, partition_name=partition_name, expected_account_id=expected_account_id
        )

        observations: list[NormalizedObservation] = []
        received = 0
        pages = 0
        observed_at = datetime.now(UTC)
        for region in regions:
            next_token: str | None = None
            seen_tokens: set[str] = set()
            while True:
                pages += 1
                if pages > _MAX_PAGES:
                    raise InventoryConnectorError("AWS EC2 pagination exceeded its page limit")
                parameters = {
                    "Action": "DescribeInstances",
                    "Version": "2016-11-15",
                    "MaxResults": str(page_size),
                }
                if next_token is not None:
                    parameters["NextToken"] = next_token
                page = await self._query(
                    credentials,
                    partition=partition,
                    region=region,
                    service="ec2",
                    parameters=parameters,
                    timeout_seconds=timeout_seconds,
                    operation=f"EC2 inventory read in {region}",
                )
                records, next_token = _instance_page(page, expected_account_id=account_id)
                received += len(records)
                if received > record_limit:
                    raise InventoryConnectorError("AWS EC2 inventory exceeded the record limit")
                for record in records:
                    observation = _instance_observation(
                        record,
                        partition=partition_name,
                        account_id=account_id,
                        region=region,
                        observed_at=observed_at,
                        include_terminated=include_terminated,
                    )
                    if observation is not None:
                        observations.append(observation)
                if next_token is None:
                    break
                if next_token in seen_tokens:
                    raise InventoryConnectorError("AWS EC2 pagination repeated a token")
                seen_tokens.add(next_token)
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("AWS EC2 inventory returned duplicate instance IDs")
        return observations, received, account_id, partition_name, regions

    async def _query(
        self,
        credentials: _CredentialEnvelope,
        *,
        partition: _Partition,
        region: str,
        service: str,
        parameters: dict[str, str],
        timeout_seconds: int,
        operation: str,
    ) -> ElementTree.Element:
        hostname = f"{service}.{region}.{partition.dns_suffix}"
        url = f"https://{hostname}/"
        body = urlencode(sorted(parameters.items())).encode("ascii")
        request = AWSRequest(
            method="POST",
            url=url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        )
        SigV4Auth(
            Credentials(
                credentials.access_key_id,
                credentials.secret_access_key,
                credentials.session_token,
            ),
            service,
            region,
        ).add_auth(request)
        headers = {str(key): str(value) for key, value in request.headers.items()}
        headers.update(
            {
                "Accept": "application/xml",
                "Host": hostname,
                "User-Agent": "Vulna-AWS-Inventory/1",
            }
        )
        try:
            response = await self._sender(
                url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
            )
        except _AwsTransportError as exc:
            raise InventoryConnectorError(f"AWS {operation} failed: {exc}") from exc
        if not 200 <= response.status_code < 300:
            code = _error_code(response.body)
            detail = f" ({code})" if code else ""
            raise InventoryConnectorError(
                f"AWS {operation} failed: provider returned HTTP {response.status_code}{detail}"
            )
        return _parse_xml(response.body, operation=operation)


async def _post_xml(
    url: str,
    *,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: int,
    transport: httpx.AsyncBaseTransport | None = None,
) -> _AwsResponse:
    """Send one signed request to a DNS-pinned public AWS endpoint."""

    try:
        host, address = notifications.resolve_validated(url, allow_private=False)
    except notifications.NotificationError as exc:
        safe = str(exc).replace("Webhook", "AWS endpoint")
        raise _AwsTransportError(safe) from exc
    pinned_url = notifications.pin_url_to_ip(url, address)
    try:
        async with (
            httpx.AsyncClient(
                timeout=float(timeout_seconds),
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            ) as client,
            client.stream(
                "POST",
                pinned_url,
                headers=headers,
                content=body,
                extensions={"sni_hostname": host},
            ) as response,
        ):
            response_body = bytearray()
            async for chunk in response.aiter_bytes():
                response_body.extend(chunk)
                if len(response_body) > _MAX_RESPONSE_BYTES:
                    raise _AwsTransportError("provider response exceeded 1 MiB")
            return _AwsResponse(response.status_code, bytes(response_body))
    except httpx.HTTPError as exc:
        raise _AwsTransportError(f"request failed: {type(exc).__name__}") from exc


def _parse_xml(value: bytes, *, operation: str) -> ElementTree.Element:
    if not value or len(value) > _MAX_RESPONSE_BYTES:
        raise InventoryConnectorError(f"AWS {operation} returned an invalid XML response")
    try:
        return fromstring(value)
    except (DefusedXmlException, ElementTree.ParseError, ValueError) as exc:
        raise InventoryConnectorError(f"AWS {operation} returned an invalid XML response") from exc


def _caller_account(
    root: ElementTree.Element,
    *,
    partition_name: str,
    expected_account_id: str | None,
) -> str:
    if _local_name(root) != "GetCallerIdentityResponse":
        raise InventoryConnectorError("AWS identity response has an unexpected root")
    result = _one_child(root, "GetCallerIdentityResult", required=True)
    account_id = cast(str, _child_text(result, "Account", required=True, maximum=12))
    arn = cast(str, _child_text(result, "Arn", required=True, maximum=2_048))
    if not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise InventoryConnectorError("AWS identity response contains an invalid account ID")
    if not arn.startswith(f"arn:{partition_name}:") or f"::{account_id}:" not in arn:
        raise InventoryConnectorError("AWS identity response does not match its partition/account")
    if expected_account_id is not None and account_id != expected_account_id:
        raise InventoryConnectorError("AWS credentials do not match expected_account_id")
    return account_id


def _instance_page(
    root: ElementTree.Element, *, expected_account_id: str
) -> tuple[list[ElementTree.Element], str | None]:
    if _local_name(root) != "DescribeInstancesResponse":
        raise InventoryConnectorError("AWS EC2 response has an unexpected root")
    reservation_set = _one_child(root, "reservationSet", required=True)
    records: list[ElementTree.Element] = []
    for reservation in _children(reservation_set, "item"):
        owner_id = _child_text(reservation, "ownerId", required=True, maximum=12)
        if owner_id != expected_account_id:
            raise InventoryConnectorError("AWS EC2 reservation owner does not match the account")
        instance_set = _one_child(reservation, "instancesSet", required=True)
        records.extend(_children(instance_set, "item"))
    next_token = _child_text(root, "nextToken", required=False, maximum=_MAX_NEXT_TOKEN)
    if next_token is not None and not _printable(next_token):
        raise InventoryConnectorError("AWS EC2 next token is invalid")
    return records, next_token


def _instance_observation(
    record: ElementTree.Element,
    *,
    partition: str,
    account_id: str,
    region: str,
    observed_at: datetime,
    include_terminated: bool,
) -> NormalizedObservation | None:
    instance_id = cast(str, _child_text(record, "instanceId", required=True, maximum=64))
    if not _INSTANCE_ID_RE.fullmatch(instance_id):
        raise InventoryConnectorError("AWS EC2 instance identifier is invalid")
    state_node = _one_child(record, "instanceState", required=True)
    state = cast(str, _child_text(state_node, "name", required=True, maximum=32))
    if not _STATE_RE.fullmatch(state):
        raise InventoryConnectorError("AWS EC2 instance state is invalid")
    if state == "terminated" and not include_terminated:
        return None

    tags, redacted_tags = _tags(record)
    cloud_id = f"aws:ec2:{partition}:{account_id}:{region}:{instance_id}"
    identifiers: list[dict[str, str]] = [{"type": "cloud_instance_id", "value": cloud_id}]
    for field in ("privateIpAddress", "ipAddress"):
        value = _child_text(record, field, required=False, maximum=64)
        if value is not None:
            _append_ip(identifiers, value, field=field)
    hostnames: list[str] = []
    for field in ("privateDnsName", "dnsName"):
        value = _child_text(record, field, required=False, maximum=253)
        if value is None:
            continue
        hostname = _hostname(value)
        if hostname is None:
            raise InventoryConnectorError(f"AWS EC2 {field} is invalid")
        hostnames.append(hostname)
        _append_identifier(
            identifiers,
            {"type": "fqdn" if "." in hostname else "hostname", "value": hostname},
        )

    name = tags.get("Name")
    canonical_name = (
        name if name and len(name) <= 255 else (hostnames[0] if hostnames else instance_id)
    )
    attributes: dict[str, Any] = {
        "canonical_name": canonical_name,
        "asset_type": "virtual_machine",
        "manufacturer": "Amazon Web Services",
        "aws_account_id": account_id,
        "aws_partition": partition,
        "aws_region": region,
        "aws_instance_id": instance_id,
        "aws_instance_state": state,
    }
    mapping = {
        "imageId": "aws_image_id",
        "instanceType": "aws_instance_type",
        "architecture": "architecture",
        "virtualizationType": "aws_virtualization_type",
        "hypervisor": "aws_hypervisor",
        "vpcId": "aws_vpc_id",
        "subnetId": "aws_subnet_id",
        "platform": "aws_platform",
        "platformDetails": "operating_system",
    }
    for source, target in mapping.items():
        value = _child_text(record, source, required=False, maximum=512)
        if value is not None:
            attributes[target] = value
    placement = _one_child(record, "placement", required=False)
    if placement is not None:
        availability_zone = _child_text(placement, "availabilityZone", required=False, maximum=64)
        tenancy = _child_text(placement, "tenancy", required=False, maximum=32)
        if availability_zone is not None:
            attributes["aws_availability_zone"] = availability_zone
        if tenancy is not None:
            attributes["aws_tenancy"] = tenancy
    launch_time = _child_text(record, "launchTime", required=False, maximum=64)
    if launch_time is not None:
        _validate_timestamp(launch_time, "launchTime")
        attributes["aws_launch_time"] = launch_time
    if tags:
        attributes["aws_tags"] = tags
    if redacted_tags:
        attributes["aws_tags_redacted"] = redacted_tags
    return NormalizedObservation(
        source_record_id=cloud_id,
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _tags(record: ElementTree.Element) -> tuple[dict[str, str], int]:
    tag_set = _one_child(record, "tagSet", required=False)
    if tag_set is None:
        return {}, 0
    items = _children(tag_set, "item")
    if len(items) > _MAX_TAGS:
        raise InventoryConnectorError("AWS EC2 instance has too many tags")
    tags: dict[str, str] = {}
    redacted = 0
    for item in items:
        key = cast(str, _child_text(item, "key", required=True, maximum=128))
        value = _child_text(item, "value", required=False, maximum=256, allow_empty=True) or ""
        if key in tags:
            raise InventoryConnectorError("AWS EC2 instance contains duplicate tag keys")
        normalized_key = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if any(fragment in normalized_key for fragment in _SECRET_FRAGMENTS):
            redacted += 1
            continue
        tags[key] = value
    return dict(sorted(tags.items())), redacted


def _partition(value: Any) -> tuple[str, _Partition]:
    if not isinstance(value, str) or value not in _PARTITIONS:
        raise InventoryConnectorError("AWS partition must be aws, aws-us-gov, or aws-cn")
    return value, _PARTITIONS[value]


def _regions(value: Any, *, partition: _Partition) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_REGIONS
        or not all(isinstance(item, str) for item in value)
    ):
        raise InventoryConnectorError("AWS regions must be a list containing 1-40 regions")
    regions = [item.strip() for item in cast(list[str], value)]
    if any(item not in partition.regions for item in regions):
        raise InventoryConnectorError("AWS regions must belong to the selected partition")
    if len(regions) != len(set(regions)):
        raise InventoryConnectorError("AWS regions must not contain duplicates")
    return regions


def _credentials(value: str | None) -> _CredentialEnvelope:
    if not isinstance(value, str) or not value or len(value) > 32_768:
        raise InventoryConnectorError("AWS credential envelope is required")
    try:
        decoded = json.loads(value)
    except ValueError as exc:
        raise InventoryConnectorError("AWS credential envelope must be valid JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) not in (
        {"access_key_id", "secret_access_key"},
        {"access_key_id", "secret_access_key", "session_token"},
    ):
        raise InventoryConnectorError("AWS credential envelope contains invalid fields")
    access_key_id = decoded.get("access_key_id")
    secret_access_key = decoded.get("secret_access_key")
    session_token = decoded.get("session_token")
    if not isinstance(access_key_id, str) or not _ACCESS_KEY_RE.fullmatch(access_key_id):
        raise InventoryConnectorError("AWS access key ID is invalid")
    if not _credential_text(secret_access_key, minimum=16, maximum=256):
        raise InventoryConnectorError("AWS secret access key is invalid")
    if session_token is not None and not _credential_text(session_token, minimum=1, maximum=8_192):
        raise InventoryConnectorError("AWS session token is invalid")
    if access_key_id.startswith("ASIA") and session_token is None:
        raise InventoryConnectorError("AWS temporary credentials require a session token")
    return _CredentialEnvelope(access_key_id, cast(str, secret_access_key), session_token)


def _credential_text(value: Any, *, minimum: int, maximum: int) -> bool:
    return isinstance(value, str) and minimum <= len(value) <= maximum and _printable(value)


def _optional_account_id(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _ACCOUNT_ID_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("AWS expected_account_id must contain 12 digits")
    return value.strip()


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"AWS {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"AWS {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"AWS {field} must be between {minimum} and {maximum}")
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"AWS {key} must be a boolean")
    return value


def _one_child(
    parent: ElementTree.Element | None, name: str, *, required: bool
) -> ElementTree.Element | None:
    matches = _children(parent, name)
    if len(matches) > 1 or required and not matches:
        raise InventoryConnectorError(f"AWS provider response contains invalid {name}")
    return matches[0] if matches else None


def _children(parent: ElementTree.Element | None, name: str) -> list[ElementTree.Element]:
    if parent is None:
        return []
    return [child for child in list(parent) if _local_name(child) == name]


def _child_text(
    parent: ElementTree.Element | None,
    name: str,
    *,
    required: bool,
    maximum: int,
    allow_empty: bool = False,
) -> str | None:
    child = _one_child(parent, name, required=required)
    if child is None:
        return None
    value = (child.text or "").strip()
    if len(value) > maximum or not _printable(value) or not value and not allow_empty:
        raise InventoryConnectorError(f"AWS provider response contains invalid {name}")
    return value


def _local_name(element: ElementTree.Element) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def _printable(value: str) -> bool:
    return all(32 <= ord(character) <= 126 for character in value)


def _append_ip(identifiers: list[dict[str, str]], value: str, *, field: str) -> None:
    try:
        normalized = str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InventoryConnectorError(f"AWS EC2 {field} is invalid") from exc
    _append_identifier(identifiers, {"type": "ip_address", "value": normalized})


def _append_identifier(identifiers: list[dict[str, str]], identifier: dict[str, str]) -> None:
    if identifier not in identifiers:
        identifiers.append(identifier)


def _hostname(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return None
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in candidate.split(".")):
        return None
    return candidate


def _validate_timestamp(value: str, field: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryConnectorError(f"AWS EC2 {field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InventoryConnectorError(f"AWS EC2 {field} must include a timezone")


def _error_code(body: bytes) -> str | None:
    if not body or len(body) > _MAX_RESPONSE_BYTES:
        return None
    try:
        root = fromstring(body)
    except (DefusedXmlException, ElementTree.ParseError, ValueError):
        return None
    for element in root.iter():
        if _local_name(element) == "Code":
            value = (element.text or "").strip()
            return value if _ERROR_CODE_RE.fullmatch(value) else None
    return None
