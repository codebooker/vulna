"""Read-only Google Compute Engine inventory through bounded REST calls."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public OAuth endpoint
_COMPUTE_SCOPE = "https://www.googleapis.com/auth/compute.readonly"
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_INSTANCE_NAME_RE = re.compile(r"^[a-z](?:[-a-z0-9]*[a-z0-9])?$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,256}$")
_SERVICE_ACCOUNT_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9.-]{1,128}\.iam\.gserviceaccount\.com$"
)
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ZONE_RE = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])$")
_ALLOWED_CONFIG_FIELDS = frozenset({"project_ids", "timeout_seconds", "page_size", "record_limit"})
_ALLOWED_CREDENTIAL_FIELDS = frozenset(
    {
        "type",
        "project_id",
        "private_key_id",
        "private_key",
        "client_email",
        "client_id",
        "auth_uri",
        "token_uri",
        "auth_provider_x509_cert_url",
        "client_x509_cert_url",
        "universe_domain",
    }
)
_FIELDS = (
    "nextPageToken,unreachables,"
    "items/*/warning(code),"
    "items/*/instances("
    "id,name,hostname,zone,status,creationTimestamp,machineType,cpuPlatform,"
    "canIpForward,deletionProtection,lastStartTimestamp,lastStopTimestamp,"
    "lastSuspendedTimestamp,networkInterfaces("
    "network,subnetwork,networkIP,ipv6Address,accessConfigs(natIP)))"
)
_MAX_PROJECTS = 50
_MAX_PAGE_SIZE = 500
_MAX_RECORDS = 10_000
_MAX_PAGES = 1_000


@dataclass(frozen=True)
class _ServiceAccount:
    project_id: str
    private_key_id: str
    private_key: str
    client_email: str


class GoogleCloudInventoryAdapter:
    """Collect fixed Compute Engine instance projections with service-account auth."""

    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        del source_data
        observations, received, projects = await self._read(connector, secret, cursor={})
        return {
            "records_received": received,
            "records_visible": len(observations),
            "projects": len(projects),
            "permission": "compute.instances.list",
            "oauth_scope": _COMPUTE_SCOPE,
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
        del source_data
        observations, _, _ = await self._read(connector, secret, cursor=cursor)
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], int, list[str]]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("Google Cloud connector cursor must be empty")
        if connector.base_url:
            raise InventoryConnectorError("Google Cloud connector does not accept a base URL")
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("Google Cloud connector config contains unknown fields")
        credentials = _service_account(secret)
        projects = _projects(config.get("project_ids"), default=credentials.project_id)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        page_size = _bounded_int(
            config.get("page_size", _MAX_PAGE_SIZE), "page_size", 1, _MAX_PAGE_SIZE
        )
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        assertion = _signed_assertion(credentials)
        token = await self._access_token(assertion, timeout_seconds=timeout_seconds)
        records: list[tuple[dict[str, Any], str, str]] = []
        pages = 0
        for project_id in projects:
            project_records, pages = await self._instances(
                project_id,
                token=token,
                page_size=page_size,
                record_limit=record_limit - len(records),
                pages=pages,
                timeout_seconds=timeout_seconds,
            )
            records.extend((record, project_id, scope) for record, scope in project_records)
        observed_at = datetime.now(UTC)
        observations = [
            _observation(record, project_id=project_id, scope=scope, observed_at=observed_at)
            for record, project_id, scope in records
        ]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("Google Compute Engine returned duplicate instance IDs")
        return observations, len(records), projects

    async def _access_token(self, assertion: str, *, timeout_seconds: int) -> str:
        try:
            response = await self._sender(
                "POST",
                _TOKEN_URI,
                headers={"Accept": "application/json"},
                form_body={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
                timeout_seconds=timeout_seconds,
                allow_private=False,
                user_agent="Vulna-Google-Cloud-Inventory/1",
            )
        except TicketHttpError as exc:
            raise InventoryConnectorError(_safe_provider_error(exc, "authentication")) from exc
        if not isinstance(response.data, dict):
            raise InventoryConnectorError("Google Cloud authentication returned invalid JSON")
        token = response.data.get("access_token")
        token_type = response.data.get("token_type")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 32_768
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise InventoryConnectorError("Google Cloud authentication response is invalid")
        return token

    async def _instances(
        self,
        project_id: str,
        *,
        token: str,
        page_size: int,
        record_limit: int,
        pages: int,
        timeout_seconds: int,
    ) -> tuple[list[tuple[dict[str, Any], str]], int]:
        records: list[tuple[dict[str, Any], str]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            pages += 1
            if pages > _MAX_PAGES:
                raise InventoryConnectorError("Google Compute Engine pagination exceeded its limit")
            query = {
                "maxResults": str(page_size),
                "returnPartialSuccess": "true",
                "fields": _FIELDS,
            }
            if page_token is not None:
                query["pageToken"] = page_token
            url = (
                f"https://compute.googleapis.com/compute/v1/projects/{project_id}/"
                f"aggregated/instances?{urlencode(query)}"
            )
            try:
                response = await self._sender(
                    "GET",
                    url,
                    headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
                    timeout_seconds=timeout_seconds,
                    allow_private=False,
                    user_agent="Vulna-Google-Cloud-Inventory/1",
                )
            except TicketHttpError as exc:
                raise InventoryConnectorError(
                    _safe_provider_error(exc, f"project {project_id} instance read")
                ) from exc
            page, next_token = _instance_page(response.data, page_size=page_size)
            if len(records) + len(page) > record_limit:
                raise InventoryConnectorError(
                    "Google Compute Engine read exceeded the record limit"
                )
            records.extend(page)
            if next_token is None:
                break
            if next_token in seen_tokens:
                raise InventoryConnectorError(
                    "Google Compute Engine pagination repeated a continuation token"
                )
            seen_tokens.add(next_token)
            page_token = next_token
        return records, pages


def _service_account(secret: str | None) -> _ServiceAccount:
    if not isinstance(secret, str) or not secret or len(secret) > 32_768:
        raise InventoryConnectorError("Google Cloud service-account JSON is required")
    try:
        value = json.loads(secret)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError("Google Cloud service-account JSON is invalid") from exc
    if not isinstance(value, dict) or set(value) - _ALLOWED_CREDENTIAL_FIELDS:
        raise InventoryConnectorError("Google Cloud credential contains unsupported fields")
    if value.get("type") != "service_account" or value.get("token_uri") != _TOKEN_URI:
        raise InventoryConnectorError("Google Cloud credential is not a supported service account")
    universe = value.get("universe_domain", "googleapis.com")
    if universe != "googleapis.com":
        raise InventoryConnectorError("Google Cloud credential universe is not supported")
    project_id = _project(value.get("project_id"))
    key_id = _required_text(value.get("private_key_id"), "private_key_id", maximum=256)
    if not _KEY_ID_RE.fullmatch(key_id):
        raise InventoryConnectorError("Google Cloud private_key_id is invalid")
    email = _required_text(value.get("client_email"), "client_email", maximum=254).lower()
    if not _SERVICE_ACCOUNT_RE.fullmatch(email):
        raise InventoryConnectorError("Google Cloud client_email is invalid")
    private_key = _private_key(value.get("private_key"))
    try:
        parsed_key = serialization.load_pem_private_key(private_key.encode(), password=None)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError("Google Cloud private key is invalid") from exc
    if not isinstance(parsed_key, rsa.RSAPrivateKey) or parsed_key.key_size < 2_048:
        raise InventoryConnectorError(
            "Google Cloud private key must be RSA with at least 2048 bits"
        )
    return _ServiceAccount(project_id, key_id, private_key, email)


def _signed_assertion(credentials: _ServiceAccount) -> str:
    now = datetime.now(UTC)
    try:
        assertion = jwt.encode(
            {
                "iss": credentials.client_email,
                "scope": _COMPUTE_SCOPE,
                "aud": _TOKEN_URI,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=55)).timestamp()),
            },
            credentials.private_key,
            algorithm="RS256",
            headers={"kid": credentials.private_key_id, "typ": "JWT"},
        )
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(
            "Google Cloud service-account assertion could not be signed"
        ) from exc
    if not isinstance(assertion, str) or len(assertion) > 16_384:
        raise InventoryConnectorError("Google Cloud service-account assertion is invalid")
    return assertion


def _instance_page(
    value: Any, *, page_size: int
) -> tuple[list[tuple[dict[str, Any], str]], str | None]:
    if not isinstance(value, dict):
        raise InventoryConnectorError("Google Compute Engine response is invalid")
    unreachables = value.get("unreachables", [])
    if not isinstance(unreachables, list) or not all(
        isinstance(item, str) for item in unreachables
    ):
        raise InventoryConnectorError("Google Compute Engine unreachable scopes are invalid")
    if unreachables:
        raise InventoryConnectorError("Google Compute Engine returned unreachable scopes")
    items = value.get("items", {})
    if not isinstance(items, dict) or len(items) > 10_000:
        raise InventoryConnectorError("Google Compute Engine scoped results are invalid")
    records: list[tuple[dict[str, Any], str]] = []
    for scope, raw_bucket in items.items():
        if (
            not isinstance(scope, str)
            or not _valid_scope(scope)
            or not isinstance(raw_bucket, dict)
        ):
            raise InventoryConnectorError("Google Compute Engine result scope is invalid")
        warning = raw_bucket.get("warning")
        if warning is not None and (
            not isinstance(warning, dict)
            or warning.get("code")
            not in {
                "NO_RESULTS",
                "NO_RESULTS_ON_PAGE",
            }
        ):
            raise InventoryConnectorError("Google Compute Engine returned a partial scope")
        instances = raw_bucket.get("instances", [])
        if not isinstance(instances, list) or not all(isinstance(item, dict) for item in instances):
            raise InventoryConnectorError("Google Compute Engine instance page is invalid")
        records.extend((cast(dict[str, Any], item), scope) for item in instances)
    if len(records) > page_size:
        raise InventoryConnectorError("Google Compute Engine page exceeded its requested size")
    token = value.get("nextPageToken")
    if token is not None and (
        not isinstance(token, str)
        or not token
        or len(token) > 4_096
        or any(ord(character) < 32 for character in token)
    ):
        raise InventoryConnectorError("Google Compute Engine continuation token is invalid")
    return records, token


def _observation(
    record: dict[str, Any], *, project_id: str, scope: str, observed_at: datetime
) -> NormalizedObservation:
    instance_id = _uint64(record.get("id"), "instance id")
    name = _required_text(record.get("name"), "instance name", maximum=63)
    if not _INSTANCE_NAME_RE.fullmatch(name):
        raise InventoryConnectorError("Google Cloud instance name is invalid")
    zone = _zone(record.get("zone"))
    if scope != f"zones/{zone}":
        raise InventoryConnectorError("Google Compute Engine instance crossed result scopes")
    hostname = _hostname(_optional_text(record.get("hostname"), "hostname", maximum=253))
    identifiers: list[dict[str, Any]] = [
        {"type": "cloud_instance_id", "value": f"gcp:{project_id}:{instance_id}"}
    ]
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    addresses, networks = _network_context(record.get("networkInterfaces"))
    identifiers.extend({"type": "ip_address", "value": address} for address in addresses)
    if len(identifiers) > 50:
        raise InventoryConnectorError("Google Cloud instance returned too many identifiers")
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name,
        "asset_type": "virtual_machine",
        "manufacturer": "Google",
        "gcp_project_id": project_id,
        "gcp_instance_id": instance_id,
        "gcp_instance_name": name,
        "gcp_zone": zone,
    }
    _copy_optional_text(
        record,
        attributes,
        {
            "status": "gcp_status",
            "creationTimestamp": "gcp_created_at",
            "cpuPlatform": "gcp_cpu_platform",
            "lastStartTimestamp": "gcp_last_started_at",
            "lastStopTimestamp": "gcp_last_stopped_at",
            "lastSuspendedTimestamp": "gcp_last_suspended_at",
        },
    )
    machine_type = _optional_text(record.get("machineType"), "machineType", maximum=512)
    if machine_type:
        attributes["gcp_machine_type"] = machine_type.rstrip("/").rsplit("/", 1)[-1]
    for source, target in {
        "canIpForward": "gcp_can_ip_forward",
        "deletionProtection": "gcp_deletion_protection",
    }.items():
        value = _optional_bool(record.get(source), source)
        if value is not None:
            attributes[target] = value
    if networks:
        attributes["gcp_networks"] = networks
    return NormalizedObservation(
        source_record_id=f"gcp:instance:{project_id}:{instance_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _network_context(value: Any) -> tuple[list[str], list[str]]:
    if value in (None, []):
        return [], []
    if not isinstance(value, list) or len(value) > 16:
        raise InventoryConnectorError("Google Cloud networkInterfaces is invalid")
    addresses: list[str] = []
    networks: list[str] = []
    for interface in value:
        if not isinstance(interface, dict):
            raise InventoryConnectorError("Google Cloud network interface is invalid")
        for field in ("networkIP", "ipv6Address"):
            raw = interface.get(field)
            if raw not in (None, ""):
                addresses.append(_ip(raw, field))
        network = _optional_text(interface.get("network"), "network", maximum=512)
        if network:
            networks.append(network.rstrip("/").rsplit("/", 1)[-1])
        access_configs = interface.get("accessConfigs", [])
        if not isinstance(access_configs, list) or len(access_configs) > 16:
            raise InventoryConnectorError("Google Cloud accessConfigs is invalid")
        for access in access_configs:
            if not isinstance(access, dict):
                raise InventoryConnectorError("Google Cloud access config is invalid")
            raw = access.get("natIP")
            if raw not in (None, ""):
                addresses.append(_ip(raw, "natIP"))
    return list(dict.fromkeys(addresses)), list(dict.fromkeys(networks))


def _ip(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Google Cloud {field} is invalid")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InventoryConnectorError(f"Google Cloud {field} is invalid") from exc


def _zone(value: Any) -> str:
    raw = _required_text(value, "zone", maximum=512).rstrip("/").rsplit("/", 1)[-1]
    if not _ZONE_RE.fullmatch(raw):
        raise InventoryConnectorError("Google Cloud zone is invalid")
    return raw


def _valid_scope(value: str) -> bool:
    return value.startswith("zones/") and bool(_ZONE_RE.fullmatch(value.split("/", 1)[1]))


def _uint64(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.isdigit() or value.startswith("0"):
        raise InventoryConnectorError(f"Google Cloud {field} is invalid")
    parsed = int(value)
    if not 0 < parsed <= 2**64 - 1:
        raise InventoryConnectorError(f"Google Cloud {field} is invalid")
    return str(parsed)


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        value = _optional_text(source.get(source_name), source_name, maximum=512)
        if value:
            target[target_name] = value


def _hostname(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.rstrip(".").lower()
    labels = candidate.split(".")
    if (
        len(candidate) > 253
        or not labels
        or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels)
    ):
        return None
    return candidate


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    result = _optional_text(value, field, maximum=maximum)
    if result is None:
        raise InventoryConnectorError(f"Google Cloud {field} is required")
    return result


def _private_key(value: Any) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError("Google Cloud private_key is required")
    result = value.strip()
    if (
        not result
        or len(result) > 16_384
        or "\x00" in result
        or "\r" in result
        or not result.startswith("-----BEGIN PRIVATE KEY-----")
        or not result.endswith("-----END PRIVATE KEY-----")
    ):
        raise InventoryConnectorError("Google Cloud private_key is invalid")
    return result


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Google Cloud {field} must be a string or null")
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 32 for character in result):
        raise InventoryConnectorError(f"Google Cloud {field} is invalid")
    return result


def _optional_bool(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Google Cloud {field} must be a boolean or null")
    return value


def _project(value: Any) -> str:
    if not isinstance(value, str) or not _PROJECT_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("Google Cloud project ID is invalid")
    return value.strip()


def _projects(value: Any, *, default: str) -> list[str]:
    if value is None:
        return [default]
    if not isinstance(value, list) or not value or len(value) > _MAX_PROJECTS:
        raise InventoryConnectorError(
            f"Google Cloud project_ids must contain 1-{_MAX_PROJECTS} project IDs"
        )
    result = [_project(item) for item in value]
    if len(result) != len(set(result)):
        raise InventoryConnectorError("Google Cloud project_ids must not contain duplicates")
    return result


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"Google Cloud {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"Google Cloud {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(
            f"Google Cloud {field} must be between {minimum} and {maximum}"
        )
    return parsed


def _safe_provider_error(exc: TicketHttpError, operation: str) -> str:
    message = str(exc).replace("ticket provider", "Google Cloud provider")
    message = message.replace("Ticket connector", "Google Cloud connector")
    return f"Google Cloud {operation} failed: {message}"
