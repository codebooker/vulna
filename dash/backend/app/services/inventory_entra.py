"""Read-only Microsoft Entra device inventory through bounded Microsoft Graph calls."""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlsplit

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]


@dataclass(frozen=True)
class _Cloud:
    authority_host: str
    graph_host: str


_CLOUDS = {
    "global": _Cloud("login.microsoftonline.com", "graph.microsoft.com"),
    "us_government": _Cloud("login.microsoftonline.us", "graph.microsoft.us"),
    "us_government_dod": _Cloud("login.microsoftonline.us", "dod-graph.microsoft.us"),
    "china": _Cloud("login.chinacloudapi.cn", "microsoftgraph.chinacloudapi.cn"),
}
_DEVICE_FIELDS = (
    "id",
    "accountEnabled",
    "approximateLastSignInDateTime",
    "deviceId",
    "deviceOwnership",
    "displayName",
    "enrollmentProfileName",
    "enrollmentType",
    "isCompliant",
    "isManaged",
    "managementType",
    "manufacturer",
    "model",
    "onPremisesLastSyncDateTime",
    "onPremisesSyncEnabled",
    "operatingSystem",
    "operatingSystemVersion",
    "profileType",
    "registrationDateTime",
    "systemLabels",
    "trustType",
)
_SELECT = ",".join(_DEVICE_FIELDS)
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_RECORDS = 10_000
_MAX_PAGE_SIZE = 999
_MAX_PAGES = 1_000
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "tenant_id",
        "client_id",
        "cloud",
        "timeout_seconds",
        "page_size",
        "record_limit",
        "include_disabled",
    }
)


class EntraInventoryAdapter:
    """Collect registered devices without exposing arbitrary Graph URLs or queries."""

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
        observations, received, cloud_name = await self._read(connector, secret, cursor={})
        return {
            "records_received": received,
            "records_visible": len(observations),
            "cloud": cloud_name,
            "permission": "Device.Read.All",
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
    ) -> tuple[list[NormalizedObservation], int, str]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("Microsoft Entra connector cursor must be empty")
        if connector.base_url:
            raise InventoryConnectorError("Microsoft Entra connector does not accept a base URL")
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError(
                "Microsoft Entra connector config contains unknown fields"
            )
        tenant_id = _uuid(config.get("tenant_id"), "tenant_id")
        client_id = _uuid(config.get("client_id"), "client_id")
        cloud_name, cloud = _cloud(config.get("cloud", "global"))
        if not secret:
            raise InventoryConnectorError("Microsoft Entra client secret is required")
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        page_size = _bounded_int(config.get("page_size", 500), "page_size", 1, _MAX_PAGE_SIZE)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        include_disabled = _boolean(config, "include_disabled", default=False)
        token = await self._access_token(
            cloud,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=secret,
            timeout_seconds=timeout_seconds,
        )
        records = await self._devices(
            cloud,
            token=token,
            page_size=page_size,
            record_limit=record_limit,
            timeout_seconds=timeout_seconds,
        )
        observed_at = datetime.now(UTC)
        observations = [
            observation
            for record in records
            if (
                observation := _observation(
                    record,
                    tenant_id=tenant_id,
                    observed_at=observed_at,
                    include_disabled=include_disabled,
                )
            )
            is not None
        ]
        return observations, len(records), cloud_name

    async def _access_token(
        self,
        cloud: _Cloud,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        timeout_seconds: int,
    ) -> str:
        url = f"https://{cloud.authority_host}/{tenant_id}/oauth2/v2.0/token"
        try:
            response = await self._sender(
                "POST",
                url,
                headers={"Accept": "application/json"},
                form_body={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                    "scope": f"https://{cloud.graph_host}/.default",
                },
                timeout_seconds=timeout_seconds,
                allow_private=False,
                user_agent="Vulna-Entra-Inventory/1",
            )
        except TicketHttpError as exc:
            raise InventoryConnectorError(_safe_provider_error(exc, "authentication")) from exc
        if not isinstance(response.data, dict):
            raise InventoryConnectorError("Microsoft Entra authentication returned invalid JSON")
        token = response.data.get("access_token")
        token_type = response.data.get("token_type")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 32_768
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise InventoryConnectorError("Microsoft Entra authentication response is invalid")
        return token

    async def _devices(
        self,
        cloud: _Cloud,
        *,
        token: str,
        page_size: int,
        record_limit: int,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        query = urlencode({"$select": _SELECT, "$top": str(page_size)})
        url: str | None = f"https://{cloud.graph_host}/v1.0/devices?{query}"
        records: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        pages = 0
        while url is not None:
            url = _validated_devices_url(url, cloud=cloud, first_page=pages == 0)
            if url in seen_urls:
                raise InventoryConnectorError("Microsoft Graph device pagination repeated a page")
            seen_urls.add(url)
            pages += 1
            if pages > _MAX_PAGES:
                raise InventoryConnectorError(
                    "Microsoft Graph device pagination exceeded its limit"
                )
            try:
                response = await self._sender(
                    "GET",
                    url,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    timeout_seconds=timeout_seconds,
                    allow_private=False,
                    user_agent="Vulna-Entra-Inventory/1",
                )
            except TicketHttpError as exc:
                raise InventoryConnectorError(_safe_provider_error(exc, "device read")) from exc
            page, next_url = _device_page(response.data, page_size=page_size)
            if len(records) + len(page) > record_limit:
                raise InventoryConnectorError(
                    "Microsoft Graph device read exceeded the record limit"
                )
            records.extend(page)
            url = next_url
        return records


def _validated_devices_url(url: str, *, cloud: _Cloud, first_page: bool) -> str:
    if not isinstance(url, str) or len(url) > 8192:
        raise InventoryConnectorError("Microsoft Graph device page URL is invalid")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise InventoryConnectorError("Microsoft Graph device page URL is invalid") from exc
    if (
        parts.scheme != "https"
        or parts.hostname != cloud.graph_host
        or parts.username
        or parts.password
        or port not in (None, 443)
        or parts.path != "/v1.0/devices"
        or parts.fragment
    ):
        raise InventoryConnectorError("Microsoft Graph device page escaped its fixed endpoint")
    try:
        query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise InventoryConnectorError("Microsoft Graph device page query is invalid") from exc
    if set(query) - {"$select", "$top", "$skiptoken"} or any(
        len(values) != 1 for values in query.values()
    ):
        raise InventoryConnectorError("Microsoft Graph device page query is not allowed")
    if "$select" in query and query["$select"][0] != _SELECT:
        raise InventoryConnectorError("Microsoft Graph device page changed the field allowlist")
    if "$top" in query:
        _bounded_int(query["$top"][0], "$top", 1, _MAX_PAGE_SIZE)
    if first_page:
        if set(query) != {"$select", "$top"}:
            raise InventoryConnectorError("Microsoft Graph first device page is invalid")
    else:
        skiptoken = query.get("$skiptoken", [""])[0]
        if not skiptoken or len(skiptoken) > 4096 or any(ord(char) < 32 for char in skiptoken):
            raise InventoryConnectorError("Microsoft Graph device pagination token is invalid")
    return url


def _device_page(value: Any, *, page_size: int) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(value, dict) or not isinstance(value.get("value"), list):
        raise InventoryConnectorError("Microsoft Graph device response is invalid")
    raw_page = value["value"]
    if len(raw_page) > page_size or not all(isinstance(item, dict) for item in raw_page):
        raise InventoryConnectorError("Microsoft Graph device page exceeded its requested size")
    next_url = value.get("@odata.nextLink")
    if next_url is not None and not isinstance(next_url, str):
        raise InventoryConnectorError("Microsoft Graph device next link is invalid")
    return cast(list[dict[str, Any]], raw_page), next_url


def _observation(
    record: dict[str, Any],
    *,
    tenant_id: str,
    observed_at: datetime,
    include_disabled: bool,
) -> NormalizedObservation | None:
    object_id = _uuid(record.get("id"), "device id")
    account_enabled = _optional_bool(record.get("accountEnabled"), "accountEnabled")
    if account_enabled is False and not include_disabled:
        return None
    device_id = _optional_uuid(record.get("deviceId"), "deviceId")
    immutable_id = device_id or object_id
    display_name = _optional_text(record.get("displayName"), "displayName", maximum=256)
    identifiers: list[dict[str, Any]] = [
        {"type": "cloud_instance_id", "value": f"entra:{tenant_id}:{immutable_id}"}
    ]
    hostname = _hostname(display_name)
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    attributes: dict[str, Any] = {
        "canonical_name": hostname or display_name or immutable_id,
        "entra_object_id": object_id,
        "entra_tenant_id": tenant_id,
        "entra_account_enabled": account_enabled,
    }
    if device_id:
        attributes["entra_device_id"] = device_id
    _copy_text_fields(
        record,
        attributes,
        {
            "approximateLastSignInDateTime": "entra_approximate_last_sign_in_at",
            "deviceOwnership": "entra_device_ownership",
            "enrollmentProfileName": "entra_enrollment_profile_name",
            "enrollmentType": "entra_enrollment_type",
            "managementType": "entra_management_type",
            "manufacturer": "manufacturer",
            "model": "model",
            "onPremisesLastSyncDateTime": "entra_on_premises_last_sync_at",
            "operatingSystem": "operating_system",
            "operatingSystemVersion": "operating_system_version",
            "profileType": "entra_profile_type",
            "registrationDateTime": "entra_registration_at",
            "trustType": "entra_trust_type",
        },
    )
    for source, target in {
        "isCompliant": "entra_is_compliant",
        "isManaged": "entra_is_managed",
        "onPremisesSyncEnabled": "entra_on_premises_sync_enabled",
    }.items():
        value = _optional_bool(record.get(source), source)
        if value is not None:
            attributes[target] = value
    labels = _text_list(record.get("systemLabels"), "systemLabels")
    if labels:
        attributes["entra_system_labels"] = labels
    return NormalizedObservation(
        source_record_id=f"entra:{object_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _copy_text_fields(
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
    if len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return candidate


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Microsoft Entra {field} must be a UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError(f"Microsoft Entra {field} must be a UUID") from exc


def _optional_uuid(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    return _uuid(value, field)


def _cloud(value: Any) -> tuple[str, _Cloud]:
    if not isinstance(value, str) or value not in _CLOUDS:
        raise InventoryConnectorError(
            "Microsoft Entra cloud must be global, us_government, us_government_dod, or china"
        )
    return value, _CLOUDS[value]


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"Microsoft Entra {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"Microsoft Entra {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(
            f"Microsoft Entra {field} must be between {minimum} and {maximum}"
        )
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Microsoft Entra {key} must be a boolean")
    return value


def _optional_bool(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Microsoft Graph {field} must be a boolean or null")
    return value


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Microsoft Graph {field} must be a string or null")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise InventoryConnectorError(f"Microsoft Graph {field} is invalid")
    return normalized


def _text_list(value: Any, field: str) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 50:
        raise InventoryConnectorError(f"Microsoft Graph {field} must be a bounded string list")
    result = [_optional_text(item, field, maximum=256) for item in value]
    if any(item is None for item in result):
        raise InventoryConnectorError(f"Microsoft Graph {field} contains an invalid value")
    return cast(list[str], result)


def _safe_provider_error(exc: TicketHttpError, operation: str) -> str:
    message = str(exc).replace("ticket provider", "Microsoft Graph")
    message = message.replace("Ticket connector", "Microsoft Entra connector")
    return f"Microsoft Entra {operation} failed: {message}"
