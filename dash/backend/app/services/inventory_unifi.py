"""Read-only UniFi Site Manager device inventory adapter."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_DEVICES_URL = "https://api.ui.com/v1/devices"
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_CONFIG_FIELDS = frozenset({"host_ids", "page_size", "timeout_seconds", "record_limit"})
_MAX_HOST_IDS = 100
_MAX_PAGE_SIZE = 200
_MAX_RECORDS = 10_000
_MAX_PAGES = 1_000
_MAX_NEXT_TOKEN = 4_096
_MAX_API_KEY = 4_096


class UnifiInventoryAdapter:
    """Collect the fixed Site Manager device resource with GET requests only."""

    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        observations, received, hosts = await self._read(
            connector,
            secret,
            cursor={},
            source_data=source_data,
        )
        return {
            "records_received": received,
            "records_visible": len(observations),
            "devices_received": received,
            "hosts_received": hosts,
            "resource": "Site Manager devices",
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
        observations, _, _ = await self._read(
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
    ) -> tuple[list[NormalizedObservation], int, int]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("UniFi connector cursor must be empty")
        if source_data is not None:
            raise InventoryConnectorError("UniFi connector does not accept source data")
        if connector.base_url:
            raise InventoryConnectorError(
                "UniFi Site Manager uses the fixed https://api.ui.com endpoint and does not "
                "accept a base URL"
            )
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("UniFi connector config contains unknown fields")
        api_key = _api_key(secret)
        host_ids = _host_ids(config.get("host_ids"))
        page_size = _bounded_int(config.get("page_size", 100), "page_size", 1, _MAX_PAGE_SIZE)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        records, host_count = await self._pages(
            api_key=api_key,
            host_ids=host_ids,
            page_size=page_size,
            timeout_seconds=timeout_seconds,
            record_limit=record_limit,
        )
        observed_at = datetime.now(UTC)
        observations = [
            _device_observation(
                item,
                host_id=host_id,
                host_name=host_name,
                host_updated_at=host_updated_at,
                observed_at=observed_at,
            )
            for item, host_id, host_name, host_updated_at in records
        ]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("UniFi Site Manager returned a duplicate device")
        return observations, len(records), host_count

    async def _pages(
        self,
        *,
        api_key: str,
        host_ids: list[str],
        page_size: int,
        timeout_seconds: int,
        record_limit: int,
    ) -> tuple[list[tuple[dict[str, Any], str, str | None, str | None]], int]:
        records: list[tuple[dict[str, Any], str, str | None, str | None]] = []
        next_token: str | None = None
        seen_tokens: set[str] = set()
        host_count = 0
        pages = 0
        while True:
            pages += 1
            if pages > _MAX_PAGES:
                raise InventoryConnectorError("UniFi Site Manager pagination exceeded its limit")
            query: list[tuple[str, str]] = []
            if host_ids:
                query.append(("hostIds[]", ",".join(host_ids)))
            query.append(("pageSize", str(page_size)))
            if next_token is not None:
                query.append(("nextToken", next_token))
            url = f"{_DEVICES_URL}?{urlencode(query)}"
            try:
                response = await self._sender(
                    "GET",
                    url,
                    headers={"Accept": "application/json", "X-API-Key": api_key},
                    timeout_seconds=timeout_seconds,
                    allow_private=False,
                    user_agent="Vulna-UniFi-Site-Manager-Inventory/1",
                )
            except TicketHttpError as exc:
                safe = str(exc).replace("ticket provider", "UniFi Site Manager provider")
                safe = safe.replace("Ticket connector", "UniFi connector")
                raise InventoryConnectorError(safe) from exc
            hosts, returned_token = _page(response.data, page_size=page_size)
            host_count += len(hosts)
            for host in hosts:
                host_id, host_name, host_updated_at, devices = _host_devices(host)
                if len(records) + len(devices) > record_limit:
                    raise InventoryConnectorError(
                        "UniFi Site Manager device read exceeded the record limit"
                    )
                records.extend((device, host_id, host_name, host_updated_at) for device in devices)
            if returned_token is None:
                return records, host_count
            if returned_token in seen_tokens:
                raise InventoryConnectorError(
                    "UniFi Site Manager pagination repeated a continuation token"
                )
            seen_tokens.add(returned_token)
            next_token = returned_token


def _page(value: Any, *, page_size: int) -> tuple[list[dict[str, Any]], str | None]:
    if (
        not isinstance(value, dict)
        or value.get("httpStatusCode") != 200
        or not isinstance(value.get("data"), list)
    ):
        raise InventoryConnectorError("UniFi Site Manager devices response is invalid")
    raw = value["data"]
    if len(raw) > page_size or not all(isinstance(item, dict) for item in raw):
        raise InventoryConnectorError("UniFi Site Manager devices page is invalid")
    token = value.get("nextToken")
    if token is not None and (
        not isinstance(token, str)
        or not 1 <= len(token) <= _MAX_NEXT_TOKEN
        or any(ord(char) < 32 or ord(char) == 127 for char in token)
    ):
        raise InventoryConnectorError("UniFi Site Manager continuation token is invalid")
    return cast(list[dict[str, Any]], raw), token


def _host_devices(
    value: dict[str, Any],
) -> tuple[str, str | None, str | None, list[dict[str, Any]]]:
    host_id = _provider_id(value.get("hostId"), "hostId", pattern=_HOST_ID_RE)
    host_name = _optional_text(value.get("hostName"), "hostName", maximum=256)
    host_updated_at = _optional_text(value.get("updatedAt"), "updatedAt", maximum=128)
    devices = value.get("devices")
    if not isinstance(devices, list) or not all(isinstance(item, dict) for item in devices):
        raise InventoryConnectorError("UniFi Site Manager host devices must be a list")
    return host_id, host_name, host_updated_at, cast(list[dict[str, Any]], devices)


def _device_observation(
    value: dict[str, Any],
    *,
    host_id: str,
    host_name: str | None,
    host_updated_at: str | None,
    observed_at: datetime,
) -> NormalizedObservation:
    device_id = _provider_id(value.get("id"), "device id", pattern=_DEVICE_ID_RE)
    mac = _mac(value.get("mac"), required=False)
    if mac is None and re.fullmatch(r"[0-9A-Fa-f]{12}", device_id):
        mac = _mac(device_id, required=True)
    address = _ip(value.get("ip"), "device ip")
    name = _optional_text(value.get("name"), "device name", maximum=256)
    hostname = _hostname(name)
    identifiers: list[dict[str, Any]] = []
    if mac:
        identifiers.append({"type": "mac_address", "value": mac})
    if address:
        identifiers.append({"type": "ip_address", "value": address})
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name or mac or address or device_id,
        "asset_type": "network_device",
        "manufacturer": "Ubiquiti",
        "unifi_host_id": host_id,
        "unifi_device_id": device_id,
    }
    if host_name:
        attributes["unifi_host_name"] = host_name
    if host_updated_at:
        attributes["unifi_host_updated_at"] = host_updated_at
    _copy_optional_text(
        value,
        attributes,
        {
            "model": "model",
            "shortname": "unifi_shortname",
            "productLine": "unifi_product_line",
            "status": "unifi_status",
            "version": "firmware_version",
            "firmwareStatus": "unifi_firmware_status",
            "startupTime": "unifi_startup_time",
            "adoptionTime": "unifi_adoption_time",
            "note": "unifi_note",
        },
    )
    for source, target in {
        "isConsole": "unifi_is_console",
        "isManaged": "unifi_is_managed",
    }.items():
        item = _optional_bool(value.get(source), f"device {source}")
        if item is not None:
            attributes[target] = item
    return NormalizedObservation(
        source_record_id=f"unifi:device:{host_id}:{device_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        item = _optional_text(source.get(source_name), source_name, maximum=512)
        if item:
            target[target_name] = item


def _host_ids(value: Any) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_HOST_IDS:
        raise InventoryConnectorError("UniFi host_ids must be a bounded string list")
    result = [_provider_id(item, "host_ids entry", pattern=_HOST_ID_RE) for item in value]
    if len(result) != len(set(result)):
        raise InventoryConnectorError("UniFi host_ids must not contain duplicates")
    return result


def _api_key(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_API_KEY
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InventoryConnectorError("UniFi Site Manager API key is required")
    return value


def _provider_id(value: Any, field: str, *, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value.strip()):
        raise InventoryConnectorError(f"UniFi {field} is invalid")
    return value.strip()


def _mac(value: Any, *, required: bool) -> str | None:
    if value in (None, "") and not required:
        return None
    if not isinstance(value, str) or not _MAC_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("UniFi MAC address is invalid")
    compact = value.strip().replace("-", "").replace(":", "").lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _ip(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"UniFi {field} is invalid")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InventoryConnectorError(f"UniFi {field} is invalid") from exc


def _hostname(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.rstrip(".").lower()
    if len(candidate) > 253 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in candidate.split(".")
    ):
        return None
    return candidate


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"UniFi {field} must be a string or null")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in normalized)
    ):
        raise InventoryConnectorError(f"UniFi {field} is invalid")
    return normalized


def _optional_bool(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"UniFi {field} must be a boolean or null")
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"UniFi {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"UniFi {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"UniFi {field} must be between {minimum} and {maximum}")
    return parsed
