"""Read-only, site-scoped UniFi Network inventory adapter."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote, urlencode

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_SITES_URL = "https://api.ui.com/v1/sites"
_CONNECTOR_ROOT = "https://api.ui.com/v1/connector/consoles"
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_ALLOWED_CONFIG_FIELDS = frozenset(
    {"host_id", "site_id", "page_size", "timeout_seconds", "record_limit"}
)
_MAX_PAGE_SIZE = 200
_MAX_RECORDS = 10_000
_MAX_SITES = 1_000
_MAX_PAGES = 1_000
_MAX_NEXT_TOKEN = 4_096
_MAX_API_KEY = 4_096


class UnifiInventoryAdapter:
    """Collect one explicitly mapped UniFi Network site with GET requests only."""

    def __init__(self, sender: SendJson = request_json) -> None:
        self._sender = sender

    async def discover_sites(self, secret: str | None) -> list[dict[str, str]]:
        """Return bounded Site Manager console/site pairs available to an API key."""

        api_key = _api_key(secret)
        sites: list[dict[str, str]] = []
        next_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(_MAX_PAGES):
            query = [("pageSize", str(_MAX_PAGE_SIZE))]
            if next_token is not None:
                query.append(("nextToken", next_token))
            response = await self._get(
                f"{_SITES_URL}?{urlencode(query)}", api_key=api_key, timeout_seconds=15
            )
            page, returned_token = _site_manager_page(response.data, page_size=_MAX_PAGE_SIZE)
            if len(sites) + len(page) > _MAX_SITES:
                raise InventoryConnectorError("UniFi Site Manager site read exceeded its limit")
            sites.extend(_site_summary(item) for item in page)
            if returned_token is None:
                break
            if returned_token in seen_tokens:
                raise InventoryConnectorError(
                    "UniFi Site Manager pagination repeated a continuation token"
                )
            seen_tokens.add(returned_token)
            next_token = returned_token
        else:
            raise InventoryConnectorError("UniFi Site Manager pagination exceeded its limit")
        keys = [(site["host_id"], site["site_id"]) for site in sites]
        if len(keys) != len(set(keys)):
            raise InventoryConnectorError("UniFi Site Manager returned a duplicate site")
        return sorted(sites, key=lambda item: (item["name"].casefold(), item["site_id"]))

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        observations, device_count, client_count = await self._read(
            connector,
            secret,
            cursor={},
            source_data=source_data,
        )
        return {
            "records_received": len(observations),
            "records_visible": len(observations),
            "devices_received": device_count,
            "clients_received": client_count,
            "sites_received": 1,
            "resource": "UniFi Network site devices and connected clients",
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
                "UniFi uses the fixed https://api.ui.com endpoint and does not accept a base URL"
            )
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("UniFi connector config contains unknown fields")
        api_key = _api_key(secret)
        host_id = _required_provider_id(config.get("host_id"), "host_id")
        site_id = _required_provider_id(config.get("site_id"), "site_id")
        page_size = _bounded_int(config.get("page_size", 100), "page_size", 1, _MAX_PAGE_SIZE)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        escaped_host = quote(host_id, safe="")
        escaped_site = quote(site_id, safe="")
        site_root = (
            f"{_CONNECTOR_ROOT}/{escaped_host}/proxy/network/integration/v1/sites/{escaped_site}"
        )
        devices = await self._network_pages(
            f"{site_root}/devices",
            api_key=api_key,
            page_size=page_size,
            timeout_seconds=timeout_seconds,
            record_limit=record_limit,
            resource="devices",
        )
        clients = await self._network_pages(
            f"{site_root}/clients",
            api_key=api_key,
            page_size=page_size,
            timeout_seconds=timeout_seconds,
            record_limit=record_limit - len(devices),
            resource="clients",
        )
        observed_at = datetime.now(UTC)
        observations = [
            _device_observation(item, host_id=host_id, site_id=site_id, observed_at=observed_at)
            for item in devices
        ]
        observations.extend(
            _client_observation(item, host_id=host_id, site_id=site_id, observed_at=observed_at)
            for item in clients
        )
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("UniFi Network returned a duplicate inventory record")
        return observations, len(devices), len(clients)

    async def _network_pages(
        self,
        base_url: str,
        *,
        api_key: str,
        page_size: int,
        timeout_seconds: int,
        record_limit: int,
        resource: str,
    ) -> list[dict[str, Any]]:
        if record_limit < 0:
            raise InventoryConnectorError("UniFi Network inventory read exceeded the record limit")
        records: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            url = f"{base_url}?{urlencode([('offset', offset), ('limit', page_size)])}"
            response = await self._get(url, api_key=api_key, timeout_seconds=timeout_seconds)
            page, total_count = _network_page(
                response.data, expected_offset=offset, page_size=page_size, resource=resource
            )
            if total_count > record_limit or len(records) + len(page) > record_limit:
                raise InventoryConnectorError(
                    "UniFi Network inventory read exceeded the record limit"
                )
            records.extend(page)
            offset += len(page)
            if offset >= total_count:
                return records
            if not page:
                raise InventoryConnectorError(
                    f"UniFi Network {resource} pagination stopped before completion"
                )
        raise InventoryConnectorError("UniFi Network pagination exceeded its limit")

    async def _get(self, url: str, *, api_key: str, timeout_seconds: int) -> JsonResponse:
        try:
            return await self._sender(
                "GET",
                url,
                headers={"Accept": "application/json", "X-API-Key": api_key},
                timeout_seconds=timeout_seconds,
                allow_private=False,
                user_agent="Vulna-UniFi-Inventory/2",
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "UniFi provider")
            safe = safe.replace("Ticket connector", "UniFi connector")
            raise InventoryConnectorError(safe) from exc


def _site_manager_page(value: Any, *, page_size: int) -> tuple[list[dict[str, Any]], str | None]:
    if (
        not isinstance(value, dict)
        or value.get("httpStatusCode") != 200
        or not isinstance(value.get("data"), list)
    ):
        raise InventoryConnectorError("UniFi Site Manager sites response is invalid")
    raw = value["data"]
    if len(raw) > page_size or not all(isinstance(item, dict) for item in raw):
        raise InventoryConnectorError("UniFi Site Manager sites page is invalid")
    token = value.get("nextToken")
    if token is not None and (
        not isinstance(token, str)
        or not 1 <= len(token) <= _MAX_NEXT_TOKEN
        or any(ord(char) < 32 or ord(char) == 127 for char in token)
    ):
        raise InventoryConnectorError("UniFi Site Manager continuation token is invalid")
    return cast(list[dict[str, Any]], raw), token


def _site_summary(value: dict[str, Any]) -> dict[str, str]:
    host_id = _required_provider_id(value.get("hostId"), "site hostId")
    site_id = _required_provider_id(value.get("siteId"), "site siteId")
    meta = value.get("meta")
    if meta is not None and not isinstance(meta, dict):
        raise InventoryConnectorError("UniFi site meta must be an object or null")
    name = _optional_text((meta or {}).get("name"), "site name", maximum=256)
    return {"host_id": host_id, "site_id": site_id, "name": name or site_id}


def _network_page(
    value: Any, *, expected_offset: int, page_size: int, resource: str
) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise InventoryConnectorError(f"UniFi Network {resource} response is invalid")
    offset = _response_int(value.get("offset"), f"{resource} offset")
    count = _response_int(value.get("count"), f"{resource} count")
    total_count = _response_int(value.get("totalCount"), f"{resource} totalCount")
    raw = value["data"]
    if (
        offset != expected_offset
        or count != len(raw)
        or count > page_size
        or total_count < expected_offset + count
        or not all(isinstance(item, dict) for item in raw)
    ):
        raise InventoryConnectorError(f"UniFi Network {resource} page is invalid")
    return cast(list[dict[str, Any]], raw), total_count


def _device_observation(
    value: dict[str, Any], *, host_id: str, site_id: str, observed_at: datetime
) -> NormalizedObservation:
    device_id = _required_provider_id(value.get("id"), "device id")
    mac = _mac(value.get("macAddress"), required=False)
    address = _ip(value.get("ipAddress"), "device ipAddress")
    name = _optional_text(value.get("name"), "device name", maximum=256)
    hostname = _hostname(name)
    identifiers = _identifiers(mac=mac, address=address, hostname=hostname)
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name or mac or address or device_id,
        "asset_type": "network_device",
        "manufacturer": "Ubiquiti",
        "unifi_host_id": host_id,
        "unifi_site_id": site_id,
        "unifi_device_id": device_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "model": "model",
            "state": "unifi_status",
            "firmwareVersion": "firmware_version",
        },
    )
    for source, target in {
        "supported": "unifi_supported",
        "firmwareUpdatable": "unifi_firmware_updatable",
    }.items():
        item = _optional_bool(value.get(source), f"device {source}")
        if item is not None:
            attributes[target] = item
    for source, target in {"features": "unifi_features", "interfaces": "unifi_interfaces"}.items():
        string_items = _optional_string_list(value.get(source), f"device {source}")
        if string_items:
            attributes[target] = string_items
    return NormalizedObservation(
        source_record_id=f"unifi:device:{host_id}:{site_id}:{device_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _client_observation(
    value: dict[str, Any], *, host_id: str, site_id: str, observed_at: datetime
) -> NormalizedObservation:
    client_id = _required_provider_id(value.get("id"), "client id")
    mac = _mac(value.get("macAddress"), required=False)
    address = _ip(value.get("ipAddress"), "client ipAddress")
    name = _optional_text(value.get("name"), "client name", maximum=256)
    hostname = _hostname(name)
    identifiers = _identifiers(mac=mac, address=address, hostname=hostname)
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name or mac or address or client_id,
        "asset_type": "unknown",
        "unifi_host_id": host_id,
        "unifi_site_id": site_id,
        "unifi_client_id": client_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "type": "unifi_client_type",
            "connectedAt": "unifi_connected_at",
            "uplinkDeviceId": "unifi_uplink_device_id",
        },
    )
    access = value.get("access")
    if access is not None:
        if not isinstance(access, dict):
            raise InventoryConnectorError("UniFi client access must be an object or null")
        access_type = _optional_text(access.get("type"), "client access type", maximum=64)
        authorized = _optional_bool(access.get("authorized"), "client access authorized")
        if access_type:
            attributes["unifi_access_type"] = access_type
        if authorized is not None:
            attributes["unifi_access_authorized"] = authorized
    return NormalizedObservation(
        source_record_id=f"unifi:client:{host_id}:{site_id}:{client_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _identifiers(
    *, mac: str | None, address: str | None, hostname: str | None
) -> list[dict[str, Any]]:
    identifiers: list[dict[str, Any]] = []
    if mac:
        identifiers.append({"type": "mac_address", "value": mac})
    if address:
        identifiers.append({"type": "ip_address", "value": address})
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    return identifiers


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        item = _optional_text(source.get(source_name), source_name, maximum=512)
        if item:
            target[target_name] = item


def _api_key(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_API_KEY
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InventoryConnectorError("UniFi Site Manager API key is required")
    return value


def _required_provider_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _PROVIDER_ID_RE.fullmatch(value.strip()):
        raise InventoryConnectorError(f"UniFi {field} is required or invalid")
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


def _optional_string_list(value: Any, field: str) -> list[str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) > 256
        or not all(
            isinstance(item, str)
            and 1 <= len(item.strip()) <= 128
            and not any(ord(char) < 32 or ord(char) == 127 for char in item)
            for item in value
        )
    ):
        raise InventoryConnectorError(f"UniFi {field} must be a bounded string list or null")
    return [item.strip() for item in value]


def _response_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InventoryConnectorError(f"UniFi Network {field} is invalid")
    return cast(int, value)


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
