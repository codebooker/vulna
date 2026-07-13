"""Read-only UniFi Network device and connected-client inventory adapter."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_REMOTE_ROOT_RE = re.compile(
    r"^/v1/connector/consoles/[A-Za-z0-9:_-]{1,255}/proxy/network/integration$"
)
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "site_id",
        "allow_private",
        "include_devices",
        "include_clients",
        "page_size",
        "timeout_seconds",
        "record_limit",
    }
)
_MAX_PAGE_SIZE = 200
_MAX_RECORDS = 10_000
_MAX_PAGES = 1_000


class UnifiInventoryAdapter:
    """Collect two fixed official UniFi Network resources with GET requests only."""

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
        observations, received, device_count, client_count = await self._read(
            connector, secret, cursor={}
        )
        return {
            "records_received": received,
            "records_visible": len(observations),
            "devices_received": device_count,
            "connected_clients_received": client_count,
            "resources": ["adopted devices", "connected clients"],
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
        observations, _, _, _ = await self._read(connector, secret, cursor=cursor)
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], int, int, int]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("UniFi connector cursor must be empty")
        if not connector.base_url:
            raise InventoryConnectorError("UniFi connector requires a Network Integration API root")
        api_root = _api_root(connector.base_url)
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("UniFi connector config contains unknown fields")
        site_id = _uuid(config.get("site_id"), "site_id")
        if not secret:
            raise InventoryConnectorError("UniFi API key is required")
        page_size = _bounded_int(config.get("page_size", 100), "page_size", 1, _MAX_PAGE_SIZE)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        allow_private = _boolean(config, "allow_private", default=False)
        include_devices = _boolean(config, "include_devices", default=True)
        include_clients = _boolean(config, "include_clients", default=True)
        if not include_devices and not include_clients:
            raise InventoryConnectorError("UniFi connector must include devices or clients")

        devices: list[dict[str, Any]] = []
        clients: list[dict[str, Any]] = []
        if include_devices:
            devices = await self._pages(
                api_root,
                site_id=site_id,
                resource="devices",
                api_key=secret,
                page_size=page_size,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                record_limit=record_limit,
                already_received=0,
            )
        if include_clients:
            clients = await self._pages(
                api_root,
                site_id=site_id,
                resource="clients",
                api_key=secret,
                page_size=page_size,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                record_limit=record_limit,
                already_received=len(devices),
            )
        observed_at = datetime.now(UTC)
        observations = [
            *(
                _device_observation(item, site_id=site_id, observed_at=observed_at)
                for item in devices
            ),
            *(
                observation
                for item in clients
                if (
                    observation := _client_observation(
                        item, site_id=site_id, observed_at=observed_at
                    )
                )
                is not None
            ),
        ]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("UniFi pagination returned a duplicate source record")
        return observations, len(devices) + len(clients), len(devices), len(clients)

    async def _pages(
        self,
        api_root: str,
        *,
        site_id: str,
        resource: str,
        api_key: str,
        page_size: int,
        timeout_seconds: int,
        allow_private: bool,
        record_limit: int,
        already_received: int,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        offset = 0
        pages = 0
        while True:
            pages += 1
            if pages > _MAX_PAGES:
                raise InventoryConnectorError("UniFi pagination exceeded its page limit")
            query = urlencode({"offset": str(offset), "limit": str(page_size)})
            url = f"{api_root}/v1/sites/{site_id}/{resource}?{query}"
            try:
                response = await self._sender(
                    "GET",
                    url,
                    headers={"Accept": "application/json", "X-API-Key": api_key},
                    timeout_seconds=timeout_seconds,
                    allow_private=allow_private,
                    user_agent="Vulna-UniFi-Inventory/1",
                )
            except TicketHttpError as exc:
                safe = str(exc).replace("ticket provider", "UniFi Network provider")
                safe = safe.replace("Ticket connector", "UniFi connector")
                raise InventoryConnectorError(safe) from exc
            page, total_count = _page(
                response.data,
                expected_offset=offset,
                requested_limit=page_size,
                resource=resource,
            )
            if already_received + total_count > record_limit:
                raise InventoryConnectorError("UniFi collection exceeded the combined record limit")
            if len(records) + len(page) > total_count:
                raise InventoryConnectorError("UniFi pagination returned inconsistent totals")
            records.extend(page)
            next_offset = offset + len(page)
            if next_offset >= total_count:
                return records
            if not page or next_offset <= offset:
                raise InventoryConnectorError("UniFi pagination did not advance")
            offset = next_offset


def _api_root(value: str) -> str:
    parts = urlsplit(value)
    path = parts.path.rstrip("/")
    remote = _REMOTE_ROOT_RE.fullmatch(path) is not None
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or "%" in path
        or "//" in path
        or (path != "/proxy/network/integration" and not remote)
        or (remote and parts.hostname.lower() != "api.ui.com")
    ):
        raise InventoryConnectorError(
            "UniFi API root must be an HTTPS local or cloud /proxy/network/integration URL"
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise InventoryConnectorError("UniFi API root contains an invalid port") from exc
    netloc = parts.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit(("https", netloc, path, "", ""))


def _page(
    value: Any,
    *,
    expected_offset: int,
    requested_limit: int,
    resource: str,
) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise InventoryConnectorError(f"UniFi {resource} response is invalid")
    offset = _response_int(value.get("offset"), "offset")
    limit = _response_int(value.get("limit"), "limit")
    count = _response_int(value.get("count"), "count")
    total_count = _response_int(value.get("totalCount"), "totalCount")
    raw = value["data"]
    if (
        offset != expected_offset
        or not 1 <= limit <= requested_limit
        or count != len(raw)
        or count > limit
        or total_count < offset + count
        or not all(isinstance(item, dict) for item in raw)
    ):
        raise InventoryConnectorError(f"UniFi {resource} pagination metadata is invalid")
    return cast(list[dict[str, Any]], raw), total_count


def _device_observation(
    value: dict[str, Any], *, site_id: str, observed_at: datetime
) -> NormalizedObservation:
    device_id = _uuid(value.get("id"), "device id")
    mac = _mac(value.get("macAddress"), required=True)
    address = _ip(value.get("ipAddress"), "device ipAddress")
    name = _optional_text(value.get("name"), "device name", maximum=256)
    hostname = _hostname(name)
    identifiers: list[dict[str, Any]] = [{"type": "mac_address", "value": mac}]
    if address:
        identifiers.append({"type": "ip_address", "value": address})
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
        identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name or mac,
        "asset_type": "network_device",
        "manufacturer": "Ubiquiti",
        "unifi_site_id": site_id,
        "unifi_device_id": device_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "model": "model",
            "state": "unifi_state",
            "firmwareVersion": "firmware_version",
        },
    )
    for source, target in {
        "supported": "unifi_supported",
        "firmwareUpdatable": "firmware_updatable",
    }.items():
        item = _optional_bool(value.get(source), f"device {source}")
        if item is not None:
            attributes[target] = item
    for source, target in {
        "features": "unifi_features",
        "interfaces": "unifi_interfaces",
    }.items():
        items = _text_list(value.get(source), f"device {source}")
        if items:
            attributes[target] = items
    return NormalizedObservation(
        source_record_id=f"unifi:device:{site_id}:{device_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _client_observation(
    value: dict[str, Any], *, site_id: str, observed_at: datetime
) -> NormalizedObservation | None:
    client_id = _uuid(value.get("id"), "client id")
    mac = _mac(value.get("macAddress"), required=False)
    address = _ip(value.get("ipAddress"), "client ipAddress")
    name = _optional_text(value.get("name"), "client name", maximum=256)
    hostname = _hostname(name)
    identifiers: list[dict[str, Any]] = []
    if mac:
        identifiers.append({"type": "mac_address", "value": mac})
    if address:
        identifiers.append({"type": "ip_address", "value": address})
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
    if not identifiers:
        return None
    attributes: dict[str, Any] = {
        "canonical_name": hostname or name or mac or address or client_id,
        "unifi_site_id": site_id,
        "unifi_client_id": client_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "type": "unifi_client_type",
            "connectedAt": "unifi_connected_at",
        },
    )
    uplink_device_id = value.get("uplinkDeviceId")
    if uplink_device_id not in (None, ""):
        attributes["unifi_uplink_device_id"] = _uuid(uplink_device_id, "client uplinkDeviceId")
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
        source_record_id=f"unifi:client:{site_id}:{client_id}",
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


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"UniFi {field} must be a UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError(f"UniFi {field} must be a UUID") from exc


def _mac(value: Any, *, required: bool) -> str | None:
    if value in (None, "") and not required:
        return None
    if not isinstance(value, str) or not _MAC_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("UniFi MAC address is invalid")
    return value.strip().replace("-", ":").lower()


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
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise InventoryConnectorError(f"UniFi {field} is invalid")
    return normalized


def _text_list(value: Any, field: str) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 50:
        raise InventoryConnectorError(f"UniFi {field} must be a bounded string list")
    result = [_optional_text(item, field, maximum=128) for item in value]
    if any(item is None for item in result):
        raise InventoryConnectorError(f"UniFi {field} contains an invalid value")
    return cast(list[str], result)


def _optional_bool(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"UniFi {field} must be a boolean or null")
    return value


def _response_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InventoryConnectorError(f"UniFi response {field} must be a non-negative integer")
    return int(value)


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


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"UniFi {key} must be a boolean")
    return value
