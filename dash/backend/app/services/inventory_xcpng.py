"""Read-only XCP-ng inventory adapter using Xen Orchestra's REST API."""

from __future__ import annotations

import ipaddress
import re
import ssl
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "allow_private",
        "include_hosts",
        "include_vms",
        "trust_pem",
        "timeout_seconds",
        "record_limit",
    }
)
_HOST_FIELDS = (
    "id",
    "uuid",
    "name_label",
    "hostname",
    "address",
    "power_state",
    "enabled",
    "version",
    "build",
    "productBrand",
    "cpus",
    "memory",
    "tags",
    "$pool",
)
_VM_FIELDS = (
    "id",
    "uuid",
    "name_label",
    "power_state",
    "addresses",
    "mainIpAddress",
    "CPUs",
    "memory",
    "os_version",
    "tags",
    "virtualizationMode",
    "$container",
    "$pool",
    "startTime",
)
_MAX_RECORDS = 10_000
_MAX_VM_NETWORK_IDENTIFIERS = 46


class XcpNgInventoryAdapter:
    """Collect fixed Xen Orchestra host and VM collections with token auth."""

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
        observations, host_count, vm_count, resources = await self._read(
            connector, secret, cursor={}
        )
        return {
            "records_received": host_count + vm_count,
            "records_visible": len(observations),
            "hosts_received": host_count,
            "virtual_machines_received": vm_count,
            "resources": resources,
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
    ) -> tuple[list[NormalizedObservation], int, int, list[str]]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("XCP-ng connector cursor must be empty")
        if not connector.base_url:
            raise InventoryConnectorError("XCP-ng connector requires an HTTPS Xen Orchestra URL")
        origin = _origin(connector.base_url)
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("XCP-ng connector config contains unknown fields")
        token = _token(secret)
        allow_private = _boolean(config, "allow_private", default=False)
        include_hosts = _boolean(config, "include_hosts", default=True)
        include_vms = _boolean(config, "include_vms", default=True)
        if not include_hosts and not include_vms:
            raise InventoryConnectorError("XCP-ng connector must include hosts or virtual machines")
        trust_pem = _trust_pem(config.get("trust_pem"))
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        collection_limit = record_limit + 1
        hosts = (
            await self._collection(
                origin,
                collection="hosts",
                fields=_HOST_FIELDS,
                token=token,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                trust_pem=trust_pem,
                maximum=collection_limit,
            )
            if include_hosts
            else []
        )
        vms = (
            await self._collection(
                origin,
                collection="vms",
                fields=_VM_FIELDS,
                token=token,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                trust_pem=trust_pem,
                maximum=collection_limit,
            )
            if include_vms
            else []
        )
        if (
            len(hosts) > record_limit
            or len(vms) > record_limit
            or len(hosts) + len(vms) > record_limit
        ):
            raise InventoryConnectorError("XCP-ng inventory exceeded the combined record limit")

        observed_at = datetime.now(UTC)
        observations = [
            *(
                _host_observation(item, connector_id=connector.id, observed_at=observed_at)
                for item in hosts
            ),
            *(
                _vm_observation(item, connector_id=connector.id, observed_at=observed_at)
                for item in vms
            ),
        ]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("XCP-ng inventory returned duplicate object IDs")
        resources = [
            *(("hosts",) if include_hosts else ()),
            *(("virtual machines",) if include_vms else ()),
        ]
        return observations, len(hosts), len(vms), resources

    async def _collection(
        self,
        origin: str,
        *,
        collection: str,
        fields: tuple[str, ...],
        token: str,
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
        maximum: int,
    ) -> list[dict[str, Any]]:
        query = urlencode({"fields": ",".join(fields), "limit": str(maximum)})
        response = await self._send(
            "GET",
            f"{origin}/rest/v0/{collection}?{query}",
            headers={
                "Accept": "application/json",
                "Cookie": f"authenticationToken={token}",
            },
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
            token=token,
        )
        if (
            not isinstance(response.data, list)
            or len(response.data) > maximum
            or not all(isinstance(item, dict) for item in response.data)
        ):
            raise InventoryConnectorError(
                f"XCP-ng {collection} response is invalid or exceeds limits"
            )
        return cast(list[dict[str, Any]], response.data)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
        token: str,
    ) -> JsonResponse:
        transport = _transport(trust_pem)
        try:
            return await self._sender(
                method,
                url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                user_agent="Vulna-XCP-ng-Inventory/1",
                **({"transport": transport} if transport is not None else {}),
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "Xen Orchestra provider")
            safe = safe.replace("Ticket connector", "Xen Orchestra connector")
            safe = safe.replace(token, "[REDACTED]")
            raise InventoryConnectorError(safe[:1024]) from exc
        finally:
            if transport is not None:
                await transport.aclose()


def _origin(value: str) -> str:
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise InventoryConnectorError("Xen Orchestra URL contains an invalid port") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or port not in (None, 443)
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or "%" in parts.netloc
    ):
        raise InventoryConnectorError("Xen Orchestra URL must be an HTTPS origin on port 443")
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return urlunsplit(("https", host, "", "", ""))


def _host_observation(
    value: dict[str, Any], *, connector_id: uuid.UUID, observed_at: datetime
) -> NormalizedObservation:
    object_id = _object_uuid(value, "host")
    name = _required_text(value.get("name_label"), "host name", maximum=512)
    hostname = _optional_hostname(value.get("hostname"), "host hostname")
    identifiers = [
        {"type": "cloud_instance_id", "value": f"xcp-ng-host:{object_id}"},
        {
            "type": "cloud_instance_id",
            "value": f"xen-orchestra:{connector_id}:host:{object_id}",
        },
    ]
    if hostname:
        _append_network_name(identifiers, hostname)
    _append_network_name(identifiers, name)
    address = _optional_text(value.get("address"), "host address", maximum=253)
    if address:
        _append_network_name(identifiers, address, strict=True)
    attributes: dict[str, Any] = {
        "canonical_name": hostname or _canonical_name(name),
        "asset_type": "hypervisor",
        "operating_system": "XCP-ng",
        "xcp_ng_object_type": "host",
        "xcp_ng_uuid": object_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "power_state": "xcp_ng_power_state",
            "version": "xcp_ng_version",
            "build": "xcp_ng_build",
            "productBrand": "xcp_ng_product_brand",
        },
    )
    enabled = value.get("enabled")
    if enabled is not None:
        attributes["xcp_ng_enabled"] = _required_boolean(enabled, "enabled")
    pool = _optional_uuid(value.get("$pool"), "$pool")
    if pool:
        attributes["xcp_ng_pool_id"] = pool
    cpus = _optional_mapping(value.get("cpus"), "cpus", maximum_fields=10)
    if cpus is not None:
        cores = _optional_int(cpus.get("cores"), "cpus.cores", maximum=1_000_000)
        if cores is not None:
            attributes["cpu_count"] = cores
        sockets = _optional_int(cpus.get("sockets"), "cpus.sockets", maximum=1_000_000)
        if sockets is not None:
            attributes["cpu_socket_count"] = sockets
    _copy_memory(value.get("memory"), attributes)
    tags = _tags(value.get("tags"))
    if tags:
        attributes["tags"] = tags
    return NormalizedObservation(
        source_record_id=f"xcp_ng:host:{object_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _vm_observation(
    value: dict[str, Any], *, connector_id: uuid.UUID, observed_at: datetime
) -> NormalizedObservation:
    object_id = _object_uuid(value, "virtual machine")
    name = _required_text(value.get("name_label"), "virtual machine name", maximum=512)
    identifiers = [
        {"type": "cloud_instance_id", "value": f"xcp-ng-vm:{object_id}"},
        {
            "type": "cloud_instance_id",
            "value": f"xen-orchestra:{connector_id}:vm:{object_id}",
        },
    ]
    _append_network_name(identifiers, name)
    for address in _vm_addresses(value):
        _append_network_name(identifiers, address, strict=True)
    attributes: dict[str, Any] = {
        "canonical_name": _canonical_name(name),
        "asset_type": "virtual_machine",
        "xcp_ng_object_type": "virtual_machine",
        "xcp_ng_uuid": object_id,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "power_state": "xcp_ng_power_state",
            "virtualizationMode": "virtualization_mode",
        },
    )
    for source, target in (("$pool", "xcp_ng_pool_id"), ("$container", "xcp_ng_host_id")):
        object_uuid = _optional_uuid(value.get(source), source)
        if object_uuid:
            attributes[target] = object_uuid
    cpus = _optional_mapping(value.get("CPUs"), "CPUs", maximum_fields=10)
    if cpus is not None:
        count = _optional_int(cpus.get("number"), "CPUs.number", maximum=1_000_000)
        if count is not None:
            attributes["cpu_count"] = count
    _copy_memory(value.get("memory"), attributes)
    os_name = _os_name(value.get("os_version"))
    if os_name:
        attributes["operating_system"] = os_name
    start_time = _optional_int(value.get("startTime"), "startTime", maximum=2**53 - 1)
    if start_time is not None:
        attributes["start_time"] = start_time
    tags = _tags(value.get("tags"))
    if tags:
        attributes["tags"] = tags
    return NormalizedObservation(
        source_record_id=f"xcp_ng:vm:{object_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _object_uuid(value: dict[str, Any], label: str) -> str:
    object_id = _uuid(value.get("id"), f"{label} id")
    provider_uuid = _uuid(value.get("uuid"), f"{label} uuid")
    if object_id != provider_uuid:
        raise InventoryConnectorError(f"XCP-ng {label} id and uuid are inconsistent")
    return object_id


def _vm_addresses(value: dict[str, Any]) -> list[str]:
    result: list[str] = []
    main = _optional_text(value.get("mainIpAddress"), "mainIpAddress", maximum=64)
    if main:
        result.append(_ip_address(main, "mainIpAddress"))
    addresses = value.get("addresses")
    if addresses is None:
        return result
    if not isinstance(addresses, dict) or len(addresses) > 64:
        raise InventoryConnectorError("XCP-ng addresses must contain at most 64 entries")
    for key, item in addresses.items():
        if not isinstance(key, str) or not key or len(key) > 128:
            raise InventoryConnectorError("XCP-ng address key is invalid")
        if item in (None, ""):
            continue
        if not isinstance(item, str):
            raise InventoryConnectorError("XCP-ng address value is invalid")
        address = _ip_address(item, "address value")
        if address not in result:
            result.append(address)
        if len(result) > _MAX_VM_NETWORK_IDENTIFIERS:
            raise InventoryConnectorError("XCP-ng VM has too many network identifiers")
    return result


def _append_network_name(
    identifiers: list[dict[str, str]], value: str, *, strict: bool = False
) -> None:
    try:
        address = str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        hostname = _hostname_or_none(value)
        if hostname:
            candidate = {"type": "fqdn" if "." in hostname else "hostname", "value": hostname}
            if candidate not in identifiers:
                identifiers.append(candidate)
            smb = {"type": "smb_name", "value": hostname.split(".", 1)[0]}
            if smb not in identifiers:
                identifiers.append(smb)
        elif strict:
            raise InventoryConnectorError("XCP-ng network address is invalid") from exc
    else:
        candidate = {"type": "ip_address", "value": address}
        if candidate not in identifiers:
            identifiers.append(candidate)


def _canonical_name(value: str) -> str:
    return _hostname_or_none(value) or value


def _optional_hostname(value: Any, field: str) -> str | None:
    text = _optional_text(value, field, maximum=253)
    if text is None:
        return None
    hostname = _hostname_or_none(text)
    if hostname is None:
        raise InventoryConnectorError(f"XCP-ng {field} is invalid")
    return hostname


def _hostname_or_none(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if len(candidate) > 253 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in candidate.split(".")
    ):
        return None
    return candidate


def _ip_address(value: str, field: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InventoryConnectorError(f"XCP-ng {field} is not an IP address") from exc


def _token(value: str | None) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("Xen Orchestra authentication token is required")
    return value.strip()


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"XCP-ng {field} is required")
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 32 for character in result):
        raise InventoryConnectorError(f"XCP-ng {field} is invalid")
    return result


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    return _required_text(value, field, maximum=maximum)


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        item = _optional_text(source.get(source_name), source_name, maximum=256)
        if item is not None:
            target[target_name] = item


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"XCP-ng {field} must be a UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError(f"XCP-ng {field} must be a UUID") from exc


def _optional_uuid(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    return _uuid(value, field)


def _required_boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"XCP-ng {field} must be a boolean")
    return value


def _optional_mapping(value: Any, field: str, *, maximum_fields: int) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > maximum_fields:
        raise InventoryConnectorError(
            f"XCP-ng {field} must contain at most {maximum_fields} fields"
        )
    return cast(dict[str, Any], value)


def _optional_int(value: Any, field: str, *, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise InventoryConnectorError(f"XCP-ng {field} is invalid")
    return int(value)


def _copy_memory(value: Any, target: dict[str, Any]) -> None:
    memory = _optional_mapping(value, "memory", maximum_fields=10)
    if memory is None:
        return
    for source, destination in (("size", "memory_size_bytes"), ("usage", "memory_usage_bytes")):
        item = _optional_int(memory.get(source), f"memory.{source}", maximum=2**63 - 1)
        if item is not None:
            target[destination] = item


def _os_name(value: Any) -> str | None:
    if value is None:
        return None
    data = _optional_mapping(value, "os_version", maximum_fields=32)
    if data is None:
        return None
    for key in ("name", "distro"):
        item = _optional_text(data.get(key), f"os_version.{key}", maximum=256)
        if item:
            return item
    return None


def _tags(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 100:
        raise InventoryConnectorError("XCP-ng tags must contain at most 100 entries")
    tags: list[str] = []
    for item in value:
        tag = _required_text(item, "tag", maximum=128)
        if tag not in tags:
            tags.append(tag)
    return tags


def _trust_pem(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("XCP-ng trust_pem must be a PEM certificate")
    result = value.strip()
    if (
        len(result) > 16_384
        or not result.startswith("-----BEGIN CERTIFICATE-----")
        or not result.endswith("-----END CERTIFICATE-----")
        or "PRIVATE KEY" in result
    ):
        raise InventoryConnectorError("XCP-ng trust_pem must be a PEM certificate")
    return f"{result}\n"


def _transport(trust_pem: str | None) -> httpx.AsyncHTTPTransport | None:
    if trust_pem is None:
        return None
    context = ssl.create_default_context()
    try:
        context.load_verify_locations(cadata=trust_pem)
    except ssl.SSLError as exc:
        raise InventoryConnectorError("XCP-ng trust_pem is not a valid CA certificate") from exc
    return httpx.AsyncHTTPTransport(verify=context)


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"XCP-ng {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"XCP-ng {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"XCP-ng {field} must be between {minimum} and {maximum}")
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"XCP-ng {key} must be a boolean")
    return value
