"""Read-only Proxmox VE node and guest inventory adapter."""

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
_API_IDENTITY_RE = re.compile(
    r"^[A-Za-z0-9._-]{1,48}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{1,63}$"
)
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "api_identity",
        "allow_private",
        "include_nodes",
        "include_guests",
        "include_templates",
        "trust_pem",
        "timeout_seconds",
        "record_limit",
    }
)
_MAX_RECORDS = 10_000


class ProxmoxInventoryAdapter:
    """Collect fixed cluster-wide node and guest resource summaries with GET only."""

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
        observations, node_count, guest_count, resources = await self._read(
            connector, secret, cursor={}
        )
        return {
            "records_received": node_count + guest_count,
            "records_visible": len(observations),
            "nodes_received": node_count,
            "guests_received": guest_count,
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
            raise InventoryConnectorError("Proxmox connector cursor must be empty")
        if not connector.base_url:
            raise InventoryConnectorError("Proxmox connector requires an HTTPS API origin")
        origin = _origin(connector.base_url)
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("Proxmox connector config contains unknown fields")
        api_identity = _api_identity(config.get("api_identity"))
        api_secret = _api_secret(secret)
        allow_private = _boolean(config, "allow_private", default=False)
        include_nodes = _boolean(config, "include_nodes", default=True)
        include_guests = _boolean(config, "include_guests", default=True)
        include_templates = _boolean(config, "include_templates", default=False)
        if not include_nodes and not include_guests:
            raise InventoryConnectorError("Proxmox connector must include nodes or guests")
        trust_pem = _trust_pem(config.get("trust_pem"))
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        authorization = f"PVEAPIToken={api_identity}={api_secret}"
        nodes = (
            await self._resources(
                origin,
                resource_type="node",
                authorization=authorization,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                trust_pem=trust_pem,
                maximum=record_limit,
                redactions=(api_identity, api_secret),
            )
            if include_nodes
            else []
        )
        guests = (
            await self._resources(
                origin,
                resource_type="vm",
                authorization=authorization,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                trust_pem=trust_pem,
                maximum=record_limit,
                redactions=(api_identity, api_secret),
            )
            if include_guests
            else []
        )
        if len(nodes) + len(guests) > record_limit:
            raise InventoryConnectorError("Proxmox inventory exceeded the combined record limit")

        observed_at = datetime.now(UTC)
        node_observations = [
            _node_observation(item, connector_id=connector.id, observed_at=observed_at)
            for item in nodes
        ]
        guest_observations = [
            observation
            for item in guests
            if (
                observation := _guest_observation(
                    item,
                    connector_id=connector.id,
                    observed_at=observed_at,
                    include_templates=include_templates,
                )
            )
            is not None
        ]
        observations = [*node_observations, *guest_observations]
        source_ids = [item.source_record_id for item in observations]
        if len(source_ids) != len(set(source_ids)):
            raise InventoryConnectorError("Proxmox inventory returned duplicate resource IDs")
        resources = [
            *(("nodes",) if include_nodes else ()),
            *(("virtual machines and containers",) if include_guests else ()),
        ]
        return observations, len(nodes), len(guests), resources

    async def _resources(
        self,
        origin: str,
        *,
        resource_type: str,
        authorization: str,
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
        maximum: int,
        redactions: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        query = urlencode({"type": resource_type})
        response = await self._send(
            "GET",
            f"{origin}/api2/json/cluster/resources?{query}",
            headers={"Accept": "application/json", "Authorization": authorization},
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
            redactions=redactions,
        )
        envelope = response.data
        if not isinstance(envelope, dict) or set(envelope) != {"data"}:
            raise InventoryConnectorError("Proxmox resource response envelope is invalid")
        data = envelope.get("data")
        if (
            not isinstance(data, list)
            or len(data) > maximum
            or not all(isinstance(item, dict) for item in data)
        ):
            raise InventoryConnectorError("Proxmox resource response is invalid or exceeds limits")
        return cast(list[dict[str, Any]], data)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
        redactions: tuple[str, ...],
    ) -> JsonResponse:
        transport = _transport(trust_pem)
        try:
            return await self._sender(
                method,
                url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                user_agent="Vulna-Proxmox-Inventory/1",
                **({"transport": transport} if transport is not None else {}),
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "Proxmox provider")
            safe = safe.replace("Ticket connector", "Proxmox connector")
            for value in redactions:
                safe = safe.replace(value, "[REDACTED]")
            raise InventoryConnectorError(safe[:1024]) from exc
        finally:
            if transport is not None:
                await transport.aclose()


def _origin(value: str) -> str:
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise InventoryConnectorError("Proxmox API origin contains an invalid port") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or port not in (None, 443, 8006)
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or "%" in parts.netloc
    ):
        raise InventoryConnectorError(
            "Proxmox API origin must use HTTPS on port 443 or 8006 without a path"
        )
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port not in (None, 443) else host
    return urlunsplit(("https", netloc, "", "", ""))


def _node_observation(
    value: dict[str, Any], *, connector_id: uuid.UUID, observed_at: datetime
) -> NormalizedObservation:
    if value.get("type") != "node":
        raise InventoryConnectorError("Proxmox node resource type is invalid")
    node = _hostname(_required_text(value.get("node"), "node", maximum=253), "node")
    resource_id = _required_text(value.get("id"), "node resource ID", maximum=258)
    if resource_id != f"node/{value.get('node')}":
        raise InventoryConnectorError("Proxmox node resource ID is inconsistent")
    identifiers = [
        {
            "type": "cloud_instance_id",
            "value": f"proxmox:{connector_id}:node:{node}",
        }
    ]
    _append_network_name(identifiers, node)
    attributes: dict[str, Any] = {
        "canonical_name": node,
        "asset_type": "hypervisor",
        "manufacturer": "Proxmox",
        "operating_system": "Proxmox VE",
        "proxmox_resource_type": "node",
        "proxmox_node": node,
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "status": "proxmox_status",
            "host-arch": "architecture",
        },
    )
    _copy_resource_numbers(value, attributes)
    return NormalizedObservation(
        source_record_id=f"proxmox:node:{node}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _guest_observation(
    value: dict[str, Any],
    *,
    connector_id: uuid.UUID,
    observed_at: datetime,
    include_templates: bool,
) -> NormalizedObservation | None:
    kind = value.get("type")
    if kind not in {"qemu", "lxc"}:
        raise InventoryConnectorError("Proxmox guest resource type is invalid")
    vmid = _required_int(value.get("vmid"), "vmid", minimum=100, maximum=999_999_999)
    if value.get("id") != f"{kind}/{vmid}":
        raise InventoryConnectorError("Proxmox guest resource ID is inconsistent")
    node = _hostname(_required_text(value.get("node"), "guest node", maximum=253), "node")
    template = _optional_boolean(value.get("template"), "template", default=False)
    if template and not include_templates:
        return None
    name = _optional_text(value.get("name"), "guest name", maximum=512) or f"{kind}-{vmid}"
    identifiers = [
        {
            "type": "cloud_instance_id",
            "value": f"proxmox:{connector_id}:{kind}:{vmid}",
        }
    ]
    _append_network_name(identifiers, name)
    attributes: dict[str, Any] = {
        "canonical_name": _canonical_name(name),
        "asset_type": "virtual_machine",
        "manufacturer": "Proxmox",
        "proxmox_resource_type": kind,
        "proxmox_vmid": vmid,
        "proxmox_node": node,
        "proxmox_template": template,
        "virtualization_kind": "container" if kind == "lxc" else "full_virtualization",
    }
    _copy_optional_text(
        value,
        attributes,
        {
            "status": "proxmox_status",
            "pool": "proxmox_pool",
            "lock": "proxmox_lock",
            "hastate": "proxmox_ha_state",
        },
    )
    _copy_resource_numbers(value, attributes)
    tags = _proxmox_tags(value.get("tags"))
    if tags:
        attributes["tags"] = tags
    return NormalizedObservation(
        source_record_id=f"proxmox:{kind}:{vmid}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _copy_resource_numbers(source: dict[str, Any], target: dict[str, Any]) -> None:
    cpu_count = _optional_number(source.get("maxcpu"), "maxcpu", maximum=1_000_000)
    if cpu_count is not None:
        if not cpu_count.is_integer():
            raise InventoryConnectorError("Proxmox maxcpu must be a whole number")
        target["cpu_count"] = int(cpu_count)
    cpu = _optional_number(source.get("cpu"), "cpu", maximum=1_000_000)
    if cpu is not None:
        target["proxmox_cpu_utilization"] = cpu
    for source_name, target_name in (
        ("mem", "memory_usage_bytes"),
        ("maxmem", "memory_size_bytes"),
        ("disk", "disk_usage_bytes"),
        ("maxdisk", "disk_size_bytes"),
        ("uptime", "uptime_seconds"),
    ):
        item = _optional_int(source.get(source_name), source_name, maximum=2**63 - 1)
        if item is not None:
            target[target_name] = item


def _append_network_name(identifiers: list[dict[str, str]], value: str) -> None:
    try:
        address = str(ipaddress.ip_address(value.strip()))
    except ValueError:
        hostname = _hostname_or_none(value)
        if hostname:
            candidate = {"type": "fqdn" if "." in hostname else "hostname", "value": hostname}
            if candidate not in identifiers:
                identifiers.append(candidate)
            smb = {"type": "smb_name", "value": hostname.split(".", 1)[0]}
            if smb not in identifiers:
                identifiers.append(smb)
    else:
        candidate = {"type": "ip_address", "value": address}
        if candidate not in identifiers:
            identifiers.append(candidate)


def _canonical_name(value: str) -> str:
    return _hostname_or_none(value) or value


def _hostname(value: str, field: str) -> str:
    result = _hostname_or_none(value)
    if result is None:
        raise InventoryConnectorError(f"Proxmox {field} is not a valid host name")
    return result


def _hostname_or_none(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if len(candidate) > 253 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in candidate.split(".")
    ):
        return None
    return candidate


def _api_identity(value: Any) -> str:
    if not isinstance(value, str) or not _API_IDENTITY_RE.fullmatch(value.strip()):
        raise InventoryConnectorError("Proxmox api_identity must use the USER@REALM!TOKENID format")
    return value.strip()


def _api_secret(value: str | None) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError("Proxmox API token secret is required")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError("Proxmox API token secret must be a UUID") from exc


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Proxmox {field} is required")
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 32 for character in result):
        raise InventoryConnectorError(f"Proxmox {field} is invalid")
    return result


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    return _required_text(value, field, maximum=maximum)


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        value = _optional_text(source.get(source_name), source_name, maximum=256)
        if value is not None:
            target[target_name] = value


def _required_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InventoryConnectorError(f"Proxmox {field} is invalid")
    return int(value)


def _optional_int(value: Any, field: str, *, maximum: int) -> int | None:
    if value is None:
        return None
    return _required_int(value, field, minimum=0, maximum=maximum)


def _optional_number(value: Any, field: str, *, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InventoryConnectorError(f"Proxmox {field} is invalid")
    result = float(value)
    if not 0 <= result <= maximum:
        raise InventoryConnectorError(f"Proxmox {field} is invalid")
    return result


def _optional_boolean(value: Any, field: str, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Proxmox {field} must be a boolean")
    return value


def _proxmox_tags(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    text = _required_text(value, "tags", maximum=4_096)
    tags = [item.strip() for item in text.split(";") if item.strip()]
    if len(tags) > 100 or any(len(item) > 128 for item in tags):
        raise InventoryConnectorError("Proxmox tags exceed supported limits")
    return tags


def _trust_pem(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Proxmox trust_pem must be a PEM certificate")
    result = value.strip()
    if (
        len(result) > 16_384
        or not result.startswith("-----BEGIN CERTIFICATE-----")
        or not result.endswith("-----END CERTIFICATE-----")
        or "PRIVATE KEY" in result
    ):
        raise InventoryConnectorError("Proxmox trust_pem must be a PEM certificate")
    return f"{result}\n"


def _transport(trust_pem: str | None) -> httpx.AsyncHTTPTransport | None:
    if trust_pem is None:
        return None
    context = ssl.create_default_context()
    try:
        context.load_verify_locations(cadata=trust_pem)
    except ssl.SSLError as exc:
        raise InventoryConnectorError("Proxmox trust_pem is not a valid CA certificate") from exc
    return httpx.AsyncHTTPTransport(verify=context)


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"Proxmox {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"Proxmox {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"Proxmox {field} must be between {minimum} and {maximum}")
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Proxmox {key} must be a boolean")
    return value
