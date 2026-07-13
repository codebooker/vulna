"""Read-only VMware vCenter host and virtual-machine inventory adapter."""

from __future__ import annotations

import base64
import ipaddress
import re
import ssl
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MOREF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ALLOWED_CONFIG_FIELDS = frozenset(
    {
        "username",
        "allow_private",
        "include_hosts",
        "include_vms",
        "trust_pem",
        "timeout_seconds",
        "record_limit",
    }
)
_MAX_HOSTS = 2_500
_MAX_VMS = 4_000
_MAX_RECORDS = _MAX_HOSTS + _MAX_VMS


class VcenterInventoryAdapter:
    """Collect fixed vCenter host/VM summaries and always invalidate the session."""

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
            raise InventoryConnectorError("vCenter connector cursor must be empty")
        if not connector.base_url:
            raise InventoryConnectorError("vCenter connector requires an HTTPS server URL")
        origin = _origin(connector.base_url)
        config = connector.config_json
        if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG_FIELDS:
            raise InventoryConnectorError("vCenter connector config contains unknown fields")
        username = _username(config.get("username"))
        if not isinstance(secret, str) or not secret or len(secret) > 4_096:
            raise InventoryConnectorError("vCenter password is required")
        allow_private = _boolean(config, "allow_private", default=False)
        include_hosts = _boolean(config, "include_hosts", default=True)
        include_vms = _boolean(config, "include_vms", default=True)
        if not include_hosts and not include_vms:
            raise InventoryConnectorError(
                "vCenter connector must include hosts or virtual machines"
            )
        trust_pem = _trust_pem(config.get("trust_pem"))
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        session_id = await self._create_session(
            origin,
            username=username,
            password=secret,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
        )
        resources: list[str] = []
        try:
            hosts = (
                await self._inventory(
                    origin,
                    session_id=session_id,
                    resource="host",
                    maximum=_MAX_HOSTS,
                    timeout_seconds=timeout_seconds,
                    allow_private=allow_private,
                    trust_pem=trust_pem,
                )
                if include_hosts
                else []
            )
            if include_hosts:
                resources.append("hosts")
            vms = (
                await self._inventory(
                    origin,
                    session_id=session_id,
                    resource="vm",
                    maximum=_MAX_VMS,
                    timeout_seconds=timeout_seconds,
                    allow_private=allow_private,
                    trust_pem=trust_pem,
                )
                if include_vms
                else []
            )
            if include_vms:
                resources.append("virtual machines")
            if len(hosts) + len(vms) > record_limit:
                raise InventoryConnectorError(
                    "vCenter inventory exceeded the combined record limit"
                )
            observed_at = datetime.now(UTC)
            observations = [
                *(
                    _host_observation(
                        item,
                        connector_id=connector.id,
                        observed_at=observed_at,
                    )
                    for item in hosts
                ),
                *(
                    _vm_observation(
                        item,
                        connector_id=connector.id,
                        observed_at=observed_at,
                    )
                    for item in vms
                ),
            ]
            source_ids = [item.source_record_id for item in observations]
            if len(source_ids) != len(set(source_ids)):
                raise InventoryConnectorError("vCenter inventory returned duplicate object IDs")
        except Exception:
            with suppress(InventoryConnectorError):
                await self._delete_session(
                    origin,
                    session_id=session_id,
                    timeout_seconds=timeout_seconds,
                    allow_private=allow_private,
                    trust_pem=trust_pem,
                )
            raise
        await self._delete_session(
            origin,
            session_id=session_id,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
        )
        return observations, len(hosts), len(vms), resources

    async def _create_session(
        self,
        origin: str,
        *,
        username: str,
        password: str,
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
    ) -> str:
        credential = base64.b64encode(f"{username}:{password}".encode()).decode()
        response = await self._send(
            "POST",
            f"{origin}/api/session",
            headers={"Accept": "application/json", "Authorization": f"Basic {credential}"},
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
            operation="session creation",
        )
        session_id = response.data
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 16_384
            or any(ord(char) < 33 or ord(char) > 126 for char in session_id)
        ):
            raise InventoryConnectorError("vCenter session response is invalid")
        return session_id

    async def _inventory(
        self,
        origin: str,
        *,
        session_id: str,
        resource: str,
        maximum: int,
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
    ) -> list[dict[str, Any]]:
        response = await self._send(
            "GET",
            f"{origin}/api/vcenter/{resource}",
            headers={"Accept": "application/json", "vmware-api-session-id": session_id},
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
            operation=f"{resource} inventory read",
        )
        if (
            not isinstance(response.data, list)
            or len(response.data) > maximum
            or not all(isinstance(item, dict) for item in response.data)
        ):
            raise InventoryConnectorError(f"vCenter {resource} inventory response is invalid")
        return cast(list[dict[str, Any]], response.data)

    async def _delete_session(
        self,
        origin: str,
        *,
        session_id: str,
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
    ) -> None:
        await self._send(
            "DELETE",
            f"{origin}/api/session",
            headers={"Accept": "application/json", "vmware-api-session-id": session_id},
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            trust_pem=trust_pem,
            operation="session invalidation",
        )

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
        allow_private: bool,
        trust_pem: str | None,
        operation: str,
    ) -> JsonResponse:
        transport = _transport(trust_pem)
        try:
            return await self._sender(
                method,
                url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private,
                user_agent="Vulna-vCenter-Inventory/1",
                **({"transport": transport} if transport is not None else {}),
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "vCenter provider")
            safe = safe.replace("Ticket connector", "vCenter connector")
            raise InventoryConnectorError(f"vCenter {operation} failed: {safe}") from exc
        finally:
            if transport is not None:
                await transport.aclose()


def _origin(value: str) -> str:
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise InventoryConnectorError("vCenter URL contains an invalid port") from exc
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
        raise InventoryConnectorError("vCenter URL must be an HTTPS origin on port 443")
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return urlunsplit(("https", host, "", "", ""))


def _host_observation(
    value: dict[str, Any], *, connector_id: uuid.UUID, observed_at: datetime
) -> NormalizedObservation:
    object_id = _moref(value.get("host"), "host")
    name = _required_text(value.get("name"), "host name", maximum=512)
    identifiers = [
        {
            "type": "cloud_instance_id",
            "value": f"vcenter:{connector_id}:host:{object_id}",
        }
    ]
    host_uuid = _optional_uuid(value.get("host_uuid"), "host_uuid")
    if host_uuid:
        identifiers.append({"type": "cloud_instance_id", "value": f"vmware-host:{host_uuid}"})
    _append_network_name(identifiers, name)
    attributes: dict[str, Any] = {
        "canonical_name": _canonical_name(name),
        "asset_type": "hypervisor",
        "manufacturer": "VMware",
        "operating_system": "VMware ESXi",
        "vcenter_object_id": object_id,
        "vcenter_object_type": "host",
    }
    if host_uuid:
        attributes["vcenter_host_uuid"] = host_uuid
    _copy_optional_text(
        value,
        attributes,
        {
            "connection_state": "vcenter_connection_state",
            "power_state": "vcenter_power_state",
        },
    )
    return NormalizedObservation(
        source_record_id=f"vcenter:host:{object_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _vm_observation(
    value: dict[str, Any], *, connector_id: uuid.UUID, observed_at: datetime
) -> NormalizedObservation:
    object_id = _moref(value.get("vm"), "virtual machine")
    name = _required_text(value.get("name"), "virtual machine name", maximum=512)
    identifiers = [
        {
            "type": "cloud_instance_id",
            "value": f"vcenter:{connector_id}:vm:{object_id}",
        }
    ]
    _append_network_name(identifiers, name)
    attributes: dict[str, Any] = {
        "canonical_name": _canonical_name(name),
        "asset_type": "virtual_machine",
        "manufacturer": "VMware",
        "vcenter_object_id": object_id,
        "vcenter_object_type": "virtual_machine",
    }
    _copy_optional_text(value, attributes, {"power_state": "vcenter_power_state"})
    for source, target, maximum in (
        ("cpu_count", "cpu_count", 1_000_000),
        ("memory_size_mib", "memory_size_mib", 2**53 - 1),
    ):
        item = _optional_int(value.get(source), source, maximum=maximum)
        if item is not None:
            attributes[target] = item
    return NormalizedObservation(
        source_record_id=f"vcenter:vm:{object_id}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _append_network_name(identifiers: list[dict[str, str]], value: str) -> None:
    try:
        address = str(ipaddress.ip_address(value.strip()))
    except ValueError:
        hostname = _hostname(value)
        if hostname:
            identifiers.append(
                {"type": "fqdn" if "." in hostname else "hostname", "value": hostname}
            )
            identifiers.append({"type": "smb_name", "value": hostname.split(".", 1)[0]})
    else:
        identifiers.append({"type": "ip_address", "value": address})


def _canonical_name(value: str) -> str:
    return _hostname(value) or value


def _hostname(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if len(candidate) > 253 or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in candidate.split(".")
    ):
        return None
    return candidate


def _moref(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _MOREF_RE.fullmatch(value.strip()):
        raise InventoryConnectorError(f"vCenter {field} identifier is invalid")
    return value.strip()


def _username(value: Any) -> str:
    result = _required_text(value, "username", maximum=512)
    if ":" in result:
        raise InventoryConnectorError("vCenter username cannot contain a colon")
    return result


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError(f"vCenter {field} is required")
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 32 for character in result):
        raise InventoryConnectorError(f"vCenter {field} is invalid")
    return result


def _copy_optional_text(
    source: dict[str, Any], target: dict[str, Any], mapping: dict[str, str]
) -> None:
    for source_name, target_name in mapping.items():
        value = source.get(source_name)
        if value is None:
            continue
        target[target_name] = _required_text(value, source_name, maximum=128)


def _optional_uuid(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"vCenter {field} must be a UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise InventoryConnectorError(f"vCenter {field} must be a UUID") from exc


def _optional_int(value: Any, field: str, *, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise InventoryConnectorError(f"vCenter {field} is invalid")
    return int(value)


def _trust_pem(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("vCenter trust_pem must be a PEM certificate")
    result = value.strip()
    if (
        len(result) > 16_384
        or not result.startswith("-----BEGIN CERTIFICATE-----")
        or not result.endswith("-----END CERTIFICATE-----")
        or "PRIVATE KEY" in result
    ):
        raise InventoryConnectorError("vCenter trust_pem must be a PEM certificate")
    return f"{result}\n"


def _transport(trust_pem: str | None) -> httpx.AsyncHTTPTransport | None:
    if trust_pem is None:
        return None
    context = ssl.create_default_context()
    try:
        context.load_verify_locations(cadata=trust_pem)
    except ssl.SSLError as exc:
        raise InventoryConnectorError("vCenter trust_pem is not a valid CA certificate") from exc
    return httpx.AsyncHTTPTransport(verify=context)


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InventoryConnectorError(f"vCenter {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryConnectorError(f"vCenter {field} must be an integer") from exc
    if str(parsed) != str(value).strip() or not minimum <= parsed <= maximum:
        raise InventoryConnectorError(f"vCenter {field} must be between {minimum} and {maximum}")
    return parsed


def _boolean(config: dict[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"vCenter {key} must be a boolean")
    return value
