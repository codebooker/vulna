"""Read-only, paginated Kea DHCPv4 lease inventory adapter."""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTEGER_RE = re.compile(r"^[0-9]+$")
_READ_COMMAND = "lease4-get-page"
_MAX_PAGE_SIZE = 1000


class DhcpInventoryAdapter:
    """Collect bounded Kea DHCPv4 lease pages without exposing a command surface."""

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
        observations, cursor, returned = await self._page(connector, secret, cursor={})
        return {
            "leases_returned": returned,
            "records_visible": len(observations),
            "has_more": bool(cursor),
            "command": _READ_COMMAND,
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
        observations, next_cursor, _ = await self._page(connector, secret, cursor=cursor)
        return observations, next_cursor

    async def _page(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], dict[str, Any], int]:
        if not connector.base_url:
            raise InventoryConnectorError("DHCP connector requires a Kea HTTPS control URL")
        config = connector.config_json
        page_size = _bounded_int(config.get("page_size", 500), "page_size", 1, _MAX_PAGE_SIZE)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        start = _cursor_address(cursor)
        headers = _authorization(config, secret)
        command: dict[str, Any] = {
            "command": _READ_COMMAND,
            "arguments": {"from": start, "limit": page_size},
        }
        if _boolean(config, "legacy_control_agent", default=False):
            command["service"] = ["dhcp4"]
        try:
            response = await self._sender(
                "POST",
                connector.base_url,
                headers=headers,
                json_body=command,
                timeout_seconds=timeout_seconds,
                allow_private=_boolean(config, "allow_private", default=False),
                user_agent="Vulna-DHCP-Inventory/1",
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "Kea DHCP provider")
            safe = safe.replace("Ticket connector", "Kea DHCP connector")
            raise InventoryConnectorError(safe) from exc
        leases = _leases(response.data, page_size)
        addresses = [_ipv4(lease.get("ip-address"), field="ip-address") for lease in leases]
        previous = ipaddress.IPv4Address(start) if start != "start" else None
        for address in addresses:
            if previous is not None and int(address) <= int(previous):
                raise InventoryConnectorError("Kea DHCP lease page did not advance its cursor")
            previous = address
        include_inactive = _boolean(config, "include_inactive", default=False)
        observations = [
            observation
            for lease in leases
            if (observation := _observation(lease, include_inactive=include_inactive)) is not None
        ]
        next_cursor: dict[str, Any] = {}
        if len(leases) == page_size:
            next_cursor = {"from": str(addresses[-1])}
        return observations, next_cursor, len(leases)


def _authorization(config: dict[str, Any], secret: str | None) -> dict[str, str]:
    raw_username = config.get("username")
    if raw_username is not None and not isinstance(raw_username, str):
        raise InventoryConnectorError("Kea DHCP username must be a string")
    username = (raw_username or "").strip()
    if username:
        if len(username) > 128 or ":" in username or any(ord(char) < 32 for char in username):
            raise InventoryConnectorError("Kea DHCP username is invalid")
        if not secret:
            raise InventoryConnectorError("Kea DHCP basic authentication requires a password")
        encoded = base64.b64encode(f"{username}:{secret}".encode()).decode("ascii")
        return {"Accept": "application/json", "Authorization": f"Basic {encoded}"}
    if secret:
        raise InventoryConnectorError("Kea DHCP password requires a configured username")
    if not _boolean(config, "allow_unauthenticated", default=False):
        raise InventoryConnectorError(
            "Kea DHCP authentication is required unless allow_unauthenticated is explicit"
        )
    return {"Accept": "application/json"}


def _leases(value: Any, page_size: int) -> list[dict[str, Any]]:
    if isinstance(value, list):
        if len(value) != 1 or not isinstance(value[0], dict):
            raise InventoryConnectorError("Kea DHCP returned an invalid command response")
        value = value[0]
    if not isinstance(value, dict):
        raise InventoryConnectorError("Kea DHCP returned an invalid command response")
    result = value.get("result")
    if isinstance(result, bool) or not isinstance(result, int):
        raise InventoryConnectorError("Kea DHCP response is missing an integer result")
    if result == 3:
        return []
    if result != 0:
        raise InventoryConnectorError(f"Kea DHCP read command failed with result {result}")
    arguments = value.get("arguments")
    if not isinstance(arguments, dict) or not isinstance(arguments.get("leases"), list):
        raise InventoryConnectorError("Kea DHCP response is missing its lease list")
    raw_leases = arguments["leases"]
    if len(raw_leases) > page_size:
        raise InventoryConnectorError("Kea DHCP returned more leases than the requested page")
    if not all(isinstance(lease, dict) for lease in raw_leases):
        raise InventoryConnectorError("Kea DHCP lease entries must be objects")
    return cast(list[dict[str, Any]], raw_leases)


def _observation(lease: dict[str, Any], *, include_inactive: bool) -> NormalizedObservation | None:
    state = _bounded_int(lease.get("state", 0), "lease state", 0, 255)
    if state != 0 and not include_inactive:
        return None
    address = _ipv4(lease.get("ip-address"), field="ip-address")
    identifiers: list[dict[str, Any]] = [{"type": "ip_address", "value": str(address)}]
    hardware = _mac_address(lease.get("hw-address"))
    if hardware:
        identifiers.append({"type": "mac_address", "value": hardware})
    hostname = _hostname(lease.get("hostname"))
    if hostname:
        identifiers.append({"type": "fqdn" if "." in hostname else "hostname", "value": hostname})
    client_id = _bounded_text(lease.get("client-id"), "client-id", maximum=255)
    subnet_id = _bounded_int(lease.get("subnet-id", 0), "subnet-id", 0, 2**32 - 1)
    valid_lifetime = _bounded_int(lease.get("valid-lft", 0), "valid-lft", 0, 2**32 - 1)
    observed_at = _observed_at(lease.get("cltt"))
    attributes: dict[str, Any] = {
        "canonical_name": hostname or str(address),
        "dhcp_subnet_id": subnet_id,
        "dhcp_state": state,
        "lease_valid_lifetime_seconds": valid_lifetime,
        "lease_expires_at": (observed_at + timedelta(seconds=valid_lifetime)).isoformat(),
    }
    if hostname:
        attributes["hostname"] = hostname
    if client_id:
        attributes["dhcp_client_id"] = client_id
    return NormalizedObservation(
        source_record_id=f"kea4:{address}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=attributes,
    )


def _cursor_address(cursor: dict[str, Any]) -> str:
    if not isinstance(cursor, dict) or set(cursor) - {"from"}:
        raise InventoryConnectorError("Kea DHCP cursor is invalid")
    value = cursor.get("from", "start")
    if value == "start":
        return "start"
    return str(_ipv4(value, field="cursor"))


def _ipv4(value: Any, *, field: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise InventoryConnectorError(f"Kea DHCP {field} must be an IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise InventoryConnectorError(f"Kea DHCP {field} must be an IPv4 address")
    return address


def _mac_address(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Kea DHCP hw-address is invalid")
    raw = value.strip()
    if not _MAC_RE.fullmatch(raw):
        raise InventoryConnectorError("Kea DHCP hw-address is invalid")
    return raw.replace("-", ":").lower()


def _hostname(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Kea DHCP hostname is invalid")
    raw = value.strip().rstrip(".").lower()
    if len(raw) > 253 or any(not _HOST_LABEL_RE.fullmatch(label) for label in raw.split(".")):
        raise InventoryConnectorError("Kea DHCP hostname is invalid")
    return raw


def _bounded_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Kea DHCP {field} is invalid")
    raw = value.strip()
    if not raw or len(raw) > maximum or any(ord(char) < 32 for char in raw):
        raise InventoryConnectorError(f"Kea DHCP {field} is invalid")
    return raw


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int) or isinstance(value, str) and _INTEGER_RE.fullmatch(value.strip())
    ):
        raise InventoryConnectorError(f"Kea DHCP {field} must be an integer")
    result = int(value)
    if result < minimum or result > maximum:
        raise InventoryConnectorError(f"Kea DHCP {field} must be between {minimum} and {maximum}")
    return result


def _boolean(config: dict[str, Any], field: str, *, default: bool) -> bool:
    value = config.get(field, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Kea DHCP {field} must be true or false")
    return value


def _observed_at(value: Any) -> datetime:
    if value in (None, 0, "0", ""):
        return datetime.now(UTC)
    timestamp = _bounded_int(value, "cltt", 1, 2**63 - 1)
    try:
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise InventoryConnectorError("Kea DHCP cltt is outside the supported date range") from exc
