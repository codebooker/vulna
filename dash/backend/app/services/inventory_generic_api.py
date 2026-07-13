"""Read-only, bounded generic JSON API inventory adapter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from app.models.enums import IdentifierType
from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation
from app.services.ticket_adapters.http import JsonResponse, TicketHttpError, request_json

SendJson = Callable[..., Awaitable[JsonResponse]]
_DEFAULT_ATTRIBUTES = (
    "canonical_name",
    "hostname",
    "asset_type",
    "operating_system",
    "manufacturer",
)


class GenericApiInventoryAdapter:
    """Map a read-only JSON endpoint into normalized source observations."""

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
        response = await self._request(connector, secret, cursor={})
        items = _items(response.data, connector.config_json)
        return {
            "status_code": response.status_code,
            "records_visible": len(items),
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
        response = await self._request(connector, secret, cursor=cursor)
        config = connector.config_json
        source_field = _field_name(config.get("source_id_field", "id"))
        identifier_fields = _identifier_fields(config.get("identifier_fields", []))
        attribute_fields = _attribute_fields(
            config.get("attribute_fields", list(_DEFAULT_ATTRIBUTES))
        )
        observed_at = datetime.now(UTC)
        observations: list[NormalizedObservation] = []
        for item in _items(response.data, config):
            source_id = _value(item, source_field)
            if source_id is None:
                raise InventoryConnectorError(
                    f"generic API item is missing source_id_field '{source_field}'"
                )
            identifiers = [
                {"type": kind.value, "value": str(value)}
                for kind, field in identifier_fields
                if (value := _value(item, field)) is not None
            ]
            if not identifiers:
                raise InventoryConnectorError(
                    f"generic API item '{source_id}' has no configured identifiers"
                )
            attributes = {
                field.split(".")[-1]: value
                for field in attribute_fields
                if (value := _value(item, field)) is not None
            }
            observations.append(
                NormalizedObservation(
                    source_record_id=str(source_id),
                    observed_at=observed_at,
                    identifiers=identifiers,
                    attributes=attributes,
                )
            )
        next_cursor_field = _field_name(config.get("next_cursor_field", "next_cursor"))
        next_cursor = _value(response.data, next_cursor_field)
        return observations, ({"value": str(next_cursor)} if next_cursor else {})

    async def _request(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> JsonResponse:
        if not connector.base_url:
            raise InventoryConnectorError("generic API connector requires a base URL")
        config = connector.config_json
        url = _endpoint(connector.base_url, config.get("path", ""), cursor, config)
        headers = {"Accept": "application/json"}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        timeout_seconds = int(config.get("timeout_seconds", 15))
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise InventoryConnectorError("generic API timeout_seconds must be between 1 and 60")
        try:
            return await self._sender(
                "GET",
                url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                allow_private=bool(config.get("allow_private", False)),
                user_agent="Vulna-Inventory-Connector/1",
            )
        except TicketHttpError as exc:
            safe = str(exc).replace("ticket provider", "inventory provider")
            raise InventoryConnectorError(safe) from exc


def _endpoint(
    base_url: str,
    raw_path: Any,
    cursor: dict[str, Any],
    config: dict[str, Any],
) -> str:
    path = str(raw_path or "").strip()
    decoded_path = unquote(path)
    if path and (
        not path.startswith("/")
        or ".." in decoded_path
        or "?" in path
        or "#" in path
        or decoded_path.startswith("//")
    ):
        raise InventoryConnectorError("generic API path must be an absolute path without traversal")
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if cursor.get("value"):
        query[_field_name(config.get("cursor_parameter", "cursor"))] = str(cursor["value"])
    page_size = int(config.get("page_size", 1000))
    if page_size < 1 or page_size > 10_000:
        raise InventoryConnectorError("generic API page_size must be between 1 and 10000")
    query[_field_name(config.get("page_size_parameter", "limit"))] = str(page_size)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"{parts.path.rstrip('/')}{path}", urlencode(query), "")
    )


def _field_name(value: Any) -> str:
    field = str(value).strip()
    parts = field.split(".")
    if (
        not field
        or len(parts) > 5
        or any(not part.replace("_", "").isalnum() or len(part) > 64 for part in parts)
    ):
        raise InventoryConnectorError("generic API fields must use bounded dotted names")
    return field


def _lookup(value: Any, field: str) -> Any:
    current = value
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _value(value: Any, field: str) -> Any:
    current = _lookup(value, field)
    if isinstance(current, (dict, list)):
        return None
    return current


def _items(value: Any, config: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (
        value
        if isinstance(value, list)
        else _lookup(value, _field_name(config.get("items_field", "items")))
    )
    if not isinstance(raw, list) or len(raw) > 10_000:
        raise InventoryConnectorError("generic API response must contain at most 10000 items")
    if not all(isinstance(item, dict) for item in raw):
        raise InventoryConnectorError("generic API items must be JSON objects")
    return raw


def _identifier_fields(value: Any) -> list[tuple[IdentifierType, str]]:
    if not isinstance(value, list) or not value or len(value) > 20:
        raise InventoryConnectorError("identifier_fields must contain 1-20 type=field mappings")
    result: list[tuple[IdentifierType, str]] = []
    for entry in value:
        kind_text, separator, field = str(entry).partition("=")
        if not separator:
            raise InventoryConnectorError("identifier_fields entries must use type=field")
        try:
            kind = IdentifierType(kind_text.strip())
        except ValueError as exc:
            raise InventoryConnectorError("identifier_fields contains an unsupported type") from exc
        result.append((kind, _field_name(field)))
    return result


def _attribute_fields(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 50:
        raise InventoryConnectorError("attribute_fields must contain at most 50 fields")
    return [_field_name(item) for item in value]
