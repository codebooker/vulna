"""Strict, read-only CSV inventory adapter."""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, datetime
from typing import Any

from app.models.enums import IdentifierType
from app.models.passive_inventory import InventoryConnector
from app.services.passive_inventory import (
    MAX_CSV_SOURCE_BYTES,
    InventoryConnectorError,
    NormalizedObservation,
)

MAX_CSV_ROWS = 10_000
MAX_CSV_COLUMNS = 100
MAX_CELL_CHARS = 16_384
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ -]{0,127}$")
_TARGET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_RESERVED_FRAGMENTS = {
    "secret",
    "token",
    "password",
    "private_key",
    "credential",
    "api_key",
    "authorization",
}
_DEFAULT_ATTRIBUTES = {
    "name": "canonical_name",
    "canonical_name": "canonical_name",
    "hostname": "hostname",
    "asset_type": "asset_type",
    "operating_system": "operating_system",
    "os": "operating_system",
    "manufacturer": "manufacturer",
}


class CsvInventoryAdapter:
    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        del secret
        headers, rows = _parse(source_data, connector.config_json)
        _mapping(connector.config_json, headers)
        return {
            "headers": headers,
            "records_visible": len(rows),
            "sha256": connector.source_sha256,
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
        del secret, cursor
        headers, rows = _parse(source_data, connector.config_json)
        source_field, identifier_fields, attribute_fields = _mapping(connector.config_json, headers)
        observed_field = connector.config_json.get("observed_at_field")
        if observed_field is not None:
            observed_field = _header(str(observed_field), headers)
        now = datetime.now(UTC)
        observations: list[NormalizedObservation] = []
        for index, row in enumerate(rows, start=2):
            source_id = row.get(source_field, "").strip()
            if not source_id:
                raise InventoryConnectorError(
                    f"CSV row {index} is missing source ID column '{source_field}'"
                )
            identifiers = [
                {"type": kind.value, "value": value.strip()}
                for kind, column in identifier_fields
                if (value := row.get(column, "")).strip()
            ]
            if not identifiers:
                raise InventoryConnectorError(f"CSV row {index} has no mapped identifier")
            attributes = {
                target: value.strip()
                for target, column in attribute_fields
                if (value := row.get(column, "")).strip()
            }
            observed_at = now
            if observed_field and (raw_observed := row.get(observed_field, "").strip()):
                try:
                    observed_at = datetime.fromisoformat(raw_observed.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise InventoryConnectorError(
                        f"CSV row {index} has an invalid observed timestamp"
                    ) from exc
                if observed_at.tzinfo is None or observed_at.utcoffset() is None:
                    raise InventoryConnectorError(
                        f"CSV row {index} observed timestamp must include a timezone"
                    )
            observations.append(
                NormalizedObservation(
                    source_record_id=source_id,
                    observed_at=observed_at,
                    identifiers=identifiers,
                    attributes=attributes,
                )
            )
        return observations, {}


def _parse(
    source_data: bytes | None, config: dict[str, Any]
) -> tuple[list[str], list[dict[str, str]]]:
    if source_data is None:
        raise InventoryConnectorError("CSV connector requires an uploaded source file")
    if not source_data or len(source_data) > MAX_CSV_SOURCE_BYTES:
        raise InventoryConnectorError("CSV source must contain 1 byte to 5 MiB")
    try:
        text = source_data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InventoryConnectorError("CSV source must be UTF-8") from exc
    if "\x00" in text:
        raise InventoryConnectorError("CSV source contains a NUL byte")
    delimiter = str(config.get("delimiter", ","))
    if delimiter == "\\t":
        delimiter = "\t"
    if delimiter not in {",", ";", "\t", "|"}:
        raise InventoryConnectorError("CSV delimiter must be comma, semicolon, tab, or pipe")
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        raw_headers = reader.fieldnames or []
        headers = [item.strip() for item in raw_headers]
        if (
            not headers
            or len(headers) > MAX_CSV_COLUMNS
            or len(set(headers)) != len(headers)
            or any(not _FIELD_RE.fullmatch(item) for item in headers)
        ):
            raise InventoryConnectorError("CSV headers must be unique bounded field names")
        rows: list[dict[str, str]] = []
        for raw in reader:
            if len(rows) >= MAX_CSV_ROWS:
                raise InventoryConnectorError("CSV source exceeds 10000 data rows")
            if None in raw:
                raise InventoryConnectorError("CSV row contains more fields than the header")
            row = {
                header: str(raw.get(original) or "")
                for header, original in zip(headers, raw_headers, strict=True)
            }
            if any(len(value) > MAX_CELL_CHARS for value in row.values()):
                raise InventoryConnectorError("CSV cell exceeds 16384 characters")
            if any("\x00" in value for value in row.values()):
                raise InventoryConnectorError("CSV cell contains a NUL byte")
            if any(value.strip() for value in row.values()):
                rows.append(row)
    except csv.Error as exc:
        raise InventoryConnectorError("CSV source is malformed") from exc
    if not rows:
        raise InventoryConnectorError("CSV source contains no data rows")
    return headers, rows


def _mapping(
    config: dict[str, Any], headers: list[str]
) -> tuple[str, list[tuple[IdentifierType, str]], list[tuple[str, str]]]:
    source_field = config.get("source_id_field")
    if source_field is None:
        source_field = next(
            (
                field
                for field in (
                    "id",
                    "asset_id",
                    "device_id",
                    "cloud_instance_id",
                    "agent_id",
                    "fqdn",
                    "hostname",
                    "mac_address",
                    "ip_address",
                )
                if field in headers
            ),
            None,
        )
    if source_field is None:
        raise InventoryConnectorError("CSV mapping requires source_id_field")
    source = _header(str(source_field), headers)

    raw_identifiers = config.get("identifier_fields")
    if raw_identifiers is None:
        raw_identifiers = [
            f"{kind.value}={kind.value}" for kind in IdentifierType if kind.value in headers
        ]
    identifiers = _typed_mapping(raw_identifiers, headers)
    if not identifiers:
        raise InventoryConnectorError("CSV mapping requires at least one identifier field")

    raw_attributes = config.get("attribute_fields")
    if raw_attributes is None:
        raw_attributes = [
            f"{target}={column}"
            for column, target in _DEFAULT_ATTRIBUTES.items()
            if column in headers
        ]
    attributes = _named_mapping(raw_attributes, headers, max_items=50)
    return source, identifiers, attributes


def _header(value: str, headers: list[str]) -> str:
    field = value.strip()
    if field not in headers:
        raise InventoryConnectorError(f"CSV mapping references unknown column '{field}'")
    if any(fragment in field.lower() for fragment in _RESERVED_FRAGMENTS):
        raise InventoryConnectorError("CSV mapping references a reserved secret-shaped column")
    return field


def _typed_mapping(value: Any, headers: list[str]) -> list[tuple[IdentifierType, str]]:
    if not isinstance(value, list) or len(value) > 20:
        raise InventoryConnectorError("identifier_fields must contain at most 20 mappings")
    result: list[tuple[IdentifierType, str]] = []
    for raw in value:
        target, separator, column = str(raw).partition("=")
        if not separator:
            raise InventoryConnectorError("identifier_fields entries must use type=column")
        try:
            kind = IdentifierType(target.strip())
        except ValueError as exc:
            raise InventoryConnectorError("identifier_fields contains an unsupported type") from exc
        result.append((kind, _header(column, headers)))
    return result


def _named_mapping(value: Any, headers: list[str], *, max_items: int) -> list[tuple[str, str]]:
    if not isinstance(value, list) or len(value) > max_items:
        raise InventoryConnectorError(f"attribute_fields must contain at most {max_items} mappings")
    result: list[tuple[str, str]] = []
    targets: set[str] = set()
    for raw in value:
        target, separator, column = str(raw).partition("=")
        target = target.strip()
        if not separator or not _TARGET_RE.fullmatch(target):
            raise InventoryConnectorError("attribute_fields entries must use target=column")
        if target in targets:
            raise InventoryConnectorError("attribute_fields targets must be unique")
        if any(fragment in target.lower() for fragment in _RESERVED_FRAGMENTS):
            raise InventoryConnectorError(
                "attribute_fields contains a reserved secret-shaped target"
            )
        targets.add(target)
        result.append((target, _header(column, headers)))
    return result
