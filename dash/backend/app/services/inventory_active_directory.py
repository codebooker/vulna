"""Read-only, paginated Active Directory computer inventory adapter."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ldap3 import (  # type: ignore[import-untyped]
    NONE,
    SAFE_SYNC,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException  # type: ignore[import-untyped]
from ldap3.utils.dn import parse_dn  # type: ignore[import-untyped]

from app.models.passive_inventory import InventoryConnector
from app.services import notifications
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation

QueryDirectory = Callable[..., list[dict[str, Any]]]
ResolveServer = Callable[..., tuple[str, str]]

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTEGER_RE = re.compile(r"^[0-9]+$")
_COMPUTER_FILTER = "(&(objectCategory=computer)(objectClass=computer))"
_COMPUTER_ATTRIBUTES = (
    "objectGUID",
    "objectSid",
    "dNSHostName",
    "name",
    "sAMAccountName",
    "operatingSystem",
    "operatingSystemVersion",
    "operatingSystemServicePack",
    "description",
    "location",
    "managedBy",
    "userAccountControl",
    "whenChanged",
)
_ACCOUNT_DISABLED = 0x0002
_MAX_RECORDS = 10_000


class ActiveDirectoryInventoryAdapter:
    """Collect computer objects through one fixed, verified-LDAPS search contract."""

    def __init__(
        self,
        query: QueryDirectory | None = None,
        resolver: ResolveServer | None = None,
    ) -> None:
        self._query = query or _query_directory
        self._resolver = resolver

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        del source_data
        observations, records = await self._read(connector, secret, cursor={})
        return {
            "records_received": records,
            "records_visible": len(observations),
            "transport": "LDAPS",
            "filter": "computer objects",
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
        observations, _ = await self._read(connector, secret, cursor=cursor)
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], int]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("Active Directory connector cursor must be empty")
        config = connector.config_json
        server = _server(config.get("server"))
        bind_user = _required_text(config.get("bind_user"), "bind_user", maximum=512)
        if not secret:
            raise InventoryConnectorError("Active Directory bind password is required")
        base_dn = _base_dn(config.get("base_dn"))
        allow_private = _boolean(config, "allow_private", default=False)
        trust_pem = _trust_pem(config.get("trust_pem"))
        page_size = _bounded_int(config.get("page_size", 500), "page_size", 1, 1_000)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 15), "timeout_seconds", 1, 60)
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        include_disabled = _boolean(config, "include_disabled", default=False)
        pinned_ip = _resolve_server(
            server,
            allow_private=allow_private,
            resolver=self._resolver or notifications.resolve_validated,
        )
        try:
            records = await asyncio.to_thread(
                self._query,
                pinned_ip,
                tls_hostname=server,
                bind_user=bind_user,
                password=secret,
                base_dn=base_dn,
                trust_pem=trust_pem,
                page_size=page_size,
                timeout_seconds=timeout_seconds,
                record_limit=record_limit,
            )
        except InventoryConnectorError:
            raise
        except (LDAPException, OSError, ValueError) as exc:
            raise InventoryConnectorError(
                "Active Directory bind or read-only search failed"
            ) from exc
        if len(records) > record_limit:
            raise InventoryConnectorError("Active Directory search exceeded the record limit")
        observed_at = datetime.now(UTC)
        observations = [
            observation
            for record in records
            if (
                observation := _observation(
                    record,
                    observed_at=observed_at,
                    include_disabled=include_disabled,
                )
            )
            is not None
        ]
        return observations, len(records)


def _query_directory(
    pinned_ip: str,
    *,
    tls_hostname: str,
    bind_user: str,
    password: str,
    base_dn: str,
    trust_pem: str | None,
    page_size: int,
    timeout_seconds: int,
    record_limit: int,
) -> list[dict[str, Any]]:
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        valid_names=[tls_hostname],
        sni=tls_hostname,
        ca_certs_data=trust_pem,
    )
    server = Server(
        pinned_ip,
        port=636,
        use_ssl=True,
        tls=tls,
        get_info=NONE,
        connect_timeout=timeout_seconds,
        allowed_referral_hosts=[],
    )
    connection = Connection(
        server,
        user=bind_user,
        password=password,
        client_strategy=SAFE_SYNC,
        auto_referrals=False,
        check_names=False,
        read_only=True,
        raise_exceptions=True,
        receive_timeout=timeout_seconds,
    )
    records: list[dict[str, Any]] = []
    cookie: bytes | None = None
    try:
        connection.open(read_server_info=False)
        connection.bind()
        while True:
            status, result, response, _ = connection.search(
                search_base=base_dn,
                search_filter=_COMPUTER_FILTER,
                search_scope=SUBTREE,
                attributes=list(_COMPUTER_ATTRIBUTES),
                size_limit=0,
                time_limit=timeout_seconds,
                paged_size=page_size,
                paged_criticality=True,
                paged_cookie=cookie,
            )
            if not status or not isinstance(result, dict) or not isinstance(response, list):
                raise InventoryConnectorError("Active Directory search returned an invalid result")
            if not all(isinstance(entry, dict) for entry in response):
                raise InventoryConnectorError("Active Directory search entries are invalid")
            entries = [entry for entry in response if entry.get("type") == "searchResEntry"]
            if len(entries) > page_size:
                raise InventoryConnectorError(
                    "Active Directory returned more entries than the requested page"
                )
            if len(records) + len(entries) > record_limit:
                raise InventoryConnectorError("Active Directory search exceeded the record limit")
            records.extend(entries)
            cookie = _page_cookie(result)
            if not cookie:
                break
            if len(records) >= record_limit:
                raise InventoryConnectorError("Active Directory search exceeded the record limit")
    finally:
        connection.unbind()
    return records


def _page_cookie(result: dict[str, Any]) -> bytes | None:
    controls = result.get("controls", {})
    if not isinstance(controls, dict):
        raise InventoryConnectorError("Active Directory paging controls are invalid")
    paging = controls.get("1.2.840.113556.1.4.319")
    if paging is None:
        return None
    if not isinstance(paging, dict) or not isinstance(paging.get("value"), dict):
        raise InventoryConnectorError("Active Directory paging controls are invalid")
    cookie = paging["value"].get("cookie")
    if cookie in (None, b"", ""):
        return None
    if isinstance(cookie, str):
        encoded = cookie.encode()
        if len(encoded) > 4_096:
            raise InventoryConnectorError("Active Directory paging cookie is invalid")
        return encoded
    if not isinstance(cookie, bytes) or len(cookie) > 4_096:
        raise InventoryConnectorError("Active Directory paging cookie is invalid")
    return cookie


def _observation(
    record: dict[str, Any],
    *,
    observed_at: datetime,
    include_disabled: bool,
) -> NormalizedObservation | None:
    if not isinstance(record, dict):
        raise InventoryConnectorError("Active Directory entry is invalid")
    attributes = record.get("attributes")
    raw_attributes = record.get("raw_attributes")
    if not isinstance(attributes, dict) or not isinstance(raw_attributes, dict):
        raise InventoryConnectorError("Active Directory entry attributes are invalid")
    object_guid = _object_guid(raw_attributes.get("objectGUID"))
    user_account_control = _integer_attribute(attributes.get("userAccountControl"), default=0)
    disabled = bool(user_account_control & _ACCOUNT_DISABLED)
    if disabled and not include_disabled:
        return None
    fqdn = _hostname(_single(attributes.get("dNSHostName")))
    name = _computer_name(_single(attributes.get("name")))
    sam_name = _computer_name(_single(attributes.get("sAMAccountName")))
    canonical_name = fqdn or name or sam_name
    if not canonical_name:
        raise InventoryConnectorError("Active Directory computer has no usable name")
    identifiers: list[dict[str, str]] = []
    if fqdn:
        identifiers.append({"type": "fqdn", "value": fqdn})
    if name:
        identifiers.append({"type": "hostname", "value": name})
    if sam_name:
        identifiers.append({"type": "smb_name", "value": sam_name})
    directory_attributes: dict[str, Any] = {
        "canonical_name": canonical_name,
        "directory_object_guid": str(object_guid),
        "directory_enabled": not disabled,
        "directory_user_account_control": user_account_control,
    }
    dn = _optional_text(record.get("dn"), "distinguished name", maximum=2_048)
    if dn:
        directory_attributes["directory_distinguished_name"] = dn
    sid = _object_sid(raw_attributes.get("objectSid"))
    if sid:
        directory_attributes["directory_object_sid"] = sid
    for source, target in (
        ("operatingSystem", "operating_system"),
        ("operatingSystemVersion", "operating_system_version"),
        ("operatingSystemServicePack", "operating_system_service_pack"),
        ("description", "directory_description"),
        ("location", "directory_location"),
        ("managedBy", "directory_managed_by"),
        ("whenChanged", "directory_when_changed"),
    ):
        value = _attribute_text(attributes.get(source), source, maximum=2_048)
        if value:
            directory_attributes[target] = value
    return NormalizedObservation(
        source_record_id=f"ad:{object_guid}",
        observed_at=observed_at,
        identifiers=identifiers,
        attributes=directory_attributes,
    )


def _server(value: Any) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError("Active Directory server must be a hostname or IP address")
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ord(char) < 33 for char in raw):
        raise InventoryConnectorError("Active Directory server must be a hostname or IP address")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        if any(not _HOST_LABEL_RE.fullmatch(label) for label in raw.split(".")):
            raise InventoryConnectorError(
                "Active Directory server must be a hostname or IP address"
            ) from None
        return raw.lower()


def _resolve_server(
    server: str,
    *,
    allow_private: bool,
    resolver: ResolveServer,
) -> str:
    try:
        address = ipaddress.ip_address(server)
        host = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        host = server
    try:
        _, pinned_ip = resolver(f"https://{host}/", allow_private=allow_private)
    except notifications.NotificationError as exc:
        safe = str(exc).replace("Webhook host", "Active Directory server")
        safe = safe.replace("Webhook URL", "Active Directory server")
        raise InventoryConnectorError(safe) from exc
    return pinned_ip


def _base_dn(value: Any) -> str:
    result = _required_text(value, "base_dn", maximum=2_048)
    try:
        components = parse_dn(result, escape=True, strip=True)
    except (LDAPException, ValueError) as exc:
        raise InventoryConnectorError("Active Directory base_dn is invalid") from exc
    if not components:
        raise InventoryConnectorError("Active Directory base_dn is invalid")
    return result


def _trust_pem(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Active Directory trust_pem must be a PEM certificate")
    result = value.strip()
    if (
        len(result) > 4_096
        or not result.startswith("-----BEGIN CERTIFICATE-----")
        or not result.endswith("-----END CERTIFICATE-----")
        or "PRIVATE KEY" in result
    ):
        raise InventoryConnectorError("Active Directory trust_pem must be a PEM certificate")
    return f"{result}\n"


def _object_guid(value: Any) -> uuid.UUID:
    raw = _single_raw(value)
    if raw is None or len(raw) != 16:
        raise InventoryConnectorError("Active Directory objectGUID is invalid")
    return uuid.UUID(bytes_le=raw)


def _object_sid(value: Any) -> str | None:
    raw = _single_raw(value)
    if raw is None:
        return None
    if len(raw) < 8:
        raise InventoryConnectorError("Active Directory objectSid is invalid")
    revision = raw[0]
    count = raw[1]
    if revision != 1 or len(raw) != 8 + count * 4:
        raise InventoryConnectorError("Active Directory objectSid is invalid")
    authority = int.from_bytes(raw[2:8], "big")
    subauthorities = [
        str(int.from_bytes(raw[offset : offset + 4], "little")) for offset in range(8, len(raw), 4)
    ]
    return "-".join([f"S-{revision}-{authority}", *subauthorities])


def _single_raw(value: Any) -> bytes | None:
    if value in (None, [], b""):
        return None
    if isinstance(value, list):
        if len(value) != 1:
            raise InventoryConnectorError("Active Directory binary attribute is not single-valued")
        value = value[0]
    if not isinstance(value, bytes):
        raise InventoryConnectorError("Active Directory binary attribute is invalid")
    return value


def _single(value: Any) -> Any:
    if isinstance(value, list):
        if len(value) > 1:
            raise InventoryConnectorError("Active Directory attribute is not single-valued")
        return value[0] if value else None
    return value


def _hostname(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Active Directory dNSHostName is invalid")
    raw = value.strip().rstrip(".").lower()
    if len(raw) > 253 or any(not _HOST_LABEL_RE.fullmatch(label) for label in raw.split(".")):
        raise InventoryConnectorError("Active Directory dNSHostName is invalid")
    return raw


def _computer_name(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError("Active Directory computer name is invalid")
    raw = value.strip().rstrip("$").lower()
    if not raw or len(raw) > 255 or any(ord(char) < 33 for char in raw):
        raise InventoryConnectorError("Active Directory computer name is invalid")
    return raw


def _attribute_text(value: Any, field: str, *, maximum: int) -> str | None:
    value = _single(value)
    if isinstance(value, datetime):
        result = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return result.isoformat()
    return _optional_text(value, field, maximum=maximum)


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise InventoryConnectorError(f"Active Directory {field} is invalid")
    result = value.strip()
    if not result or len(result) > maximum or "\x00" in result:
        raise InventoryConnectorError(f"Active Directory {field} is invalid")
    return result


def _required_text(value: Any, field: str, *, maximum: int) -> str:
    result = _optional_text(value, field, maximum=maximum)
    if result is None:
        raise InventoryConnectorError(f"Active Directory {field} is required")
    return result


def _integer_attribute(value: Any, *, default: int) -> int:
    value = _single(value)
    if value in (None, ""):
        return default
    if isinstance(value, bool) or not (
        isinstance(value, int) or isinstance(value, str) and _INTEGER_RE.fullmatch(value.strip())
    ):
        raise InventoryConnectorError("Active Directory integer attribute is invalid")
    result = int(value)
    if result < 0 or result > 2**32 - 1:
        raise InventoryConnectorError("Active Directory integer attribute is invalid")
    return result


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int) or isinstance(value, str) and _INTEGER_RE.fullmatch(value.strip())
    ):
        raise InventoryConnectorError(f"Active Directory {field} must be an integer")
    result = int(value)
    if result < minimum or result > maximum:
        raise InventoryConnectorError(
            f"Active Directory {field} must be between {minimum} and {maximum}"
        )
    return result


def _boolean(config: dict[str, Any], field: str, *, default: bool) -> bool:
    value = config.get(field, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"Active Directory {field} must be true or false")
    return value
