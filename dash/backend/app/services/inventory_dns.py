"""Read-only authoritative DNS zone-transfer inventory adapter."""

from __future__ import annotations

import binascii
import hashlib
import ipaddress
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import dns.asyncquery
import dns.exception
import dns.name
import dns.query
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.reversename
import dns.transaction
import dns.tsig
import dns.tsigkeyring
import dns.xfr
import dns.zone

from app.models.passive_inventory import InventoryConnector
from app.services import notifications
from app.services.passive_inventory import InventoryConnectorError, NormalizedObservation

TransferZone = Callable[..., Awaitable[dns.zone.Zone]]
ResolveServer = Callable[..., tuple[str, str]]

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTEGER_RE = re.compile(r"^[0-9]+$")
_MAX_ZONES = 20
_MAX_RECORDS = 10_000
_SUPPORTED_TYPES = frozenset(
    {
        dns.rdatatype.A,
        dns.rdatatype.AAAA,
        dns.rdatatype.CNAME,
        dns.rdatatype.PTR,
    }
)
_TSIG_ALGORITHMS: dict[str, dns.name.Name] = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


class DnsInventoryAdapter:
    """Transfer explicit authoritative zones without exposing DNS mutation/query APIs."""

    def __init__(
        self,
        transfer: TransferZone | None = None,
        resolver: ResolveServer | None = None,
    ) -> None:
        self._transfer = transfer or _transfer_zone
        self._resolver = resolver

    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, Any]:
        del source_data
        observations, zones, records = await self._read(connector, secret, cursor={})
        return {
            "zones_transferred": zones,
            "records_received": records,
            "records_visible": len(observations),
            "transfer": "AXFR",
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
        observations, _, _ = await self._read(connector, secret, cursor=cursor)
        return observations, {}

    async def _read(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, Any],
    ) -> tuple[list[NormalizedObservation], int, int]:
        if not isinstance(cursor, dict) or cursor:
            raise InventoryConnectorError("DNS connector cursor must be empty")
        config = connector.config_json
        server = _server(config.get("server"))
        zones = _zones(config.get("zones"))
        allow_private = _boolean(config, "allow_private", default=False)
        keyring, keyname, algorithm = _tsig(config, secret)
        timeout_seconds = _bounded_int(config.get("timeout_seconds", 10), "timeout_seconds", 1, 30)
        lifetime_seconds = _bounded_int(
            config.get("lifetime_seconds", 30), "lifetime_seconds", 1, 60
        )
        if lifetime_seconds < timeout_seconds:
            raise InventoryConnectorError(
                "DNS lifetime_seconds must be greater than or equal to timeout_seconds"
            )
        record_limit = _bounded_int(
            config.get("record_limit", _MAX_RECORDS), "record_limit", 1, _MAX_RECORDS
        )
        pinned_ip = _resolve_server(
            server,
            allow_private=allow_private,
            resolver=self._resolver or notifications.resolve_validated,
        )
        observed_at = datetime.now(UTC)
        observations: list[NormalizedObservation] = []
        records_received = 0
        for zone_name in zones:
            remaining = record_limit - records_received
            if remaining <= 0:
                raise InventoryConnectorError("DNS transfers exceeded the configured record limit")
            try:
                zone = await self._transfer(
                    pinned_ip,
                    zone_name,
                    keyring=keyring,
                    keyname=keyname,
                    algorithm=algorithm,
                    timeout_seconds=timeout_seconds,
                    lifetime_seconds=lifetime_seconds,
                    record_limit=remaining,
                )
            except InventoryConnectorError:
                raise
            except dns.exception.Timeout as exc:
                raise InventoryConnectorError("DNS zone transfer timed out") from exc
            except (dns.exception.DNSException, OSError, ValueError) as exc:
                raise InventoryConnectorError(
                    "DNS zone transfer was refused or returned invalid data"
                ) from exc
            mapped, received = _observations(
                zone,
                configured_zone=zone_name,
                observed_at=observed_at,
                record_limit=remaining,
            )
            records_received += received
            observations.extend(mapped)
        return observations, len(zones), records_received


async def _transfer_zone(
    pinned_ip: str,
    zone_name: dns.name.Name,
    *,
    keyring: dict[dns.name.Name, Any] | None,
    keyname: dns.name.Name | None,
    algorithm: dns.name.Name,
    timeout_seconds: int,
    lifetime_seconds: int,
    record_limit: int,
) -> dns.zone.Zone:
    zone = _BoundedZone(zone_name, relativize=False, record_limit=record_limit)
    query, _ = dns.xfr.make_query(
        zone,
        serial=None,
        keyring=keyring,
        keyname=keyname,
        keyalgorithm=algorithm,
    )
    await dns.asyncquery.inbound_xfr(
        pinned_ip,
        zone,
        query=query,
        port=53,
        timeout=timeout_seconds,
        lifetime=lifetime_seconds,
        udp_mode=dns.query.UDPMode.NEVER,
    )
    return zone


class _BoundedZone(dns.zone.Zone):
    """Zone transaction manager that aborts an oversized transfer while receiving it."""

    def __init__(
        self,
        origin: dns.name.Name,
        *,
        relativize: bool,
        record_limit: int,
    ) -> None:
        super().__init__(origin, relativize=relativize)
        self.record_limit = record_limit
        self.records_received = 0

    def writer(self, replacement: bool = False) -> dns.zone.Transaction:
        transaction = _BoundedTransaction(self, replacement)
        transaction._setup_version()  # type: ignore[no-untyped-call]
        return transaction


class _BoundedTransaction(dns.zone.Transaction):
    def __init__(self, zone: _BoundedZone, replacement: bool) -> None:
        super().__init__(zone, replacement)  # type: ignore[no-untyped-call]
        self._bounded_zone = zone

    def add(self, *args: Any) -> None:
        self._count(args)
        super().add(*args)

    def replace(self, *args: Any) -> None:
        self._count(args)
        super().replace(*args)

    def _count(self, args: tuple[Any, ...]) -> None:
        value = args[-1]
        amount = len(value) if isinstance(value, dns.rdataset.Rdataset) else 1
        self._bounded_zone.records_received += amount
        if self._bounded_zone.records_received > self._bounded_zone.record_limit:
            raise InventoryConnectorError("DNS transfers exceeded the configured record limit")


def _observations(
    zone: dns.zone.Zone,
    *,
    configured_zone: dns.name.Name,
    observed_at: datetime,
    record_limit: int,
) -> tuple[list[NormalizedObservation], int]:
    observations: list[NormalizedObservation] = []
    records_received = 0
    zone_text = _record_name(configured_zone, configured_zone)
    for owner, ttl, rdata in zone.iterate_rdatas():
        records_received += 1
        if records_received > record_limit:
            raise InventoryConnectorError("DNS transfers exceeded the configured record limit")
        if rdata.rdtype not in _SUPPORTED_TYPES:
            continue
        owner_text = _record_name(owner, configured_zone)
        if owner_text.startswith("*."):
            # Wildcards describe a DNS policy, not one concrete inventory asset.
            continue
        record_type = dns.rdatatype.to_text(rdata.rdtype)
        value = str(rdata).strip()
        if rdata.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise InventoryConnectorError("DNS address record is invalid") from exc
            identifiers = [
                {"type": "fqdn", "value": owner_text},
                {"type": "ip_address", "value": address},
            ]
            canonical_name = owner_text
            normalized_value = address
        elif rdata.rdtype == dns.rdatatype.PTR:
            try:
                address = dns.reversename.to_address(owner)
            except dns.exception.DNSException as exc:
                raise InventoryConnectorError("DNS PTR owner is not a reverse address") from exc
            target = _target_name(value, configured_zone)
            identifiers = [
                {"type": "ip_address", "value": address},
                {"type": "fqdn", "value": target},
            ]
            canonical_name = target
            normalized_value = target
        else:
            target = _target_name(value, configured_zone)
            identifiers = [
                {"type": "fqdn", "value": owner_text},
                {"type": "fqdn", "value": target},
            ]
            canonical_name = owner_text
            normalized_value = target
        digest = hashlib.sha256(normalized_value.encode()).hexdigest()[:24]
        observations.append(
            NormalizedObservation(
                source_record_id=f"dns:{record_type.lower()}:{owner_text}:{digest}",
                observed_at=observed_at,
                identifiers=identifiers,
                attributes={
                    "canonical_name": canonical_name,
                    "dns_zone": zone_text,
                    "dns_record_type": record_type,
                    "dns_record_value": normalized_value,
                    "dns_ttl": int(ttl),
                },
            )
        )
    return observations, records_received


def _server(value: Any) -> str:
    if not isinstance(value, str):
        raise InventoryConnectorError("DNS server must be a hostname or IP address")
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ord(char) < 33 for char in raw):
        raise InventoryConnectorError("DNS server must be a hostname or IP address")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        if any(not _HOST_LABEL_RE.fullmatch(label) for label in raw.split(".")):
            raise InventoryConnectorError("DNS server must be a hostname or IP address") from None
        return raw.lower()


def _zones(value: Any) -> list[dns.name.Name]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_ZONES:
        raise InventoryConnectorError(f"DNS zones must contain 1-{_MAX_ZONES} explicit names")
    result: list[dns.name.Name] = []
    seen: set[dns.name.Name] = set()
    for item in value:
        if not isinstance(item, str):
            raise InventoryConnectorError("DNS zone names must be strings")
        raw = item.strip().rstrip(".")
        if (
            not raw
            or raw == "*"
            or len(raw) > 253
            or any(not _HOST_LABEL_RE.fullmatch(label) for label in raw.split("."))
        ):
            raise InventoryConnectorError("DNS zones must be explicit non-root names")
        try:
            name = dns.name.from_text(f"{raw}.").canonicalize()
        except dns.exception.DNSException as exc:
            raise InventoryConnectorError("DNS zone name is invalid") from exc
        if name not in seen:
            result.append(name)
            seen.add(name)
    return result


def _tsig(
    config: dict[str, Any], secret: str | None
) -> tuple[dict[dns.name.Name, Any] | None, dns.name.Name | None, dns.name.Name]:
    raw_name = config.get("tsig_name")
    if raw_name is not None and not isinstance(raw_name, str):
        raise InventoryConnectorError("DNS TSIG key name must be a string")
    name_text = (raw_name or "").strip()
    allow_unsigned = _boolean(config, "allow_unsigned", default=False)
    if not secret and not name_text:
        if not allow_unsigned:
            raise InventoryConnectorError(
                "DNS TSIG authentication is required unless unsigned AXFR is explicitly allowed"
            )
        return None, None, dns.tsig.HMAC_SHA256
    if not secret or not name_text:
        raise InventoryConnectorError("DNS TSIG key name and secret must be configured together")
    if len(name_text) > 253 or any(ord(char) < 33 for char in name_text):
        raise InventoryConnectorError("DNS TSIG key name is invalid")
    raw_algorithm = config.get("tsig_algorithm", "hmac-sha256")
    if not isinstance(raw_algorithm, str):
        raise InventoryConnectorError("DNS TSIG algorithm must be a string")
    algorithm_name = raw_algorithm.strip().lower().rstrip(".")
    algorithm = _TSIG_ALGORITHMS.get(algorithm_name)
    if algorithm is None:
        raise InventoryConnectorError("DNS TSIG algorithm must be hmac-sha256 or hmac-sha512")
    try:
        keyname = dns.name.from_text(name_text).canonicalize()
        keyring = dns.tsigkeyring.from_text({name_text: (algorithm, secret)})
    except (binascii.Error, dns.exception.DNSException, ValueError) as exc:
        raise InventoryConnectorError("DNS TSIG key name or secret encoding is invalid") from exc
    return keyring, keyname, algorithm


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
        safe = str(exc).replace("Webhook host", "DNS server").replace("Webhook URL", "DNS server")
        raise InventoryConnectorError(safe) from exc
    return pinned_ip


def _record_name(name: dns.name.Name, origin: dns.name.Name) -> str:
    absolute = name if name.is_absolute() else name.derelativize(origin)
    return absolute.to_text(omit_final_dot=True).lower()


def _target_name(value: str, origin: dns.name.Name) -> str:
    try:
        name = dns.name.from_text(value, origin=origin)
    except dns.exception.DNSException as exc:
        raise InventoryConnectorError("DNS target name is invalid") from exc
    if not name.is_absolute() or name == dns.name.root:
        raise InventoryConnectorError("DNS target name is invalid")
    result = name.to_text(omit_final_dot=True).lower()
    if result.startswith("*."):
        raise InventoryConnectorError("DNS target name is invalid")
    return result


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int) or isinstance(value, str) and _INTEGER_RE.fullmatch(value.strip())
    ):
        raise InventoryConnectorError(f"DNS {field} must be an integer")
    result = int(value)
    if result < minimum or result > maximum:
        raise InventoryConnectorError(f"DNS {field} must be between {minimum} and {maximum}")
    return result


def _boolean(config: dict[str, Any], field: str, *, default: bool) -> bool:
    value = config.get(field, default)
    if not isinstance(value, bool):
        raise InventoryConnectorError(f"DNS {field} must be true or false")
    return value
