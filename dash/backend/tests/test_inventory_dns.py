"""Authoritative DNS inventory adapter contract and security coverage."""

from __future__ import annotations

from typing import Any

import dns.asyncquery
import dns.name
import dns.query
import dns.rdataset
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.zone
import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import notifications, passive_inventory
from app.services.inventory_dns import DnsInventoryAdapter, _transfer_zone

pytestmark = pytest.mark.release_gate


def _zone(origin: str, records: str) -> dns.zone.Zone:
    return dns.zone.from_text(
        f"""$ORIGIN {origin}
@ 3600 IN SOA ns hostmaster 1 3600 600 86400 60
@ 3600 IN NS ns
{records}
""",
        origin=origin,
        relativize=False,
        check_origin=False,
    )


async def test_dns_axfr_maps_records_with_tsig_and_pinned_resolution() -> None:
    calls: list[dict[str, Any]] = []
    resolved: list[tuple[str, bool]] = []

    def resolve(url: str, *, allow_private: bool = False) -> tuple[str, str]:
        resolved.append((url, allow_private))
        return "dns.internal.test", "10.20.30.40"

    async def transfer(
        pinned_ip: str,
        zone_name: dns.name.Name,
        **kwargs: Any,
    ) -> dns.zone.Zone:
        calls.append({"pinned_ip": pinned_ip, "zone": str(zone_name), **kwargs})
        return _zone(
            "example.test.",
            """www 60 IN A 192.0.2.10
www 60 IN AAAA 2001:db8::10
portal 120 IN CNAME www
* 60 IN A 192.0.2.99
""",
        )

    connector = InventoryConnector(
        name="Authoritative DNS",
        connector_type=PassiveConnectorType.DNS,
        config_json={
            "server": "DNS.Internal.Test.",
            "zones": ["Example.Test."],
            "tsig_name": "vulna-transfer.example.test.",
            "tsig_algorithm": "hmac-sha512",
            "allow_private": True,
            "timeout_seconds": 12,
            "lifetime_seconds": 45,
            "record_limit": 100,
        },
    )
    secret = "c3VwZXItc2VjcmV0"
    adapter = DnsInventoryAdapter(transfer=transfer, resolver=resolve)
    tested = await adapter.test(connector, secret, source_data=None)
    assert tested == {
        "zones_transferred": 1,
        "records_received": 6,
        "records_visible": 3,
        "transfer": "AXFR",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(connector, secret, cursor={}, source_data=None)
    assert cursor == {}
    assert observations[0].identifiers == [
        {"type": "fqdn", "value": "www.example.test"},
        {"type": "ip_address", "value": "192.0.2.10"},
    ]
    assert observations[0].attributes == {
        "canonical_name": "www.example.test",
        "dns_zone": "example.test",
        "dns_record_type": "A",
        "dns_record_value": "192.0.2.10",
        "dns_ttl": 60,
    }
    assert observations[1].identifiers[-1] == {
        "type": "ip_address",
        "value": "2001:db8::10",
    }
    assert observations[2].identifiers == [
        {"type": "fqdn", "value": "portal.example.test"},
        {"type": "fqdn", "value": "www.example.test"},
    ]
    assert all(secret not in str(observation) for observation in observations)
    assert resolved == [
        ("https://dns.internal.test/", True),
        ("https://dns.internal.test/", True),
    ]
    call = calls[-1]
    assert call["pinned_ip"] == "10.20.30.40"
    assert call["zone"] == "example.test."
    assert call["keyname"] == dns.name.from_text("vulna-transfer.example.test.")
    assert call["algorithm"] == dns.tsig.HMAC_SHA512
    assert call["timeout_seconds"] == 12
    assert call["lifetime_seconds"] == 45
    assert call["record_limit"] == 100
    assert secret not in str(tested)
    assert secret not in str(cursor)
    assert PassiveConnectorType.DNS in passive_inventory.ADAPTERS


async def test_dns_unsigned_opt_in_collects_all_explicit_zones_and_ptr() -> None:
    transferred: list[str] = []

    async def transfer(
        pinned_ip: str,
        zone_name: dns.name.Name,
        **kwargs: Any,
    ) -> dns.zone.Zone:
        del pinned_ip
        transferred.append(str(zone_name))
        assert kwargs["keyring"] is None
        if str(zone_name) == "2.0.192.in-addr.arpa.":
            return _zone("2.0.192.in-addr.arpa.", "10 60 IN PTR app.example.test.\n")
        return _zone("example.test.", "app 60 IN A 192.0.2.10\n")

    connector = InventoryConnector(
        name="Unsigned DNS",
        connector_type=PassiveConnectorType.DNS,
        config_json={
            "server": "203.0.113.53",
            "zones": ["2.0.192.in-addr.arpa", "example.test"],
            "allow_unsigned": True,
        },
    )
    adapter = DnsInventoryAdapter(
        transfer=transfer,
        resolver=lambda _url, **_kwargs: ("203.0.113.53", "203.0.113.53"),
    )
    observations, cursor = await adapter.collect(connector, None, cursor={}, source_data=None)
    assert cursor == {}
    assert transferred == ["2.0.192.in-addr.arpa.", "example.test."]
    assert observations[0].identifiers == [
        {"type": "ip_address", "value": "192.0.2.10"},
        {"type": "fqdn", "value": "app.example.test"},
    ]
    assert observations[0].attributes["dns_record_type"] == "PTR"
    assert len(observations) == 2


async def test_dns_rejects_implicit_unsigned_access_bad_auth_cursor_and_limits() -> None:
    async def transfer(
        pinned_ip: str,
        zone_name: dns.name.Name,
        **kwargs: Any,
    ) -> dns.zone.Zone:
        del pinned_ip, zone_name, kwargs
        return _zone(
            "example.test.",
            """one 60 IN A 192.0.2.1
two 60 IN A 192.0.2.2
three 60 IN A 192.0.2.3
""",
        )

    connector = InventoryConnector(
        name="DNS safety",
        connector_type=PassiveConnectorType.DNS,
        config_json={"server": "dns.example.test", "zones": ["example.test"]},
    )
    adapter = DnsInventoryAdapter(
        transfer=transfer,
        resolver=lambda _url, **_kwargs: ("dns.example.test", "198.51.100.53"),
    )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="TSIG authentication"):
        await adapter.test(connector, None, source_data=None)

    connector.config_json["tsig_name"] = "transfer.example.test"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="configured together"):
        await adapter.test(connector, None, source_data=None)

    with pytest.raises(passive_inventory.InventoryConnectorError, match="encoding is invalid"):
        await adapter.test(connector, "not-base64", source_data=None)

    connector.config_json = {
        "server": "dns.example.test",
        "zones": ["example.test"],
        "allow_unsigned": True,
    }
    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(connector, None, cursor={"operation": "UPDATE"}, source_data=None)

    connector.config_json["record_limit"] = 2
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await adapter.collect(connector, None, cursor={}, source_data=None)

    def blocked(url: str, *, allow_private: bool = False) -> tuple[str, str]:
        del url, allow_private
        raise notifications.NotificationError("Webhook host resolves to a blocked address")

    with pytest.raises(passive_inventory.InventoryConnectorError, match="DNS server resolves"):
        await DnsInventoryAdapter(transfer=transfer, resolver=blocked).test(
            connector, None, source_data=None
        )


async def test_dns_transport_forces_axfr_tcp_tsig_and_aborts_during_oversize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def inbound(
        where: str,
        zone: dns.zone.Zone,
        **kwargs: Any,
    ) -> None:
        calls.append({"where": where, "zone": zone, **kwargs})
        first = dns.rdataset.from_text("IN", "A", 60, "192.0.2.1")
        second = dns.rdataset.from_text("IN", "A", 60, "192.0.2.2")
        with zone.writer(True) as transaction:
            transaction.add(dns.name.from_text("one.example.test."), first)
            transaction.add(dns.name.from_text("two.example.test."), second)

    monkeypatch.setattr(dns.asyncquery, "inbound_xfr", inbound)
    keyname = dns.name.from_text("transfer.example.test.")
    keyring = dns.tsigkeyring.from_text(
        {"transfer.example.test.": (dns.tsig.HMAC_SHA256, "c3VwZXItc2VjcmV0")}
    )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await _transfer_zone(
            "192.0.2.53",
            dns.name.from_text("example.test."),
            keyring=keyring,
            keyname=keyname,
            algorithm=dns.tsig.HMAC_SHA256,
            timeout_seconds=7,
            lifetime_seconds=20,
            record_limit=1,
        )
    call = calls[0]
    assert call["where"] == "192.0.2.53"
    assert call["port"] == 53
    assert call["timeout"] == 7
    assert call["lifetime"] == 20
    assert call["udp_mode"] == dns.query.UDPMode.NEVER
    query = call["query"]
    assert query.question[0].rdtype == dns.rdatatype.AXFR
    assert query.keyring.name == keyname
    assert query.keyring.algorithm == dns.tsig.HMAC_SHA256
