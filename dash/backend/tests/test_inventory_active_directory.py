"""Active Directory read-only importer contract and security coverage."""

from __future__ import annotations

import ssl
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import ANY

import pytest
from app.models.enums import PassiveConnectorType
from app.models.passive_inventory import InventoryConnector
from app.services import inventory_active_directory as directory
from app.services import notifications, passive_inventory
from app.services.inventory_active_directory import ActiveDirectoryInventoryAdapter
from ldap3 import NONE, SAFE_SYNC, SUBTREE  # type: ignore[import-untyped]

pytestmark = pytest.mark.release_gate


def _sid(*subauthorities: int) -> bytes:
    return (
        bytes([1, len(subauthorities)])
        + (5).to_bytes(6, "big")
        + b"".join(value.to_bytes(4, "little") for value in subauthorities)
    )


def _entry(
    guid: uuid.UUID,
    *,
    name: str,
    fqdn: str,
    disabled: bool = False,
) -> dict[str, Any]:
    return {
        "type": "searchResEntry",
        "dn": f"CN={name},OU=Servers,DC=example,DC=test",
        "attributes": {
            "dNSHostName": fqdn,
            "name": name,
            "sAMAccountName": f"{name}$",
            "operatingSystem": "Windows Server 2025",
            "operatingSystemVersion": "10.0 (26100)",
            "operatingSystemServicePack": [],
            "description": "Production application server",
            "location": "Datacenter A",
            "managedBy": "CN=Operations,OU=Groups,DC=example,DC=test",
            "userAccountControl": 4096 | (2 if disabled else 0),
            "whenChanged": datetime(2026, 7, 12, 20, 30, tzinfo=UTC),
        },
        "raw_attributes": {
            "objectGUID": [guid.bytes_le],
            "objectSid": [_sid(21, 111, 222, 333, 1234)],
        },
    }


async def test_active_directory_maps_pinned_paged_computers_and_excludes_disabled() -> None:
    calls: list[dict[str, Any]] = []
    resolved: list[tuple[str, bool]] = []
    active_guid = uuid.UUID("64bb6c74-f58f-4e5a-b479-7db79dfd28c5")

    def resolve(url: str, *, allow_private: bool = False) -> tuple[str, str]:
        resolved.append((url, allow_private))
        return "dc01.example.test", "10.20.30.50"

    def query(pinned_ip: str, **kwargs: Any) -> list[dict[str, Any]]:
        calls.append({"pinned_ip": pinned_ip, **kwargs})
        return [
            _entry(
                active_guid,
                name="APP-01",
                fqdn="APP-01.Example.Test.",
            ),
            _entry(
                uuid.UUID("b93468b3-6664-4a10-a208-ce7e71d4ddc5"),
                name="OLD-01",
                fqdn="old-01.example.test",
                disabled=True,
            ),
        ]

    connector = InventoryConnector(
        name="Domain computers",
        connector_type=PassiveConnectorType.ACTIVE_DIRECTORY,
        config_json={
            "server": "DC01.Example.Test.",
            "bind_user": "vulna-reader@example.test",
            "base_dn": "DC=example,DC=test",
            "allow_private": True,
            "page_size": 250,
            "timeout_seconds": 20,
            "record_limit": 5000,
        },
    )
    password = "bind-password-never-returned"
    adapter = ActiveDirectoryInventoryAdapter(query=query, resolver=resolve)
    tested = await adapter.test(connector, password, source_data=None)
    assert tested == {
        "records_received": 2,
        "records_visible": 1,
        "transport": "LDAPS",
        "filter": "computer objects",
        "read_only": True,
    }
    observations, cursor = await adapter.collect(connector, password, cursor={}, source_data=None)
    assert cursor == {}
    assert len(observations) == 1
    observation = observations[0]
    assert observation.source_record_id == f"ad:{active_guid}"
    assert observation.identifiers == [
        {"type": "fqdn", "value": "app-01.example.test"},
        {"type": "hostname", "value": "app-01"},
        {"type": "smb_name", "value": "app-01"},
    ]
    assert observation.attributes == {
        "canonical_name": "app-01.example.test",
        "directory_object_guid": str(active_guid),
        "directory_enabled": True,
        "directory_user_account_control": 4096,
        "directory_distinguished_name": "CN=APP-01,OU=Servers,DC=example,DC=test",
        "directory_object_sid": "S-1-5-21-111-222-333-1234",
        "operating_system": "Windows Server 2025",
        "operating_system_version": "10.0 (26100)",
        "directory_description": "Production application server",
        "directory_location": "Datacenter A",
        "directory_managed_by": "CN=Operations,OU=Groups,DC=example,DC=test",
        "directory_when_changed": "2026-07-12T20:30:00+00:00",
    }
    assert resolved == [
        ("https://dc01.example.test/", True),
        ("https://dc01.example.test/", True),
    ]
    call = calls[-1]
    assert call["pinned_ip"] == "10.20.30.50"
    assert call["tls_hostname"] == "dc01.example.test"
    assert call["bind_user"] == "vulna-reader@example.test"
    assert call["base_dn"] == "DC=example,DC=test"
    assert call["page_size"] == 250
    assert call["timeout_seconds"] == 20
    assert call["record_limit"] == 5000
    assert password not in str(tested)
    assert password not in str(cursor)
    assert password not in str(observation)
    assert PassiveConnectorType.ACTIVE_DIRECTORY in passive_inventory.ADAPTERS


async def test_active_directory_strict_configuration_limits_and_private_guard() -> None:
    def query(pinned_ip: str, **kwargs: Any) -> list[dict[str, Any]]:
        del pinned_ip, kwargs
        return [
            _entry(uuid.uuid4(), name="ONE", fqdn="one.example.test"),
            _entry(uuid.uuid4(), name="TWO", fqdn="two.example.test"),
        ]

    connector = InventoryConnector(
        name="Directory safety",
        connector_type=PassiveConnectorType.ACTIVE_DIRECTORY,
        config_json={
            "server": "dc.example.test",
            "bind_user": "reader@example.test",
            "base_dn": "DC=example,DC=test",
        },
    )
    adapter = ActiveDirectoryInventoryAdapter(
        query=query,
        resolver=lambda _url, **_kwargs: ("dc.example.test", "198.51.100.50"),
    )
    with pytest.raises(passive_inventory.InventoryConnectorError, match="password is required"):
        await adapter.test(connector, None, source_data=None)

    with pytest.raises(passive_inventory.InventoryConnectorError, match="cursor must be empty"):
        await adapter.collect(
            connector,
            "bind-password",
            cursor={"filter": "(objectClass=*)"},
            source_data=None,
        )

    connector.config_json["record_limit"] = 1
    with pytest.raises(passive_inventory.InventoryConnectorError, match="record limit"):
        await adapter.test(connector, "bind-password", source_data=None)

    connector.config_json["trust_pem"] = "-----BEGIN PRIVATE KEY-----\nvalue"
    with pytest.raises(passive_inventory.InventoryConnectorError, match="PEM certificate"):
        await adapter.test(connector, "bind-password", source_data=None)

    connector.config_json.pop("trust_pem")

    def blocked(url: str, *, allow_private: bool = False) -> tuple[str, str]:
        del url, allow_private
        raise notifications.NotificationError("Webhook host resolves to a blocked address")

    with pytest.raises(
        passive_inventory.InventoryConnectorError, match="Active Directory server resolves"
    ):
        await ActiveDirectoryInventoryAdapter(query=query, resolver=blocked).test(
            connector, "bind-password", source_data=None
        )


def test_active_directory_transport_is_verified_read_only_and_internally_paged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {"searches": []}

    class FakeTls:
        def __init__(self, **kwargs: Any) -> None:
            seen["tls"] = kwargs

    class FakeServer:
        def __init__(self, host: str, **kwargs: Any) -> None:
            seen["server"] = {"host": host, **kwargs}

    class FakeConnection:
        def __init__(self, server: Any, **kwargs: Any) -> None:
            del server
            seen["connection"] = {key: value for key, value in kwargs.items() if key != "password"}
            seen["password_present"] = bool(kwargs.get("password"))

        def open(self, *, read_server_info: bool) -> None:
            seen["open"] = read_server_info

        def bind(self) -> None:
            seen["bound"] = True

        def search(self, **kwargs: Any) -> tuple[bool, dict[str, Any], list[Any], None]:
            seen["searches"].append(kwargs)
            page = len(seen["searches"])
            cookie = b"next-page" if page == 1 else b""
            entry = _entry(
                uuid.UUID(int=page),
                name=f"HOST-{page}",
                fqdn=f"host-{page}.example.test",
            )
            return (
                True,
                {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}}},
                [entry],
                None,
            )

        def unbind(self) -> None:
            seen["unbound"] = True

    monkeypatch.setattr(directory, "Tls", FakeTls)
    monkeypatch.setattr(directory, "Server", FakeServer)
    monkeypatch.setattr(directory, "Connection", FakeConnection)
    trust = "-----BEGIN CERTIFICATE-----\npublic-root\n-----END CERTIFICATE-----\n"
    records = directory._query_directory(
        "10.20.30.50",
        tls_hostname="dc01.example.test",
        bind_user="reader@example.test",
        password="one-way-password",
        base_dn="DC=example,DC=test",
        trust_pem=trust,
        page_size=100,
        timeout_seconds=15,
        record_limit=5,
    )
    assert len(records) == 2
    assert seen["tls"] == {
        "validate": ssl.CERT_REQUIRED,
        "valid_names": ["dc01.example.test"],
        "sni": "dc01.example.test",
        "ca_certs_data": trust,
    }
    assert seen["server"] == {
        "host": "10.20.30.50",
        "port": 636,
        "use_ssl": True,
        "tls": ANY,
        "get_info": NONE,
        "connect_timeout": 15,
        "allowed_referral_hosts": [],
    }
    assert (
        seen["connection"].items()
        >= {
            "user": "reader@example.test",
            "client_strategy": SAFE_SYNC,
            "auto_referrals": False,
            "check_names": False,
            "read_only": True,
            "raise_exceptions": True,
            "receive_timeout": 15,
        }.items()
    )
    assert seen["password_present"] is True
    assert seen["open"] is False
    assert seen["bound"] is True and seen["unbound"] is True
    assert len(seen["searches"]) == 2
    first = seen["searches"][0]
    assert first["search_filter"] == "(&(objectCategory=computer)(objectClass=computer))"
    assert first["search_scope"] == SUBTREE
    assert first["attributes"] == list(directory._COMPUTER_ATTRIBUTES)
    assert first["paged_size"] == 100
    assert first["paged_criticality"] is True
    assert first["paged_cookie"] is None
    assert seen["searches"][1]["paged_cookie"] == b"next-page"
