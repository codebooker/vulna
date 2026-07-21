"""End-to-end asset discovery: result upload -> ingest/dedup -> asset API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.models.asset import Asset
from app.models.enums import AssetType
from app.models.organization import Organization
from app.models.site import Site
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers, start_job_attempt
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

SAMPLE_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.5" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
    <hostnames><hostname name="host5.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx"/></port>
    </ports>
    <os><osmatch name="Linux 5.4" accuracy="98"/></os>
  </host>
</nmaprun>
"""

# A -Pn scan reports every scanned address as "up" even when nothing is there.
# An address with no open service (and no MAC on the local segment) is empty space.
EMPTY_HOST_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

IP_ONLY_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.8" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
  </host>
</nmaprun>
"""

HOSTNAME_ENRICHED_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.20.0.8" addrtype="ipv4"/>
    <hostnames><hostname name="portal.example.test" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
  </host>
</nmaprun>
"""

_XML_HEADERS = {"Content-Type": "application/xml"}


async def _create_job(
    client: AsyncClient, admin_headers: dict[str, str], probe: dict[str, str]
) -> tuple[str, dict[str, str]]:
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    job_id = resp.json()["id"]
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == job_id
    return job_id, attempt_headers


async def test_upload_discovers_assets_and_services(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}

    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["hosts_seen"] == 1
    assert body["assets_created"] == 1
    assert body["assets_updated"] == 0
    assert body["services_upserted"] == 2
    assert body["change_events"] == 1  # asset_discovered
    assert body["findings_created"] == 0

    # The asset and its services are readable via the API.
    listed = await client.get("/api/v1/assets", headers=admin_headers)
    assert listed.json()["total"] == 1
    asset = listed.json()["items"][0]
    assert asset["operating_system"] == "Linux 5.4"

    detail = await client.get(f"/api/v1/assets/{asset['id']}", headers=admin_headers)
    body = detail.json()
    assert {s["port"] for s in body["services"]} == {22, 80}
    id_values = {i["identifier_value"] for i in body["identifiers"]}
    assert {"10.20.0.5", "00:11:22:33:44:55", "host5.lan"} <= id_values


async def test_empty_address_does_not_create_phantom_asset(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}

    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=EMPTY_HOST_XML,
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["hosts_seen"] == 1
    assert body["assets_created"] == 0  # empty address is not a device

    listed = await client.get("/api/v1/assets", headers=admin_headers)
    assert listed.json()["total"] == 0


async def test_reupload_updates_not_duplicates(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}
    url = f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results"

    first = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert first.json()["assets_created"] == 1
    second = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["assets_created"] == 0
    assert second.json()["assets_updated"] == 0

    # Still exactly one asset — repeated scans update rather than duplicate.
    listed = await client.get("/api/v1/assets", headers=admin_headers)
    assert listed.json()["total"] == 1


async def test_reupload_promotes_ip_name_and_lists_identifiers(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}
    url = f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results"

    first = await client.post(url, content=IP_ONLY_XML, headers=headers)
    assert first.json()["assets_created"] == 1
    second = await client.post(url, content=HOSTNAME_ENRICHED_XML, headers=headers)
    assert second.json()["assets_updated"] == 1

    listed = await client.get("/api/v1/assets", headers=admin_headers)
    asset = listed.json()["items"][0]
    assert asset["canonical_name"] == "portal.example.test"
    assert asset["ip_addresses"] == ["10.20.0.8"]
    assert asset["hostnames"] == ["portal.example.test"]
    assert asset["mac_addresses"] == []


async def test_upload_rejects_malformed_xml(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=b"<not-nmap/>",
        headers=headers,
    )
    assert resp.status_code == 422


async def test_upload_requires_client_cert(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, _ = await _create_job(client, admin_headers, probe)
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=_XML_HEADERS,
    )
    assert resp.status_code == 401


async def test_assets_are_org_scoped(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers, **_XML_HEADERS}
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=headers,
    )
    # A viewer in the same org can read assets (read is any authenticated role).
    resp = await client.get("/api/v1/assets", headers=viewer_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


async def test_asset_offset_pages_are_stable_when_last_seen_ties(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = Site(
        organization_id=organization.id,
        name="Paging site",
        code="PAGING-ASSETS",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.flush()
    seen_at = datetime(2026, 7, 20, tzinfo=UTC)
    assets = [
        Asset(
            organization_id=organization.id,
            site_id=site.id,
            canonical_name=f"10.30.0.{index}",
            asset_type=AssetType.UNKNOWN,
            last_seen_at=seen_at,
        )
        for index in range(1, 206)
    ]
    db_session.add_all(assets)
    await db_session.commit()

    first = await client.get("/api/v1/assets?limit=200&offset=0", headers=admin_headers)
    second = await client.get("/api/v1/assets?limit=200&offset=200", headers=admin_headers)
    ids = [item["id"] for item in first.json()["items"] + second.json()["items"]]

    assert len(ids) == 205
    assert len(set(ids)) == 205
    assert ids == sorted(ids)
