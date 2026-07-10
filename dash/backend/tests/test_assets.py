"""End-to-end asset discovery: result upload -> ingest/dedup -> asset API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from httpx import AsyncClient

from tests.conftest import probe_cert_headers
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

_XML_HEADERS = {"Content-Type": "application/xml"}


async def _create_job(
    client: AsyncClient, admin_headers: dict[str, str], probe: dict[str, str]
) -> str:
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    return resp.json()["id"]


async def test_upload_discovers_assets_and_services(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS}

    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body == {
        "hosts_seen": 1,
        "assets_created": 1,
        "assets_updated": 0,
        "services_upserted": 2,
    }

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


async def test_reupload_updates_not_duplicates(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS}
    url = f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results"

    first = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert first.json()["assets_created"] == 1
    second = await client.post(url, content=SAMPLE_XML, headers=headers)
    assert second.json()["assets_created"] == 0
    assert second.json()["assets_updated"] == 1

    # Still exactly one asset — repeated scans update rather than duplicate.
    listed = await client.get("/api/v1/assets", headers=admin_headers)
    assert listed.json()["total"] == 1


async def test_upload_rejects_malformed_xml(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS}
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
    job_id = await _create_job(client, admin_headers, probe)
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=_XML_HEADERS,
    )
    assert resp.status_code == 401


async def test_assets_are_org_scoped(
    client: AsyncClient, admin_headers: dict[str, str], viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id = await _create_job(client, admin_headers, probe)
    headers = {**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS}
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=SAMPLE_XML,
        headers=headers,
    )
    # A viewer in the same org can read assets (read is any authenticated role).
    resp = await client.get("/api/v1/assets", headers=viewer_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
