"""Change-detection tests: port open/close and version-change events."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from httpx import AsyncClient

from tests.conftest import probe_cert_headers
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

_XML_HEADERS = {"Content-Type": "application/xml"}


def _scan_xml(ip: str, ports: list[tuple[int, str, str, str]]) -> bytes:
    """Build minimal Nmap XML for a host with the given open ports."""
    port_xml = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/>'
        f'<service name="{name}" product="{product}" version="{version}"/></port>'
        for p, name, product, version in ports
    )
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        f"<ports>{port_xml}</ports></host></nmaprun>"
    ).encode()


async def _setup(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> tuple[dict[str, str], str, dict[str, str]]:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    job_id = job.json()["id"]
    headers = {**probe_cert_headers(probe["fingerprint"]), **_XML_HEADERS}
    return probe, job_id, headers


async def _upload(client: AsyncClient, probe: dict[str, str], job_id: str, xml: bytes,
                  headers: dict[str, str]) -> dict[str, int]:
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results",
        content=xml,
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _change_types(client: AsyncClient, admin_headers: dict[str, str]) -> list[str]:
    resp = await client.get("/api/v1/changes", headers=admin_headers)
    assert resp.status_code == 200
    return [e["event_type"] for e in resp.json()["items"]]


async def test_first_scan_records_asset_discovered(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    summary = await _upload(
        client, probe, job_id, _scan_xml("10.20.0.5", [(22, "ssh", "", "")]), headers
    )
    assert summary["change_events"] >= 1
    assert "asset_discovered" in await _change_types(client, admin_headers)


async def test_opening_a_port_creates_an_event(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(client, probe, job_id, _scan_xml("10.20.0.5", [(22, "ssh", "", "")]), headers)
    # Second scan: port 80 is now open.
    summary = await _upload(
        client, probe, job_id,
        _scan_xml("10.20.0.5", [(22, "ssh", "", ""), (80, "http", "nginx", "")]), headers
    )
    assert summary["change_events"] == 1
    assert "new_port_opened" in await _change_types(client, admin_headers)


async def test_closing_a_port_creates_an_event(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(
        client, probe, job_id,
        _scan_xml("10.20.0.5", [(22, "ssh", "", ""), (80, "http", "", "")]), headers
    )
    # Second scan: port 80 has closed.
    summary = await _upload(
        client, probe, job_id, _scan_xml("10.20.0.5", [(22, "ssh", "", "")]), headers
    )
    assert summary["change_events"] == 1
    assert "port_closed" in await _change_types(client, admin_headers)


async def test_scan_comparison_shows_open_and_close(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    """Acceptance: opening then closing a port yields two events, both visible."""
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(client, probe, job_id, _scan_xml("10.20.0.5", [(22, "ssh", "", "")]), headers)
    await _upload(
        client, probe, job_id,
        _scan_xml("10.20.0.5", [(22, "ssh", "", ""), (8080, "http", "", "")]), headers
    )
    await _upload(client, probe, job_id, _scan_xml("10.20.0.5", [(22, "ssh", "", "")]), headers)

    # Filter to this asset and confirm both the open and close events are present.
    assets = await client.get("/api/v1/assets", headers=admin_headers)
    asset_id = assets.json()["items"][0]["id"]
    resp = await client.get(f"/api/v1/changes?asset_id={asset_id}", headers=admin_headers)
    types = [e["event_type"] for e in resp.json()["items"]]
    assert "new_port_opened" in types
    assert "port_closed" in types


async def test_service_version_change_event(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(
        client, probe, job_id,
        _scan_xml("10.20.0.5", [(22, "ssh", "OpenSSH", "8.9")]), headers
    )
    summary = await _upload(
        client, probe, job_id,
        _scan_xml("10.20.0.5", [(22, "ssh", "OpenSSH", "9.6")]), headers
    )
    assert summary["change_events"] == 1
    resp = await client.get(
        "/api/v1/changes?event_type=service_version_changed", headers=admin_headers
    )
    assert resp.json()["total"] == 1
    event = resp.json()["items"][0]
    assert event["before_json"]["version"] == "8.9"
    assert event["after_json"]["version"] == "9.6"


async def test_changes_require_auth(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/changes")
    assert resp.status_code == 401
