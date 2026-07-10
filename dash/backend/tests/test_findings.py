"""End-to-end finding flow: discovery -> Nuclei/testssl upload -> findings API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from httpx import AsyncClient

from tests.conftest import probe_cert_headers
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

# Discovery scan: asset 10.20.0.5 with an open 443 service.
NMAP_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
    b'<address addr="10.20.0.5" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'
    b"</ports></host></nmaprun>"
)

NUCLEI_JSONL = (
    b'{"template-id":"tls-1-0","type":"ssl","host":"10.20.0.5:443","ip":"10.20.0.5",'
    b'"matched-at":"10.20.0.5:443","info":{"name":"TLS 1.0 detected","severity":"medium",'
    b'"description":"Legacy protocol","reference":["https://ref/tls"],'
    b'"classification":{"cve-id":["CVE-2011-3389"]}}}\n'
)

TESTSSL_JSON = (
    b'[{"id":"SSLv3","ip":"host/10.20.0.5","port":"443","severity":"HIGH",'
    b'"finding":"SSLv3 is offered (POODLE)"}]'
)


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
    headers = probe_cert_headers(probe["fingerprint"])
    # Run discovery first so findings can map to a real asset/service.
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?scanner=nmap",
        content=NMAP_XML,
        headers={**headers, "Content-Type": "application/xml"},
    )
    return probe, job_id, {**headers, "Content-Type": "application/json"}


async def _upload(client: AsyncClient, probe: dict[str, str], job_id: str, scanner: str,
                  body: bytes, headers: dict[str, str]) -> dict[str, int]:
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?scanner={scanner}",
        content=body,
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_nuclei_upload_creates_normalized_finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    summary = await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    assert summary["findings_created"] == 1

    listed = await client.get("/api/v1/findings", headers=admin_headers)
    assert listed.json()["total"] == 1
    finding = listed.json()["items"][0]
    assert finding["scanner_name"] == "nuclei"
    assert finding["severity"] == "medium"
    assert finding["cve_ids_json"] == ["CVE-2011-3389"]
    # Includes scanner evidence and references (acceptance criterion).
    assert finding["references_json"] == ["https://ref/tls"]
    assert finding["evidence_json"]["matched_at"] == "10.20.0.5:443"
    # Mapped to the discovered asset.
    assert finding["asset_id"] is not None


async def test_repeated_upload_does_not_duplicate(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    first = await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    assert first["findings_created"] == 1
    second = await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    assert second["findings_created"] == 0
    assert second["findings_updated"] == 1
    listed = await client.get("/api/v1/findings", headers=admin_headers)
    assert listed.json()["total"] == 1


async def test_testssl_upload_creates_weak_protocol_finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    summary = await _upload(client, probe, job_id, "testssl", TESTSSL_JSON, headers)
    assert summary["findings_created"] == 1
    listed = await client.get(
        "/api/v1/findings?finding_type=weak_protocol", headers=admin_headers
    )
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["severity"] == "high"


async def test_resolved_finding_reopens_on_recurrence(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    finding_id = (await client.get("/api/v1/findings", headers=admin_headers)).json()["items"][0][
        "id"
    ]
    # Operator resolves it.
    resolved = await client.patch(
        f"/api/v1/findings/{finding_id}", json={"status": "resolved"}, headers=admin_headers
    )
    assert resolved.json()["status"] == "resolved"
    # The same issue recurs on the next scan -> reopened.
    summary = await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    assert summary["findings_reopened"] == 1
    got = await client.get(f"/api/v1/findings/{finding_id}", headers=admin_headers)
    assert got.json()["status"] == "reopened"
    assert got.json()["reopened_count"] == 1


async def test_finding_update_requires_operator(
    client: AsyncClient, admin_headers: dict[str, str], viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    await _upload(client, probe, job_id, "nuclei", NUCLEI_JSONL, headers)
    finding_id = (await client.get("/api/v1/findings", headers=viewer_headers)).json()["items"][0][
        "id"
    ]
    # Viewer can read but not modify.
    resp = await client.patch(
        f"/api/v1/findings/{finding_id}", json={"status": "false_positive"}, headers=viewer_headers
    )
    assert resp.status_code == 403
