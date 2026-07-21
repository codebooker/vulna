"""End-to-end finding flow: discovery -> Nuclei/testssl upload -> findings API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.models.asset import Asset
from app.models.enums import AssetType, FindingStatus, FindingType, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.site import Site
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers, start_job_attempt
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
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == job_id
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers}
    # Run discovery first so findings can map to a real asset/service.
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?stage=discovery&scanner=nmap",
        content=NMAP_XML,
        headers={**headers, "Content-Type": "application/xml"},
    )
    return probe, job_id, {**headers, "Content-Type": "application/json"}


async def _upload(
    client: AsyncClient,
    probe: dict[str, str],
    job_id: str,
    scanner: str,
    body: bytes,
    headers: dict[str, str],
) -> dict[str, int]:
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results"
        f"?stage={'vulnerability' if scanner == 'nuclei' else 'tls'}&scanner={scanner}",
        content=body,
        headers=headers,
    )
    assert resp.status_code in (200, 201), resp.text
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
    assert second["findings_updated"] == 0
    assert second["duplicate"] is True
    listed = await client.get("/api/v1/findings", headers=admin_headers)
    assert listed.json()["total"] == 1


async def test_testssl_upload_creates_weak_protocol_finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, job_id, headers = await _setup(client, admin_headers, enroll_probe)
    summary = await _upload(client, probe, job_id, "testssl", TESTSSL_JSON, headers)
    assert summary["findings_created"] == 1
    listed = await client.get("/api/v1/findings?finding_type=weak_protocol", headers=admin_headers)
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
    # The same issue recurs on the next scan -> reopened. A new job is
    # intentional: retransmitting an identical result for one attempt is a
    # durable-upload retry and must remain an idempotent no-op.
    next_job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    next_job_id = next_job.json()["id"]
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == next_job_id
    next_headers = {
        **probe_cert_headers(probe["fingerprint"]),
        **attempt_headers,
        "Content-Type": "application/json",
    }
    summary = await _upload(client, probe, next_job_id, "nuclei", NUCLEI_JSONL, next_headers)
    assert summary["findings_reopened"] == 1
    got = await client.get(f"/api/v1/findings/{finding_id}", headers=admin_headers)
    assert got.json()["status"] == "reopened"
    assert got.json()["reopened_count"] == 1


async def test_finding_update_requires_operator(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
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


async def test_finding_offset_pages_are_stable_when_last_seen_ties(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = Site(
        organization_id=organization.id,
        name="Paging site",
        code="PAGING-FINDINGS",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.flush()
    asset = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="paging-host",
        asset_type=AssetType.SERVER,
    )
    db_session.add(asset)
    await db_session.flush()
    seen_at = datetime(2026, 7, 20, tzinfo=UTC)
    db_session.add_all(
        [
            Finding(
                organization_id=organization.id,
                site_id=site.id,
                asset_id=asset.id,
                scanner_name="paging-test",
                canonical_finding_key=f"paging-{index:04d}",
                finding_type=FindingType.VULNERABILITY,
                title=f"Finding {index}",
                severity=Severity.LOW,
                status=FindingStatus.NEW,
                last_seen_at=seen_at,
            )
            for index in range(205)
        ]
    )
    await db_session.commit()

    first = await client.get("/api/v1/findings?limit=200&offset=0", headers=admin_headers)
    second = await client.get("/api/v1/findings?limit=200&offset=200", headers=admin_headers)
    ids = [item["id"] for item in first.json()["items"] + second.json()["items"]]

    assert len(ids) == 205
    assert len(set(ids)) == 205
    assert ids == sorted(ids)
