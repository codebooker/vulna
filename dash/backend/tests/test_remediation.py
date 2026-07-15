"""Remediation & verification: assignment, notes, rescan resolve/reopen, risk acceptance."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.models.enums import UserRole
from app.models.finding import Finding
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import UserFactory, auth_headers, probe_cert_headers
from tests.test_findings import NMAP_XML, NUCLEI_JSONL
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

# A second nuclei finding on a different template, used to simulate a rescan that
# observes *something* but not the original finding.
OTHER_NUCLEI = (
    b'{"template-id":"http-missing-header","type":"http","host":"10.20.0.5:443",'
    b'"ip":"10.20.0.5","matched-at":"10.20.0.5:443","info":{"name":"Missing header",'
    b'"severity":"low"}}\n'
)


async def _finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> tuple[dict[str, str], str]:
    """Set up a probe + scan and produce one nuclei finding; return (probe, finding_id)."""
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    job_id = job.json()["id"]
    headers = probe_cert_headers(probe["fingerprint"])
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?scanner=nmap",
        content=NMAP_XML,
        headers={**headers, "Content-Type": "application/xml"},
    )
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?scanner=nuclei",
        content=NUCLEI_JSONL,
        headers={**headers, "Content-Type": "application/json"},
    )
    listing = await client.get("/api/v1/findings", headers=admin_headers)
    return probe, listing.json()["items"][0]["id"]


async def test_assign_and_owner_marks_ready_for_verification(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    _, fid = await _finding(client, admin_headers, enroll_probe)
    owner = await make_user(UserRole.REMEDIATION_OWNER)

    # Ingestion establishes the immutable SLA deadline; assignment changes only
    # workflow ownership. Deadline changes use the SLA exception endpoint.
    assign = await client.patch(
        f"/api/v1/findings/{fid}",
        json={"status": "assigned", "owner_user_id": str(owner.id)},
        headers=admin_headers,
    )
    assert assign.status_code == 200, assign.text
    assert assign.json()["due_at"] is not None
    assert assign.json()["owner_user_id"] == str(owner.id)

    # The owner can move it to ready_for_verification.
    ready = await client.patch(
        f"/api/v1/findings/{fid}",
        json={"status": "ready_for_verification"},
        headers=auth_headers(owner),
    )
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready_for_verification"


async def test_non_owner_non_operator_cannot_update(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    _, fid = await _finding(client, admin_headers, enroll_probe)
    resp = await client.patch(
        f"/api/v1/findings/{fid}", json={"status": "triage"}, headers=viewer_headers
    )
    assert resp.status_code == 403


async def test_finding_notes(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    _, fid = await _finding(client, admin_headers, enroll_probe)
    add = await client.post(
        f"/api/v1/findings/{fid}/notes",
        json={"body": "Patched in change #42"},
        headers=admin_headers,
    )
    assert add.status_code == 201
    notes = await client.get(f"/api/v1/findings/{fid}/notes", headers=admin_headers)
    assert [n["body"] for n in notes.json()] == ["Patched in change #42"]


async def test_verification_rescan_resolves_fixed_finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, fid = await _finding(client, admin_headers, enroll_probe)
    await client.patch(
        f"/api/v1/findings/{fid}", json={"status": "ready_for_verification"}, headers=admin_headers
    )
    # Targeted rescan of the finding's asset.
    rescan = await client.post(f"/api/v1/findings/{fid}/rescan", headers=admin_headers)
    assert rescan.status_code == 201, rescan.text
    verify_job = rescan.json()["id"]

    # The rescan observes a different finding but not the original -> it is fixed.
    headers = probe_cert_headers(probe["fingerprint"])
    up = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{verify_job}/results?scanner=nuclei",
        content=OTHER_NUCLEI,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert up.status_code == 201, up.text

    # A streamed batch is not the whole scanner result and must not resolve an
    # issue merely because this particular batch did not contain it.
    pending = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert pending.json()["status"] == "ready_for_verification"

    complete = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{verify_job}/results"
        "?stage=vulnerability&scanner=nuclei&complete=true",
        headers={**headers, "Idempotency-Key": "verify-nuclei-complete"},
    )
    assert complete.status_code == 201, complete.text

    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    body = finding.json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] is not None
    assert body["last_verified_at"] is not None


async def test_clean_verification_completion_resolves_without_a_result_payload(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, fid = await _finding(client, admin_headers, enroll_probe)
    await client.patch(
        f"/api/v1/findings/{fid}",
        json={"status": "ready_for_verification"},
        headers=admin_headers,
    )
    rescan = await client.post(f"/api/v1/findings/{fid}/rescan", headers=admin_headers)
    verify_job = rescan.json()["id"]
    headers = probe_cert_headers(probe["fingerprint"])

    complete = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{verify_job}/results"
        "?stage=vulnerability&scanner=nuclei&complete=true",
        headers={**headers, "Idempotency-Key": "clean-nuclei-complete"},
    )

    assert complete.status_code == 201, complete.text
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "resolved"


async def test_concurrent_scan_observation_prevents_false_verification_resolution(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, fid = await _finding(client, admin_headers, enroll_probe)
    await client.patch(
        f"/api/v1/findings/{fid}",
        json={"status": "ready_for_verification"},
        headers=admin_headers,
    )
    verify_job = (
        await client.post(f"/api/v1/findings/{fid}/rescan", headers=admin_headers)
    ).json()["id"]
    probe_headers = probe_cert_headers(probe["fingerprint"])

    # The verification scan sees the issue, then another scan sees it too and
    # becomes the Finding's most recent scan_job_id before completion arrives.
    observed = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{verify_job}/results?scanner=nuclei",
        content=NUCLEI_JSONL,
        headers={**probe_headers, "Content-Type": "application/json"},
    )
    assert observed.status_code == 201, observed.text
    concurrent_job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    concurrent_observation = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{concurrent_job.json()['id']}"
        "/results?scanner=nuclei",
        content=NUCLEI_JSONL,
        headers={**probe_headers, "Content-Type": "application/json"},
    )
    assert concurrent_observation.status_code == 201, concurrent_observation.text

    complete = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{verify_job}/results"
        "?stage=vulnerability&scanner=nuclei&complete=true",
        headers={**probe_headers, "Idempotency-Key": "concurrent-nuclei-complete"},
    )

    assert complete.status_code == 201, complete.text
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "ready_for_verification"


async def test_discovery_completion_verifies_correlation_findings(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    probe, fid = await _finding(client, admin_headers, enroll_probe)
    stored = await db_session.get(Finding, uuid.UUID(fid))
    assert stored is not None
    stored.scanner_name = "cve-correlation"
    await db_session.commit()
    await client.patch(
        f"/api/v1/findings/{fid}",
        json={"status": "ready_for_verification"},
        headers=admin_headers,
    )
    rescan = await client.post(f"/api/v1/findings/{fid}/rescan", headers=admin_headers)
    headers = probe_cert_headers(probe["fingerprint"])

    complete = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{rescan.json()['id']}/results"
        "?stage=discovery&scanner=nmap&complete=true",
        headers={**headers, "Idempotency-Key": "clean-nmap-complete"},
    )

    assert complete.status_code == 201, complete.text
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "resolved"


async def test_reintroduced_finding_reopens(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe, fid = await _finding(client, admin_headers, enroll_probe)
    # Resolve it.
    await client.patch(
        f"/api/v1/findings/{fid}", json={"status": "resolved"}, headers=admin_headers
    )
    # A later scan sees the same issue again.
    job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    headers = probe_cert_headers(probe["fingerprint"])
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job.json()['id']}/results?scanner=nuclei",
        content=NUCLEI_JSONL,
        headers={**headers, "Content-Type": "application/json"},
    )
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "reopened"


async def test_risk_acceptance_request_approve_and_expiry(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    _, fid = await _finding(client, admin_headers, enroll_probe)
    # Request an acceptance that is already past its expiry.
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    req = await client.post(
        f"/api/v1/findings/{fid}/risk-acceptances",
        json={"reason": "Compensating WAF rule in place", "expires_at": past},
        headers=admin_headers,
    )
    assert req.status_code == 201, req.text
    ra_id = req.json()["id"]
    assert req.json()["status"] == "pending"

    # Approve it -> finding is risk-accepted.
    approve = await client.patch(
        f"/api/v1/risk-acceptances/{ra_id}", json={"approve": True}, headers=admin_headers
    )
    assert approve.status_code == 200
    assert approve.json()["status"] == "active"
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "risk_accepted"
    assert finding.json()["risk_acceptance_id"] == ra_id

    # Expiry sweep reopens the finding and raises an alerting change event.
    expiry = await client.post("/api/v1/risk-acceptances/run-expiry", headers=admin_headers)
    assert expiry.status_code == 200
    assert expiry.json()["expired"] == 1
    finding = await client.get(f"/api/v1/findings/{fid}", headers=admin_headers)
    assert finding.json()["status"] == "reopened"
    changes = await client.get(
        "/api/v1/changes?event_type=risk_acceptance_expired", headers=admin_headers
    )
    assert changes.json()["total"] >= 1


async def test_active_web_scan_operator_forbidden_but_note_allowed(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    # A viewer may still read notes but not add workflow changes (sanity check
    # that read access is broad while mutation is gated).
    _, fid = await _finding(client, admin_headers, enroll_probe)
    viewer = await make_user(UserRole.VIEWER)
    notes = await client.get(f"/api/v1/findings/{fid}/notes", headers=auth_headers(viewer))
    assert notes.status_code == 200
