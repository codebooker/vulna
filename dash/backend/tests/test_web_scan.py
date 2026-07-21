"""Web-assessment (ZAP) job creation, approval gating, scope, and ingestion."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from app.models.enums import UserRole
from app.models.scan_job import ScanJob
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import UserFactory, auth_headers, probe_cert_headers, start_job_attempt
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

NMAP_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
    b'<address addr="10.20.0.5" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'
    b"</ports></host></nmaprun>"
)

ZAP_REPORT = (
    b'{"@version":"2.14.0","site":[{"@name":"http://10.20.0.5","@host":"10.20.0.5",'
    b'"@port":"443","alerts":[{"pluginid":"40012","name":"Cross Site Scripting (Reflected)",'
    b'"riskcode":"3","desc":"<p>XSS</p>","cweid":"79","instances":[{"uri":"http://10.20.0.5/q",'
    b'"method":"GET","param":"x","evidence":"<script>"}]}]}]}'
)


async def _web_body(profile: str) -> dict[str, object]:
    return {
        "targets": ["10.20.0.0/24"],
        "web_scan": {"profile": profile, "start_urls": ["http://10.20.0.5/"]},
    }


async def test_standard_scan_adds_automatic_passive_zap_stage(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], "targets": ["10.20.0.0/24"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    job = await db_session.get(ScanJob, uuid.UUID(resp.json()["id"]))
    assert job is not None
    web = [s for s in job.workflow_json if s.get("plugin") == "zap"]
    assert len(web) == 1
    assert web[0]["config"] == {
        "profile": "passive_baseline",
        "auto_discover": True,
        "max_duration_minutes": 10,
        "requests_per_second": 10,
    }


async def test_passive_web_scan_adds_zap_stage(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("passive_baseline")},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    job = await db_session.get(ScanJob, uuid.UUID(resp.json()["id"]))
    assert job is not None
    web = [s for s in job.workflow_json if s.get("plugin") == "zap"]
    assert len(web) == 1
    assert web[0]["config"]["profile"] == "passive_baseline"
    assert web[0]["config"]["start_urls"] == ["http://10.20.0.5/"]


async def test_operator_can_request_passive_but_not_active(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    operator = await make_user(UserRole.SECURITY_OPERATOR)
    op_headers = auth_headers(operator)

    passive = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("passive_baseline")},
        headers=op_headers,
    )
    assert passive.status_code == 201, passive.text

    active = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("limited_active")},
        headers=op_headers,
    )
    assert active.status_code == 403  # active requires approval


async def test_approver_can_request_active(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    approver = await make_user(UserRole.PENTEST_APPROVER)

    disabled = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("limited_active")},
        headers=auth_headers(approver),
    )
    assert disabled.status_code == 409

    toggle = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/pentest",
        json={"enabled": True},
        headers=admin_headers,
    )
    assert toggle.status_code == 200, toggle.text
    resp = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("limited_active")},
        headers=auth_headers(approver),
    )
    assert resp.status_code == 201, resp.text


async def test_web_scan_rejects_out_of_scope_url(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    resp = await client.post(
        "/api/v1/jobs",
        json={
            "probe_id": probe["probe_id"],
            "targets": ["10.20.0.0/24"],
            "web_scan": {"profile": "passive_baseline", "start_urls": ["http://10.99.0.5/"]},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422


async def test_zap_upload_creates_web_finding(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job = await client.post(
        "/api/v1/jobs",
        json={"probe_id": probe["probe_id"], **await _web_body("passive_baseline")},
        headers=admin_headers,
    )
    job_id = job.json()["id"]
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == job_id
    headers = {**probe_cert_headers(probe["fingerprint"]), **attempt_headers}
    # Discovery first so the web finding maps to the asset/service.
    await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?stage=discovery&scanner=nmap",
        content=NMAP_XML,
        headers={**headers, "Content-Type": "application/xml"},
    )
    up = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/results?stage=web&scanner=zap",
        content=ZAP_REPORT,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert up.status_code == 201, up.text
    assert up.json()["findings_created"] >= 1

    findings = await client.get(
        "/api/v1/findings?finding_type=web_application_issue", headers=admin_headers
    )
    titles = [f["title"] for f in findings.json()["items"]]
    assert "Cross Site Scripting (Reflected)" in titles
