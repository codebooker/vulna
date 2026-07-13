"""End-to-end tests for report generation, download, reproducibility, and authz."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

from app.auth.password import hash_password
from app.models.asset import Asset, AssetIdentifier
from app.models.change_event import ChangeEvent
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.enums import (
    AssetType,
    ChangeEventType,
    FindingStatus,
    FindingType,
    IdentifierType,
    JobMode,
    JobStatus,
    ProbeStatus,
    ServiceState,
    ServiceTransport,
    Severity,
    UserRole,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.models.site import Site
from app.models.user import User
from app.services import asset_context
from app.services.reports.exporters import FINDINGS_COLUMNS
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, auth_headers


async def _seed_scan(session: AsyncSession, org: Organization) -> ScanJob:
    now = datetime.now(UTC)
    site = Site(organization_id=org.id, name="HQ", code="HQ")
    session.add(site)
    await session.flush()
    probe = Probe(
        organization_id=org.id,
        site_id=site.id,
        name="probe-a",
        status=ProbeStatus.ENROLLED,
        certificate_fingerprint=uuid.uuid4().hex,
    )
    session.add(probe)
    await session.flush()
    scan = ScanJob(
        organization_id=org.id,
        site_id=site.id,
        probe_id=probe.id,
        mode=JobMode.VULNERABILITY_ASSESSMENT,
        status=JobStatus.COMPLETED,
        requested_targets_json=["10.0.0.0/24"],
        workflow_json=[{"stage": "discovery", "plugin": "nmap"}],
        job_signature="sig",
        not_before=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        started_at=now - timedelta(minutes=30),
        finished_at=now,
    )
    session.add(scan)
    asset = Asset(
        organization_id=org.id,
        site_id=site.id,
        canonical_name="web01",
        asset_type=AssetType.SERVER,
        operating_system="Linux",
    )
    session.add(asset)
    await session.flush()
    session.add(
        AssetIdentifier(
            asset_id=asset.id,
            identifier_type=IdentifierType.IP_ADDRESS,
            identifier_value="10.0.0.5",
        )
    )
    session.add(
        Service(
            asset_id=asset.id,
            transport=ServiceTransport.TCP,
            port=443,
            state=ServiceState.OPEN,
            service_name="https",
            product="nginx",
            version="1.18.0",
        )
    )
    session.add(
        Finding(
            organization_id=org.id,
            site_id=site.id,
            asset_id=asset.id,
            scan_job_id=scan.id,
            scanner_name="nuclei",
            canonical_finding_key="k1",
            finding_type=FindingType.VULNERABILITY,
            title="Log4Shell RCE",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            cve_ids_json=["CVE-2021-44228"],
            known_exploited=True,
            epss_score=0.975,
            status=FindingStatus.NEW,
        )
    )
    session.add(CveRecord(cve_id="CVE-2021-44228", description="Log4Shell"))
    session.add(ThreatIntelEnrichment(cve_id="CVE-2021-44228", is_kev=True, epss_score=0.975))
    session.add(
        ChangeEvent(
            organization_id=org.id,
            site_id=site.id,
            asset_id=asset.id,
            scan_job_id=scan.id,
            event_type=ChangeEventType.NEW_FINDING,
            severity="critical",
            summary="New critical finding",
        )
    )
    await session.commit()
    return scan


async def test_generate_all_formats_and_download(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)

    resp = await client.post(
        "/api/v1/reports", json={"scan_job_id": str(scan.id)}, headers=admin_headers
    )
    assert resp.status_code == 201
    reports = resp.json()
    assert len(reports) == 9  # all report types
    types = {r["report_type"] for r in reports}
    assert {"executive_pdf", "pentest_pdf", "full_spectrum_pdf", "json_bundle"} <= types
    for r in reports:
        assert r["status"] == "completed"
        assert r["sha256"] and r["size_bytes"] > 0

    by_type = {r["report_type"]: r for r in reports}

    pdf = await client.get(
        f"/api/v1/reports/{by_type['executive_pdf']['id']}/download", headers=admin_headers
    )
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"

    jb = await client.get(
        f"/api/v1/reports/{by_type['json_bundle']['id']}/download", headers=admin_headers
    )
    assert jb.status_code == 200
    bundle = json.loads(jb.content)
    assert bundle["snapshot"]["findings"][0]["cve_ids"] == ["CVE-2021-44228"]


async def test_expired_report_is_not_downloadable(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)
    resp = await client.post(
        "/api/v1/reports", json={"scan_job_id": str(scan.id)}, headers=admin_headers
    )
    assert resp.status_code == 201
    report_id = resp.json()[0]["id"]

    # Downloadable now ...
    ok = await client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)
    assert ok.status_code == 200

    # ... but not once expired, even though the file still exists on disk.
    report = await db_session.get(Report, uuid.UUID(report_id))
    report.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    gone = await client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)
    assert gone.status_code == 410


async def test_findings_csv_columns_via_api(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)
    resp = await client.post(
        "/api/v1/reports",
        json={"scan_job_id": str(scan.id), "report_types": ["findings_csv"]},
        headers=admin_headers,
    )
    report_id = resp.json()[0]["id"]
    dl = await client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("text/csv")
    header = next(csv.reader(io.StringIO(dl.content.decode("utf-8"))))
    assert header == FINDINGS_COLUMNS


async def test_report_is_reproducible_after_data_change(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)
    resp = await client.post(
        "/api/v1/reports",
        json={"scan_job_id": str(scan.id), "report_types": ["json_bundle"]},
        headers=admin_headers,
    )
    report_id = resp.json()[0]["id"]
    first = await client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)

    # Mutate a finding after the report was generated.
    finding = (await db_session.execute(select(Finding))).scalars().first()
    assert finding is not None
    finding.severity = Severity.LOW
    finding.title = "changed"
    await db_session.commit()

    second = await client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)
    assert first.content == second.content  # stored snapshot is unchanged


async def test_download_is_organization_scoped(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)
    resp = await client.post(
        "/api/v1/reports",
        json={"scan_job_id": str(scan.id), "report_types": ["assets_csv"]},
        headers=admin_headers,
    )
    report_id = resp.json()[0]["id"]

    # A user in a different organization cannot download it.
    other_org = Organization(name="Other", slug="other", default_timezone="UTC")
    db_session.add(other_org)
    await db_session.flush()
    other_user = User(
        organization_id=other_org.id,
        email="intruder@example.com",
        hashed_password=hash_password(TEST_PASSWORD),
        full_name="Intruder",
        role=UserRole.ADMINISTRATOR,
    )
    db_session.add(other_user)
    await db_session.commit()

    forbidden = await client.get(
        f"/api/v1/reports/{report_id}/download", headers=auth_headers(other_user)
    )
    assert forbidden.status_code == 404

    # Unauthenticated download is rejected.
    anon = await client.get(f"/api/v1/reports/{report_id}/download")
    assert anon.status_code == 401


async def test_generate_for_unknown_scan_is_404(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    resp = await client.post(
        "/api/v1/reports", json={"scan_job_id": str(uuid.uuid4())}, headers=admin_headers
    )
    assert resp.status_code == 404


async def test_report_filters_by_normalized_asset_tag(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
) -> None:
    scan = await _seed_scan(db_session, organization)
    primary = await db_session.scalar(select(Asset).where(Asset.canonical_name == "web01"))
    assert primary is not None
    tag = await asset_context.ensure_tag(db_session, organization.id, "Production")
    await asset_context.assign_tag(db_session, primary, tag)
    other = Asset(
        organization_id=organization.id,
        site_id=scan.site_id,
        canonical_name="dev01",
        asset_type=AssetType.SERVER,
    )
    db_session.add(other)
    await db_session.flush()
    db_session.add(
        Finding(
            organization_id=organization.id,
            site_id=scan.site_id,
            asset_id=other.id,
            scan_job_id=scan.id,
            scanner_name="nuclei",
            canonical_finding_key="dev-finding",
            finding_type=FindingType.VULNERABILITY,
            title="Development finding",
            severity=Severity.LOW,
        )
    )
    await db_session.commit()

    response = await client.post(
        "/api/v1/reports",
        json={
            "scan_job_id": str(scan.id),
            "report_types": ["json_bundle"],
            "asset_tag_ids": [str(tag.id)],
        },
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    report = response.json()[0]
    assert report["parameters_json"]["asset_filter_ids"] == [str(primary.id)]
    download = await client.get(f"/api/v1/reports/{report['id']}/download", headers=admin_headers)
    snapshot = json.loads(download.content)["snapshot"]
    assert snapshot["summary"]["asset_count"] == 1
    assert [asset["canonical_name"] for asset in snapshot["assets"]] == ["web01"]
    assert [finding["title"] for finding in snapshot["findings"]] == ["Log4Shell RCE"]
    assert snapshot["assets"][0]["tags"] == ["Production"]

    invalid = await client.post(
        "/api/v1/reports",
        json={
            "scan_job_id": str(scan.id),
            "report_types": ["json_bundle"],
            "asset_tag_ids": [str(uuid.uuid4())],
        },
        headers=admin_headers,
    )
    assert invalid.status_code == 422
