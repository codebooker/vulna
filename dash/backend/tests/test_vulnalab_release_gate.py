"""VulnaLab release gate: a known-vulnerable target MUST produce findings.

This is the end-to-end detection guarantee. It drives the real ingest pipeline
with genuine Nmap output captured from scanning the VulnaLab ``httpd:2.4.49``
target (deploy/lab) and asserts that discovery of that known-vulnerable Apache
turns into a persisted CVE finding. If the detection chain (parse -> service ->
CVE correlation -> finding) regresses, this release-blocking test fails.

Marked ``release_gate`` so a release cannot be promoted when it goes red.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.intelligence.nvd import CveData
from app.models.enums import JobMode, JobStatus, ProbeStatus, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.services.ingest import ingest_nmap_result
from app.services.intelligence import ingest_nvd
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.release_gate

# Real Nmap -sV output captured from scanning the lab's httpd:2.4.49 target.
# Note product="Apache httpd" but the CPE product is "http_server" — the finding
# must still correlate, which is the exact gap this gate guards.
APACHE_2449_NMAP_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
    b'<address addr="10.10.10.49" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="80"><state state="open"/>'
    b'<service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Unix)" '
    b'method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.49</cpe>'
    b"</service></port></ports></host></nmaprun>"
)

# CVE-2021-41773 — the path-traversal/RCE that affects Apache httpd 2.4.49.
APACHE_CVE = CveData(
    cve_id="CVE-2021-41773",
    description="Apache HTTP Server 2.4.49 path traversal and file disclosure/RCE.",
    cpe_matches=[
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
    ],
    cwe_ids=["CWE-22"],
    references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
    cvss_v3={"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
)

# Real Nmap output shape for the ftp-anon NSE script against an anonymous FTP
# service — the anonymous-FTP exposure a plain -sV scan misses (the motivating
# printer case).
ANON_FTP_NMAP_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
    b'<address addr="10.10.10.21" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="21"><state state="open"/>'
    b'<service name="ftp" product="vsftpd" version="2.3.4"/>'
    b'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>'
    b"</port></ports></host></nmaprun>"
)


async def _completed_job(session: AsyncSession, org: Organization) -> tuple[ScanJob, Probe]:
    now = datetime.now(UTC)
    site = Site(organization_id=org.id, name="Lab", code="LAB")
    session.add(site)
    await session.flush()
    probe = Probe(
        organization_id=org.id,
        site_id=site.id,
        name="lab-scout",
        status=ProbeStatus.ENROLLED,
        certificate_fingerprint=uuid.uuid4().hex,
    )
    session.add(probe)
    await session.flush()
    job = ScanJob(
        organization_id=org.id,
        site_id=site.id,
        probe_id=probe.id,
        mode=JobMode.VULNERABILITY_ASSESSMENT,
        status=JobStatus.COMPLETED,
        requested_targets_json=["10.10.10.0/24"],
        workflow_json=[{"stage": "discovery", "plugin": "nmap"}],
        job_signature="sig",
        not_before=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
    )
    session.add(job)
    await session.flush()
    return job, probe


async def test_known_vulnerable_apache_produces_a_finding(
    db_session: AsyncSession, organization: Organization
) -> None:
    # The CVE data the deployment would have synced from NVD.
    await ingest_nvd(db_session, [APACHE_CVE], now=datetime.now(UTC))
    job, probe = await _completed_job(db_session, organization)

    # Ingest the real discovery output, exactly as a probe upload would.
    summary = await ingest_nmap_result(
        db_session, job=job, xml_bytes=APACHE_2449_NMAP_XML, probe_id=probe.id
    )

    assert summary.services_upserted >= 1, "discovery must record the Apache service"
    assert summary.cve_findings_created >= 1, (
        "RELEASE BLOCKER: scanning a known-vulnerable Apache 2.4.49 produced no CVE "
        "finding — the detection pipeline is broken."
    )

    finding = await db_session.scalar(
        select(Finding).where(
            Finding.organization_id == organization.id,
            Finding.scanner_name == "cve-correlation",
        )
    )
    assert finding is not None
    assert "CVE-2021-41773" in finding.cve_ids_json
    assert finding.severity is Severity.HIGH  # CVSS 7.5
    assert finding.confidence >= 60  # version confirmed in the affected set


async def test_anonymous_ftp_exposure_produces_a_finding(
    db_session: AsyncSession, organization: Organization
) -> None:
    job, probe = await _completed_job(db_session, organization)

    summary = await ingest_nmap_result(
        db_session, job=job, xml_bytes=ANON_FTP_NMAP_XML, probe_id=probe.id
    )

    assert summary.nse_findings_created >= 1, (
        "RELEASE BLOCKER: an anonymous-FTP service on a discovered host produced no "
        "finding — the NSE detection path is broken."
    )
    finding = await db_session.scalar(
        select(Finding).where(
            Finding.organization_id == organization.id,
            Finding.scanner_name == "nmap-nse",
        )
    )
    assert finding is not None
    assert finding.title == "Anonymous FTP access allowed"
