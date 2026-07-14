"""A re-scan refreshes a finding's scanner-derived presentation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.enums import FindingType, JobMode, JobStatus, ProbeStatus, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.services.findings import ParsedFinding, ingest_findings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _job(session: AsyncSession, org: Organization) -> ScanJob:
    now = datetime.now(UTC)
    site = Site(organization_id=org.id, name="S", code="S")
    session.add(site)
    await session.flush()
    probe = Probe(
        organization_id=org.id,
        site_id=site.id,
        name="p",
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
        requested_targets_json=["10.0.0.0/24"],
        workflow_json=[{"stage": "tls", "plugin": "testssl"}],
        job_signature="sig",
        not_before=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
    )
    session.add(job)
    await session.flush()
    return job


def _pf(title: str, **kw: object) -> ParsedFinding:
    return ParsedFinding(
        scanner="testssl",
        weakness_key="SSLv3",
        finding_type=FindingType.WEAK_PROTOCOL,
        title=title,
        severity=Severity.HIGH,
        target_ip="10.0.0.5",
        port=443,
        **kw,  # type: ignore[arg-type]
    )


async def test_rescan_refreshes_title_remediation_and_cves(
    db_session: AsyncSession, organization: Organization
) -> None:
    job = await _job(db_session, organization)
    now = datetime.now(UTC)

    # First ingest: the old, bare finding.
    await ingest_findings(db_session, job=job, parsed=[_pf("SSLv3 is offered")], now=now)

    # Re-scan with the improved parser output for the same weakness.
    improved = _pf(
        "SSLv3 supported",
        remediation="Disable SSLv3; serve only TLS 1.2 and 1.3.",
        cve_ids=["CVE-2014-3566"],
        cwe_ids=["CWE-326"],
    )
    summary = await ingest_findings(db_session, job=job, parsed=[improved], now=now)
    assert summary.findings_updated == 1
    assert summary.findings_created == 0  # deduped onto the existing finding

    finding = await db_session.scalar(
        select(Finding).where(Finding.organization_id == organization.id)
    )
    assert finding is not None
    assert finding.title == "SSLv3 supported"
    assert finding.remediation == "Disable SSLv3; serve only TLS 1.2 and 1.3."
    assert finding.cve_ids_json == ["CVE-2014-3566"]
    assert finding.cwe_ids_json == ["CWE-326"]
