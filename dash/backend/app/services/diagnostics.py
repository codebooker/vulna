"""Vulna Doctor diagnostics (Phase 26).

Aggregates the health of every major component into one place so an operator can
tell *which* part is failing without reading logs across containers. Every result
names the affected component, its impact, the data-safety status, and a next step
linked to documentation. Read-only: this never mutates state.
"""

from __future__ import annotations

import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import JobStatus, ProbeStatus, ReportStatus
from app.models.probe import Probe
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.services.health import component_health

OK = "ok"
WARN = "warn"
FAIL = "fail"

# Data-safety status for a check.
SAFE = "safe"  # data is not at risk
AT_RISK = "at_risk"  # data could be lost/inconsistent if unaddressed
DATA_NA = "not_applicable"

CERT_EXPIRING_DAYS = 14


@dataclass
class DiagnosticResult:
    component: str
    status: str
    summary: str
    impact: str
    data_safety: str
    next_step: str
    doc: str


def _ok(component: str, summary: str, doc: str = "") -> DiagnosticResult:
    return DiagnosticResult(component, OK, summary, "", SAFE, "", doc)


def _aware(dt: datetime) -> datetime:
    """Treat a naive datetime (as SQLite returns) as UTC so it can be compared."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


async def run_diagnostics(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID, now: datetime | None = None
) -> list[DiagnosticResult]:
    now = now or datetime.now(UTC)
    results: list[DiagnosticResult] = []

    health = await component_health(session, settings, now)

    # Application + database.
    results.append(_ok("application", "running"))
    if health.database == OK:
        results.append(_ok("database", "reachable"))
    else:
        results.append(
            DiagnosticResult(
                "database", FAIL, "database not reachable",
                "the app cannot read or write data", AT_RISK,
                "check the database container and DATABASE_URL; see docs/deployment.md",
                "docs/deployment.md",
            )
        )

    # Local Scout.
    results.append(_local_scout_result(health.local_scout))

    # Remote Scouts: enrolled probes with a stale heartbeat.
    results.append(await _remote_scouts_result(session, settings, org_id, now))

    # Scanner capabilities.
    if health.scanner_capabilities in (OK,):
        results.append(_ok("scanner_capabilities", "standard pack present", "docs/updates.md"))
    else:
        results.append(
            DiagnosticResult(
                "scanner_capabilities", WARN,
                f"scanner capabilities: {health.scanner_capabilities}",
                "some scan stages will be skipped", SAFE,
                "install the standard scanner pack (nmap, nuclei, testssl.sh, OWASP ZAP)",
                "docs/updates.md",
            )
        )

    # Feed freshness.
    results.append(await _feeds_result(session, health.feeds))

    # Certificate expiry (internal CA + probe certs).
    results.append(_ca_cert_result(settings, now))
    results.append(await _probe_cert_result(session, org_id, now))

    # Storage use.
    results.append(_storage_result(settings))

    # Failed jobs / reports.
    results.append(await _failed_jobs_result(session, org_id))
    results.append(await _failed_reports_result(session, org_id))

    # Update + backup posture (informational reminders — the CLI performs them).
    results.append(
        DiagnosticResult(
            "updates", OK, f"version {settings.version} on {settings.update_channel}",
            "", SAFE, "check for updates with `vulna update check`", "docs/updates.md",
        )
    )
    results.append(
        DiagnosticResult(
            "backups", WARN, "verify a recent off-host backup exists",
            "without a verified backup, recovery is not guaranteed", AT_RISK,
            "create and verify an encrypted backup with `vulna backup`", "docs/backups.md",
        )
    )
    return results


def summarize(results: list[DiagnosticResult]) -> dict[str, int]:
    counts = {OK: 0, WARN: 0, FAIL: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def as_dicts(results: list[DiagnosticResult]) -> list[dict[str, str]]:
    return [asdict(r) for r in results]


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #


def _local_scout_result(status: str) -> DiagnosticResult:
    if status in ("connected", "disabled"):
        return _ok("local_scout", status, "deploy/single-host/README.md")
    return DiagnosticResult(
        "local_scout", WARN, f"local Scout: {status}",
        "local assessments cannot run until the Scout connects", SAFE,
        "check the local-scout container; run `vulnascout doctor` on it",
        "docs/networking.md",
    )


async def _remote_scouts_result(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID, now: datetime
) -> DiagnosticResult:
    probes = (
        await session.execute(
            select(Probe).where(
                Probe.organization_id == org_id,
                Probe.status == ProbeStatus.ENROLLED,
                Probe.name != settings.local_scout_name,
            )
        )
    ).scalars().all()
    offline = [
        p
        for p in probes
        if p.last_seen_at is None
        or (now - _aware(p.last_seen_at)).total_seconds() > settings.probe_offline_after_seconds
    ]
    if not probes:
        return _ok("remote_scouts", "no remote Scouts enrolled", "docs/deployment.md")
    if offline:
        return DiagnosticResult(
            "remote_scouts", WARN, f"{len(offline)} of {len(probes)} remote Scout(s) offline",
            "those sites are not being assessed", SAFE,
            "on the offline Scout run `vulnascout doctor` to diagnose connectivity",
            "docs/deployment.md",
        )
    return _ok("remote_scouts", f"{len(probes)} remote Scout(s) connected", "docs/deployment.md")


async def _feeds_result(session: AsyncSession, feeds_status: str) -> DiagnosticResult:
    if feeds_status in (OK, "no_feeds"):
        return _ok("feeds", feeds_status, "docs/deployment.md")
    return DiagnosticResult(
        "feeds", WARN, f"intelligence feeds: {feeds_status}",
        "CVE enrichment (KEV/EPSS) may be out of date", SAFE,
        "retry the feed sync (Feeds panel) or check outbound connectivity",
        "docs/networking.md",
    )


def _ca_cert_result(settings: Settings, now: datetime) -> DiagnosticResult:
    path = Path(settings.ca_cert_path)
    if not path.exists():
        return DiagnosticResult(
            "certificate_ca", WARN, "internal CA not initialized",
            "Scouts cannot enroll until the CA exists", SAFE,
            "the CA is created on first enrollment/bootstrap", "deploy/single-host/README.md",
        )
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        days = int((cert.not_valid_after_utc - now).total_seconds() // 86400)
    except Exception:  # noqa: BLE001 - defensive
        return DiagnosticResult(
            "certificate_ca", WARN, "could not read the CA certificate", "", SAFE,
            "inspect the CA at " + settings.ca_cert_path, "docs/networking.md",
        )
    if days < 0:
        return DiagnosticResult(
            "certificate_ca", FAIL, "internal CA certificate expired",
            "Scout mutual TLS fails; enrollments and heartbeats break", AT_RISK,
            "rotate the internal CA and re-enroll Scouts", "docs/networking.md",
        )
    if days < CERT_EXPIRING_DAYS:
        return DiagnosticResult(
            "certificate_ca", WARN, f"internal CA expires in {days} day(s)",
            "Scout mutual TLS will break when it expires", SAFE,
            "plan a CA rotation before expiry", "docs/networking.md",
        )
    return _ok("certificate_ca", f"valid for {days} more day(s)", "docs/networking.md")


async def _probe_cert_result(
    session: AsyncSession, org_id: uuid.UUID, now: datetime
) -> DiagnosticResult:
    probes = (
        await session.execute(
            select(Probe).where(
                Probe.organization_id == org_id,
                Probe.status == ProbeStatus.ENROLLED,
                Probe.certificate_expires_at.is_not(None),
            )
        )
    ).scalars().all()
    soon = 0
    expired = 0
    for p in probes:
        if p.certificate_expires_at is None:
            continue
        days = (_aware(p.certificate_expires_at) - now).total_seconds() / 86400
        if days < 0:
            expired += 1
        elif days < CERT_EXPIRING_DAYS:
            soon += 1
    if expired:
        return DiagnosticResult(
            "certificate_scouts", FAIL, f"{expired} Scout certificate(s) expired",
            "those Scouts can no longer authenticate", SAFE,
            "re-enroll the affected Scouts (`vulnascout reset` then enroll)",
            "docs/deployment.md",
        )
    if soon:
        return DiagnosticResult(
            "certificate_scouts", WARN, f"{soon} Scout certificate(s) expiring soon",
            "those Scouts will stop authenticating when they expire", SAFE,
            "renew by re-enrolling before expiry", "docs/deployment.md",
        )
    return _ok("certificate_scouts", "no expiring Scout certificates", "docs/deployment.md")


def _storage_result(settings: Settings) -> DiagnosticResult:
    path = settings.reports_dir
    probe = path if Path(path).exists() else "/"
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return _ok("storage", "not checked")
    free_pct = 100.0 * usage.free / usage.total if usage.total else 100.0
    if free_pct < 5:
        return DiagnosticResult(
            "storage", FAIL, f"only {free_pct:.0f}% disk free",
            "reports, evidence, and the database may fail to write", AT_RISK,
            "free disk space or move the data volume", "docs/deployment.md",
        )
    if free_pct < 15:
        return DiagnosticResult(
            "storage", WARN, f"{free_pct:.0f}% disk free",
            "low free space; watch report/evidence growth", SAFE,
            "prune old backups/reports or add storage", "docs/backups.md",
        )
    return _ok("storage", f"{free_pct:.0f}% disk free")


async def _failed_jobs_result(session: AsyncSession, org_id: uuid.UUID) -> DiagnosticResult:
    n = await session.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.organization_id == org_id, ScanJob.status == JobStatus.FAILED)
    )
    if n:
        return DiagnosticResult(
            "scan_jobs", WARN, f"{n} failed scan job(s)",
            "some assessments did not complete", SAFE,
            "review the failed jobs and their errors, then re-run", "docs/deployment.md",
        )
    return _ok("scan_jobs", "no failed scan jobs")


async def _failed_reports_result(session: AsyncSession, org_id: uuid.UUID) -> DiagnosticResult:
    n = await session.scalar(
        select(func.count())
        .select_from(Report)
        .where(Report.organization_id == org_id, Report.status == ReportStatus.FAILED)
    )
    if n:
        return DiagnosticResult(
            "reports", WARN, f"{n} failed report(s)",
            "some reports could not be generated", SAFE,
            "re-generate the failed reports", "docs/deployment.md",
        )
    return _ok("reports", "no failed reports")


# Threshold reused by callers/tests.
def offline_cutoff(now: datetime, settings: Settings) -> datetime:
    return now - timedelta(seconds=settings.probe_offline_after_seconds)
