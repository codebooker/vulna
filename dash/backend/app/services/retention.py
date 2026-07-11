"""Retention preview, safe cleanup, and storage budgets (Phase 28).

Cleanup deletes *old, unreferenced* data — raw scanner output and stale report
artifacts — to keep a self-hosted deployment from filling its disk. It is
deliberately conservative and **fails closed**: an object is deleted only when it
is past its retention window *and* nothing still depends on it. The same planner
drives the preview and the execution, so the preview's manifest is exactly what a
cleanup will delete.

An object is protected (never deleted) when it is:

* still within its retention window,
* produced by a job that is still active (not in a terminal state),
* backing an **active finding** (a finding that is not resolved),
* referenced by a **retained report** snapshot, or
* under a **legal hold**.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingStatus, JobStatus, ReportStatus
from app.models.finding import Finding
from app.models.report import Report
from app.models.retention_hold import HOLD_REPORT, HOLD_SCAN_JOB, RetentionHold
from app.models.scan_artifact import ScanArtifact
from app.models.scan_job import ScanJob

DEFAULT_RAW_OUTPUT_DAYS = 90
DEFAULT_REPORT_DAYS = 365
MIN_RETENTION_DAYS = 7  # a floor so a policy can never aggressively purge fresh data

# A job is "active" (its data must be preserved) until it reaches a terminal state.
_TERMINAL_JOB_STATES = {
    JobStatus.COMPLETED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
    JobStatus.EXPIRED,
    JobStatus.REJECTED_BY_PROBE,
}
# A report is safe to consider for deletion only once it is in a terminal state.
_TERMINAL_REPORT_STATES = {ReportStatus.COMPLETED, ReportStatus.FAILED}


class RetentionError(ValueError):
    """Raised when a retention policy is invalid."""


@dataclass
class RetentionPolicy:
    raw_output_days: int = DEFAULT_RAW_OUTPUT_DAYS
    report_days: int = DEFAULT_REPORT_DAYS

    @classmethod
    def from_request(
        cls, raw_output_days: int | None, report_days: int | None
    ) -> RetentionPolicy:
        pol = cls(
            raw_output_days=(
                raw_output_days if raw_output_days is not None else DEFAULT_RAW_OUTPUT_DAYS
            ),
            report_days=report_days if report_days is not None else DEFAULT_REPORT_DAYS,
        )
        for name, value in (
            ("raw_output_days", pol.raw_output_days),
            ("report_days", pol.report_days),
        ):
            if value < MIN_RETENTION_DAYS:
                raise RetentionError(f"{name} must be at least {MIN_RETENTION_DAYS} days")
        return pol


@dataclass
class CleanupItem:
    kind: str  # "raw_output" | "report"
    id: str
    size_bytes: int
    created_at: str
    reason: str


@dataclass
class ProtectedItem:
    kind: str
    id: str
    reason: str


@dataclass
class CleanupPlan:
    policy: dict[str, int]
    eligible: list[CleanupItem] = field(default_factory=list)
    protected: list[ProtectedItem] = field(default_factory=list)
    reclaimable_bytes: int = 0
    generated_at: str = ""

    def manifest(self) -> dict[str, object]:
        """An auditable record of exactly what a cleanup would (or did) delete."""
        return {
            "policy": self.policy,
            "generated_at": self.generated_at,
            "reclaimable_bytes": self.reclaimable_bytes,
            "eligible": [asdict(i) for i in self.eligible],
            "protected": [asdict(i) for i in self.protected],
        }


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


async def build_cleanup_plan(
    session: AsyncSession,
    org_id: uuid.UUID,
    policy: RetentionPolicy,
    now: datetime | None = None,
) -> CleanupPlan:
    """Compute the fail-closed cleanup plan for an organization.

    Reads only; the same plan is used for both preview and execution.
    """
    now = now or datetime.now(UTC)
    raw_cutoff = now - timedelta(days=policy.raw_output_days)
    report_cutoff = now - timedelta(days=policy.report_days)

    # Reference sets (what must be preserved).
    held_jobs, held_reports = await _held_targets(session, org_id)
    active_jobs = await _active_job_ids(session, org_id)
    jobs_with_active_findings = await _jobs_with_active_findings(session, org_id)
    retained_report_jobs = await _retained_report_job_ids(
        session, org_id, report_cutoff, held_reports
    )

    plan = CleanupPlan(
        policy={"raw_output_days": policy.raw_output_days, "report_days": policy.report_days},
        generated_at=now.isoformat(),
    )

    # --- Raw scanner output (ScanArtifact) ---------------------------------- #
    artifacts = (
        await session.execute(
            select(
                ScanArtifact.id, ScanArtifact.scan_job_id, ScanArtifact.size_bytes,
                ScanArtifact.created_at,
            )
            .join(ScanJob, ScanJob.id == ScanArtifact.scan_job_id)
            .where(ScanJob.organization_id == org_id, ScanArtifact.created_at < raw_cutoff)
        )
    ).all()
    for art_id, job_id, size, created in artifacts:
        reason = _artifact_protection(
            job_id, active_jobs, held_jobs, jobs_with_active_findings, retained_report_jobs
        )
        if reason is None:
            plan.eligible.append(
                CleanupItem(
                    "raw_output", str(art_id), int(size or 0), _aware(created).isoformat(),
                    f"raw output older than {policy.raw_output_days} days from a completed job",
                )
            )
        else:
            plan.protected.append(ProtectedItem("raw_output", str(art_id), reason))

    # --- Report artifacts --------------------------------------------------- #
    reports = (
        await session.execute(
            select(Report.id, Report.size_bytes, Report.created_at, Report.status)
            .where(Report.organization_id == org_id, Report.created_at < report_cutoff)
        )
    ).all()
    for rep_id, size, created, status in reports:
        if status not in _TERMINAL_REPORT_STATES:
            plan.protected.append(
                ProtectedItem("report", str(rep_id), "report is still being generated")
            )
        elif rep_id in held_reports:
            plan.protected.append(ProtectedItem("report", str(rep_id), "under a legal hold"))
        else:
            plan.eligible.append(
                CleanupItem(
                    "report", str(rep_id), int(size or 0), _aware(created).isoformat(),
                    f"report older than {policy.report_days} days",
                )
            )

    plan.reclaimable_bytes = sum(i.size_bytes for i in plan.eligible)
    return plan


def _artifact_protection(
    job_id: uuid.UUID,
    active_jobs: set[uuid.UUID],
    held_jobs: set[uuid.UUID],
    jobs_with_active_findings: set[uuid.UUID],
    retained_report_jobs: set[uuid.UUID],
) -> str | None:
    """Return why an artifact's job is protected, or None if it is eligible."""
    if job_id in active_jobs:
        return "the scan job is still active"
    if job_id in held_jobs:
        return "under a legal hold"
    if job_id in jobs_with_active_findings:
        return "backs an active (unresolved) finding"
    if job_id in retained_report_jobs:
        return "referenced by a retained report snapshot"
    return None


async def _held_targets(
    session: AsyncSession, org_id: uuid.UUID
) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
    rows = (
        await session.execute(
            select(RetentionHold.target_type, RetentionHold.target_id).where(
                RetentionHold.organization_id == org_id
            )
        )
    ).all()
    jobs = {tid for ttype, tid in rows if ttype == HOLD_SCAN_JOB}
    reports = {tid for ttype, tid in rows if ttype == HOLD_REPORT}
    return jobs, reports


async def _active_job_ids(session: AsyncSession, org_id: uuid.UUID) -> set[uuid.UUID]:
    rows = (
        await session.execute(
            select(ScanJob.id).where(
                ScanJob.organization_id == org_id,
                ScanJob.status.not_in(_TERMINAL_JOB_STATES),
            )
        )
    ).scalars().all()
    return set(rows)


async def _jobs_with_active_findings(session: AsyncSession, org_id: uuid.UUID) -> set[uuid.UUID]:
    rows = (
        await session.execute(
            select(Finding.scan_job_id)
            .where(
                Finding.organization_id == org_id,
                Finding.scan_job_id.is_not(None),
                Finding.status != FindingStatus.RESOLVED,
            )
            .distinct()
        )
    ).scalars().all()
    return {r for r in rows if r is not None}


async def _retained_report_job_ids(
    session: AsyncSession, org_id: uuid.UUID, report_cutoff: datetime, held_reports: set[uuid.UUID]
) -> set[uuid.UUID]:
    """Job ids referenced by reports that will be retained (recent or held)."""
    rows = (
        await session.execute(
            select(Report.id, Report.scan_job_id, Report.created_at).where(
                Report.organization_id == org_id, Report.scan_job_id.is_not(None)
            )
        )
    ).all()
    retained: set[uuid.UUID] = set()
    for rep_id, job_id, created in rows:
        if job_id is None:
            continue
        if _aware(created) >= report_cutoff or rep_id in held_reports:
            retained.add(job_id)
    return retained


# --------------------------------------------------------------------------- #
# Storage budgets
# --------------------------------------------------------------------------- #


async def storage_breakdown(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, object]]:
    """Per-category storage sizes. No sensitive asset/finding data in any label."""
    raw_bytes = await session.scalar(
        select(func.coalesce(func.sum(ScanArtifact.size_bytes), 0))
        .join(ScanJob, ScanJob.id == ScanArtifact.scan_job_id)
        .where(ScanJob.organization_id == org_id)
    )
    report_bytes = await session.scalar(
        select(func.coalesce(func.sum(Report.size_bytes), 0)).where(
            Report.organization_id == org_id
        )
    )
    return [
        {"category": "raw_output", "bytes": int(raw_bytes or 0), "location": "database"},
        {"category": "reports", "bytes": int(report_bytes or 0), "location": "reports volume"},
        {
            "category": "evidence", "bytes": 0, "location": "reports volume",
            "note": "stored with reports",
        },
        {
            "category": "database", "bytes": 0, "location": "database",
            "note": "sized by the DB engine",
        },
        {
            "category": "scout_queues", "bytes": 0, "location": "on each Scout",
            "note": "see per-Scout resources",
        },
        {
            "category": "backups", "bytes": 0, "location": "off-host",
            "note": "managed by `vulna backup`",
        },
    ]
