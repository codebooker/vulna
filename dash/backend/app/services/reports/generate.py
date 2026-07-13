"""Report generation orchestration.

Builds a snapshot once, renders each requested artifact, writes it to the
reports directory with a SHA-256, and records a ``Report`` row. The stored file
is the reproducible artifact — re-downloading returns the same bytes regardless
of later database changes.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import ReportFormat, ReportStatus, ReportType
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.services.reports import exporters, pdf
from app.services.reports.snapshot import build_snapshot


@dataclass(frozen=True)
class _Spec:
    format: ReportFormat
    ext: str
    render: Callable[[dict[str, Any]], bytes]
    template_version: str


ARTIFACTS: dict[ReportType, _Spec] = {
    ReportType.EXECUTIVE_PDF: _Spec(
        ReportFormat.PDF, "pdf", pdf.executive_pdf, pdf.TEMPLATE_VERSION
    ),
    ReportType.TECHNICAL_PDF: _Spec(
        ReportFormat.PDF, "pdf", pdf.technical_pdf, pdf.TEMPLATE_VERSION
    ),
    ReportType.PENTEST_PDF: _Spec(
        ReportFormat.PDF, "pdf", pdf.pentest_pdf, pdf.TEMPLATE_VERSION
    ),
    ReportType.FULL_SPECTRUM_PDF: _Spec(
        ReportFormat.PDF, "pdf", pdf.full_spectrum_pdf, pdf.TEMPLATE_VERSION
    ),
    ReportType.FINDINGS_CSV: _Spec(ReportFormat.CSV, "csv", exporters.findings_csv, "1"),
    ReportType.ASSETS_CSV: _Spec(ReportFormat.CSV, "csv", exporters.assets_csv, "1"),
    ReportType.SERVICES_CSV: _Spec(ReportFormat.CSV, "csv", exporters.services_csv, "1"),
    ReportType.CVE_EXPOSURE_CSV: _Spec(
        ReportFormat.CSV, "csv", exporters.cve_exposure_csv, "1"
    ),
    ReportType.JSON_BUNDLE: _Spec(
        ReportFormat.JSON, "json", exporters.json_bundle, str(exporters.BUNDLE_VERSION)
    ),
}


async def generate_reports(
    session: AsyncSession,
    *,
    scan_job: ScanJob,
    report_types: list[ReportType],
    requested_by: uuid.UUID | None,
    settings: Settings,
    now: datetime,
    report_ids: dict[ReportType, uuid.UUID] | None = None,
) -> list[Report]:
    """Render and store the requested report artifacts for a scan job."""
    snapshot = await build_snapshot(session, scan_job=scan_job, now=now)
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    expires_at = now + timedelta(days=settings.report_ttl_days)

    created: list[Report] = []
    for report_type in report_types:
        spec = ARTIFACTS[report_type]
        report_id = (report_ids or {}).get(report_type, uuid.uuid4())
        existing = await session.get(Report, report_id)
        if existing is not None:
            created.append(existing)
            continue
        report = Report(
            id=report_id,
            organization_id=scan_job.organization_id,
            site_id=scan_job.site_id,
            scan_job_id=scan_job.id,
            report_type=report_type,
            format=spec.format,
            template_version=spec.template_version,
            generated_by=requested_by,
            generated_at=now,
            expires_at=expires_at,
            parameters_json={
                "snapshot_version": snapshot.get("schema_version"),
                "snapshot_generated_at": snapshot.get("generated_at"),
                "finding_count": snapshot.get("summary", {}).get("finding_count", 0),
            },
        )
        try:
            data = spec.render(snapshot)
        except Exception as exc:  # defensive: one bad artifact must not abort the rest
            report.status = ReportStatus.FAILED
            report.error = str(exc)[:1024]
            session.add(report)
            created.append(report)
            continue

        path = reports_dir / f"{report.id}.{spec.ext}"
        path.write_bytes(data)
        report.storage_path = str(path)
        report.sha256 = hashlib.sha256(data).hexdigest()
        report.size_bytes = len(data)
        report.status = ReportStatus.COMPLETED
        session.add(report)
        created.append(report)

    await session.flush()
    return created
