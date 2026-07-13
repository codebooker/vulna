"""Report generation orchestration.

Builds a snapshot once, renders each requested artifact, writes it to the
reports directory with a SHA-256, and records a ``Report`` row. The stored file
is the reproducible artifact — re-downloading returns the same bytes regardless
of later database changes.
"""

from __future__ import annotations

import copy
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
    ReportType.PENTEST_PDF: _Spec(ReportFormat.PDF, "pdf", pdf.pentest_pdf, pdf.TEMPLATE_VERSION),
    ReportType.FULL_SPECTRUM_PDF: _Spec(
        ReportFormat.PDF, "pdf", pdf.full_spectrum_pdf, pdf.TEMPLATE_VERSION
    ),
    ReportType.FINDINGS_CSV: _Spec(ReportFormat.CSV, "csv", exporters.findings_csv, "1"),
    ReportType.ASSETS_CSV: _Spec(ReportFormat.CSV, "csv", exporters.assets_csv, "1"),
    ReportType.SERVICES_CSV: _Spec(ReportFormat.CSV, "csv", exporters.services_csv, "1"),
    ReportType.CVE_EXPOSURE_CSV: _Spec(ReportFormat.CSV, "csv", exporters.cve_exposure_csv, "1"),
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
    asset_filter_ids: set[uuid.UUID] | None = None,
    template_options: dict[str, Any] | None = None,
    export_password: str | None = None,
) -> list[Report]:
    """Render and store the requested report artifacts for a scan job."""
    snapshot = await build_snapshot(
        session,
        scan_job=scan_job,
        now=now,
        asset_filter_ids=asset_filter_ids,
    )
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    expires_at = now + timedelta(days=settings.report_ttl_days)

    created: list[Report] = []
    for report_type in report_types:
        spec = ARTIFACTS[report_type]
        report_id = (report_ids or {}).get(report_type, uuid.uuid4())
        existing = await session.get(Report, report_id)
        if existing is not None and existing.status == ReportStatus.COMPLETED:
            created.append(existing)
            continue
        parameters = {
            "snapshot_version": snapshot.get("schema_version"),
            "snapshot_generated_at": snapshot.get("generated_at"),
            "finding_count": snapshot.get("summary", {}).get("finding_count", 0),
            "asset_filter_ids": (
                sorted(str(value) for value in asset_filter_ids)
                if asset_filter_ids is not None
                else None
            ),
            "report_template": template_options or None,
            "password_protected": bool(export_password and spec.format == ReportFormat.PDF),
        }
        report = existing or Report(
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
            parameters_json=parameters,
        )
        report.status = ReportStatus.GENERATING
        report.error = None
        report.generated_at = now
        report.expires_at = expires_at
        report.parameters_json = parameters
        try:
            render_snapshot = _apply_template_options(snapshot, template_options or {})
            if export_password and spec.format == ReportFormat.PDF:
                render_snapshot["_pdf_user_password"] = export_password
            data = spec.render(render_snapshot)
        except Exception as exc:  # defensive: one bad artifact must not abort the rest
            report.status = ReportStatus.FAILED
            error = str(exc)
            if export_password:
                error = error.replace(export_password, "[REDACTED]")
            report.error = error[:1024]
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


def _apply_template_options(snapshot: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Apply bounded presentation redaction without changing stored source data."""

    rendered = copy.deepcopy(snapshot)
    branding = options.get("branding") or {}
    display_name = str(branding.get("display_name") or "").strip()
    if display_name and rendered.get("organization"):
        rendered["organization"]["name"] = display_name[:255]
    redactions = set((options.get("redaction") or {}).get("fields") or [])
    sections = set(options.get("sections") or [])
    if sections:
        for section in (
            "assets",
            "services",
            "findings",
            "cve_exposure",
            "changes",
            "pentest_sessions",
        ):
            if section not in sections:
                rendered[section] = []
    for asset in rendered.get("assets", []):
        if "network_identifiers" in redactions:
            asset["ip_addresses"] = []
            asset["mac_addresses"] = []
            asset["hostnames"] = []
        if "asset_names" in redactions:
            asset["canonical_name"] = "Redacted asset"
        if "ownership" in redactions:
            asset["owner_user_id"] = None
            asset["department"] = None
    for service in rendered.get("services", []):
        if "network_identifiers" in redactions:
            service["ip_address"] = None
        if "asset_names" in redactions:
            service["asset_name"] = "Redacted asset"
    for finding in rendered.get("findings", []):
        if "asset_names" in redactions:
            finding["asset_name"] = "Redacted asset"
        if "remediation" in redactions:
            finding["remediation"] = None
    for exposure in rendered.get("cve_exposure", []):
        if "asset_names" in redactions:
            exposure["asset_name"] = "Redacted asset"
    rendered["report_template"] = {
        "name": options.get("name"),
        "version": options.get("version"),
        "sections": sorted(sections),
        "redaction": {"fields": sorted(redactions)},
        "branding": branding,
    }
    return rendered
