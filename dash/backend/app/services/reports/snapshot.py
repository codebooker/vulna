"""Point-in-time snapshot of a scan's data for reporting.

The snapshot is a plain, JSON-serializable dict. It is the single source every
report format renders from (PDF, CSV, JSON bundle), which keeps the formats
consistent and makes a stored report reproducible even if the database changes
afterward.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.change_event import ChangeEvent
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.enums import IdentifierType, ServiceState, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.models.site import Site

SNAPSHOT_VERSION = 1


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _identifiers(asset: Asset, id_type: IdentifierType) -> list[str]:
    return [i.identifier_value for i in asset.identifiers if i.identifier_type == id_type]


async def build_snapshot(
    session: AsyncSession, *, scan_job: ScanJob, now: datetime
) -> dict[str, Any]:
    """Assemble a scan's reporting snapshot (org, site, assets, services,
    findings, CVE exposure, and changes)."""
    org = await session.get(Organization, scan_job.organization_id)
    site = await session.get(Site, scan_job.site_id)

    assets = list(
        (
            await session.execute(
                select(Asset)
                .where(Asset.site_id == scan_job.site_id)
                .order_by(Asset.canonical_name)
            )
        )
        .scalars()
        .all()
    )
    asset_ids = [a.id for a in assets]
    asset_by_id = {a.id: a for a in assets}

    services = (
        list(
            (await session.execute(select(Service).where(Service.asset_id.in_(asset_ids))))
            .scalars()
            .all()
        )
        if asset_ids
        else []
    )
    services_by_asset: dict[Any, list[Service]] = {}
    for svc in services:
        services_by_asset.setdefault(svc.asset_id, []).append(svc)

    findings = list(
        (
            await session.execute(
                select(Finding)
                .where(Finding.site_id == scan_job.site_id)
                .order_by(Finding.severity, Finding.title)
            )
        )
        .scalars()
        .all()
    )

    changes = list(
        (
            await session.execute(
                select(ChangeEvent)
                .where(ChangeEvent.scan_job_id == scan_job.id)
                .order_by(ChangeEvent.created_at.desc())
            )
        )
        .scalars()
        .all()
    )

    # CVE records + enrichment for every CVE referenced by a finding.
    cve_ids: set[str] = set()
    for f in findings:
        cve_ids.update(f.cve_ids_json or [])
    cve_map: dict[str, CveRecord] = {}
    enr_map: dict[str, ThreatIntelEnrichment] = {}
    if cve_ids:
        cve_map = {
            r.cve_id: r
            for r in (
                await session.execute(select(CveRecord).where(CveRecord.cve_id.in_(cve_ids)))
            )
            .scalars()
            .all()
        }
        enr_map = {
            e.cve_id: e
            for e in (
                await session.execute(
                    select(ThreatIntelEnrichment).where(ThreatIntelEnrichment.cve_id.in_(cve_ids))
                )
            )
            .scalars()
            .all()
        }

    def _primary_ip(asset: Asset) -> str | None:
        ips = _identifiers(asset, IdentifierType.IP_ADDRESS)
        return ips[0] if ips else None

    # Per-asset finding counts.
    crit_by_asset: dict[Any, int] = {}
    high_by_asset: dict[Any, int] = {}
    for f in findings:
        if f.asset_id is None:
            continue
        if f.severity == Severity.CRITICAL:
            crit_by_asset[f.asset_id] = crit_by_asset.get(f.asset_id, 0) + 1
        elif f.severity == Severity.HIGH:
            high_by_asset[f.asset_id] = high_by_asset.get(f.asset_id, 0) + 1

    asset_rows = [
        {
            "id": str(a.id),
            "canonical_name": a.canonical_name,
            "asset_type": a.asset_type.value,
            "status": a.status.value,
            "operating_system": a.operating_system,
            "manufacturer": a.manufacturer,
            "ip_addresses": _identifiers(a, IdentifierType.IP_ADDRESS),
            "mac_addresses": _identifiers(a, IdentifierType.MAC_ADDRESS),
            "hostnames": _identifiers(a, IdentifierType.HOSTNAME)
            + _identifiers(a, IdentifierType.FQDN),
            "first_seen_at": _iso(a.first_seen_at),
            "last_seen_at": _iso(a.last_seen_at),
            "last_assessed_at": _iso(a.last_assessed_at),
            "tags": list(a.tags_json or []),
            "open_port_count": sum(
                1
                for s in services_by_asset.get(a.id, [])
                if s.state == ServiceState.OPEN
            ),
            "critical_finding_count": crit_by_asset.get(a.id, 0),
            "high_finding_count": high_by_asset.get(a.id, 0),
        }
        for a in assets
    ]

    service_rows = []
    for s in services:
        owner = asset_by_id.get(s.asset_id)
        service_rows.append(
            {
                "id": str(s.id),
                "asset_id": str(s.asset_id),
                "asset_name": owner.canonical_name if owner else "",
                "ip_address": _primary_ip(owner) if owner else None,
                "transport": s.transport.value,
                "port": s.port,
                "service_name": s.service_name,
                "product": s.product,
                "version": s.version,
                "cpe": s.cpe,
                "state": s.state.value,
                "first_seen_at": _iso(s.first_seen_at),
                "last_seen_at": _iso(s.last_seen_at),
            }
        )

    finding_rows = [
        {
            "id": str(f.id),
            "asset_id": str(f.asset_id) if f.asset_id else None,
            "asset_name": (
                asset_by_id[f.asset_id].canonical_name
                if f.asset_id in asset_by_id
                else None
            ),
            "service_id": str(f.service_id) if f.service_id else None,
            "scanner_name": f.scanner_name,
            "finding_type": f.finding_type.value,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "cve_ids": list(f.cve_ids_json or []),
            "cwe_ids": list(f.cwe_ids_json or []),
            "known_exploited": f.known_exploited,
            "epss_score": f.epss_score,
            "epss_percentile": f.epss_percentile,
            "confidence": f.confidence,
            "validation_status": f.validation_status.value,
            "status": f.status.value,
            "first_seen_at": _iso(f.first_seen_at),
            "last_seen_at": _iso(f.last_seen_at),
            "remediation": f.remediation,
            "references": list(f.references_json or []),
        }
        for f in findings
    ]

    cve_exposure: list[dict[str, Any]] = []
    for f in findings:
        for cve_id in f.cve_ids_json or []:
            enr = enr_map.get(cve_id)
            cve_exposure.append(
                {
                    "cve_id": cve_id,
                    "asset_id": str(f.asset_id) if f.asset_id else None,
                    "asset_name": (
                        asset_by_id[f.asset_id].canonical_name
                        if f.asset_id in asset_by_id
                        else None
                    ),
                    "finding_id": str(f.id),
                    "confidence": f.confidence,
                    "cvss": f.cvss_score,
                    "kev": bool(enr.is_kev) if enr else False,
                    "kev_date_added": _iso_date(enr.kev_date_added) if enr else None,
                    "ransomware": bool(enr.known_ransomware_use) if enr else False,
                    "epss": enr.epss_score if enr else f.epss_score,
                    "epss_percentile": enr.epss_percentile if enr else f.epss_percentile,
                    "first_detected": _iso(f.first_seen_at),
                    "validation_status": f.validation_status.value,
                    "remediation_status": f.status.value,
                    "in_local_db": cve_id in cve_map,
                }
            )

    change_rows = [
        {
            "timestamp": _iso(c.created_at),
            "site_id": str(c.site_id),
            "asset_id": str(c.asset_id) if c.asset_id else None,
            "event_type": c.event_type.value,
            "severity": c.severity,
            "summary": c.summary,
            "before": c.before_json,
            "after": c.after_json,
            "scan_job_id": str(c.scan_job_id) if c.scan_job_id else None,
        }
        for c in changes
    ]

    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1
    kev_count = sum(1 for f in findings if f.known_exploited)
    exploitable_count = sum(
        1 for f in findings if f.validation_status.value == "confirmed_exploitable"
    )

    return {
        "schema_version": SNAPSHOT_VERSION,
        "generated_at": _iso(now),
        "organization": (
            {"id": str(org.id), "name": org.name, "slug": org.slug} if org else None
        ),
        "site": ({"id": str(site.id), "name": site.name, "code": site.code} if site else None),
        "scan_job": {
            "id": str(scan_job.id),
            "mode": scan_job.mode.value,
            "status": scan_job.status.value,
            "created_at": _iso(scan_job.created_at),
            "started_at": _iso(scan_job.started_at),
            "finished_at": _iso(scan_job.finished_at),
            "targets": list(scan_job.requested_targets_json or []),
            "workflow": list(scan_job.workflow_json or []),
        },
        "summary": {
            "severity_counts": severity_counts,
            "kev_count": kev_count,
            "exploitable_count": exploitable_count,
            "asset_count": len(assets),
            "service_count": len(services),
            "finding_count": len(findings),
            "change_count": len(changes),
        },
        "assets": asset_rows,
        "services": service_rows,
        "findings": finding_rows,
        "cve_exposure": cve_exposure,
        "changes": change_rows,
    }


def _iso_date(d: Any) -> str | None:
    return d.isoformat() if d is not None else None
