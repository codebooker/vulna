"""CSV and JSON exporters that render a report snapshot to bytes.

CSV column orders are stable and documented (build plan Section 16.2); columns
for data introduced in later phases (owner, due date, priority, risk-acceptance
expiration) are present but empty so the schema does not churn when those land.
The JSON bundle is a versioned envelope around the snapshot (Section 16.3).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

BUNDLE_VERSION = 1

FINDINGS_COLUMNS = [
    "organization",
    "site",
    "scan_id",
    "asset_id",
    "asset_name",
    "ip_addresses",
    "service",
    "port",
    "protocol",
    "finding_id",
    "title",
    "finding_type",
    "severity",
    "priority",
    "cvss_score",
    "cvss_vector",
    "cve_ids",
    "kev_status",
    "epss_score",
    "epss_percentile",
    "validation_status",
    "confidence",
    "first_seen",
    "last_seen",
    "status",
    "owner",
    "due_date",
    "remediation",
    "references",
    "risk_acceptance_expiration",
]

ASSETS_COLUMNS = [
    "site",
    "asset_id",
    "canonical_name",
    "asset_type",
    "ip_addresses",
    "mac_addresses",
    "hostnames",
    "operating_system",
    "manufacturer",
    "criticality",
    "first_seen",
    "last_seen",
    "last_assessed",
    "status",
    "open_port_count",
    "critical_finding_count",
    "high_finding_count",
    "tags",
]

SERVICES_COLUMNS = [
    "asset_id",
    "asset_name",
    "ip_address",
    "transport",
    "port",
    "service",
    "product",
    "version",
    "cpe",
    "first_seen",
    "last_seen",
    "state",
]

CVE_EXPOSURE_COLUMNS = [
    "cve_id",
    "asset_id",
    "asset_name",
    "confidence",
    "cvss",
    "kev",
    "kev_date_added",
    "ransomware_indicator",
    "epss",
    "epss_percentile",
    "first_detected",
    "validation_status",
    "remediation_status",
]


def _join(values: Any) -> str:
    """Join a list into a stable, delimiter-safe cell value."""
    if isinstance(values, list):
        return "; ".join(str(v) for v in values)
    return "" if values is None else str(values)


def _cell(value: Any) -> str:
    return "" if value is None else str(value)


def _write_csv(columns: list[str], rows: list[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: row.get(c, "") for c in columns})
    return buf.getvalue().encode("utf-8")


def findings_csv(snapshot: dict[str, Any]) -> bytes:
    org = (snapshot.get("organization") or {}).get("name", "")
    site = (snapshot.get("site") or {}).get("name", "")
    scan_id = (snapshot.get("scan_job") or {}).get("id", "")
    svc_by_id = {s["id"]: s for s in snapshot.get("services", [])}
    rows = []
    for f in snapshot.get("findings", []):
        svc = svc_by_id.get(f.get("service_id") or "", {})
        rows.append(
            {
                "organization": org,
                "site": site,
                "scan_id": scan_id,
                "asset_id": _cell(f.get("asset_id")),
                "asset_name": _cell(f.get("asset_name")),
                "ip_addresses": _cell(svc.get("ip_address")),
                "service": _cell(svc.get("service_name")),
                "port": _cell(svc.get("port")),
                "protocol": _cell(svc.get("transport")),
                "finding_id": _cell(f.get("id")),
                "title": _cell(f.get("title")),
                "finding_type": _cell(f.get("finding_type")),
                "severity": _cell(f.get("severity")),
                "priority": "",
                "cvss_score": _cell(f.get("cvss_score")),
                "cvss_vector": _cell(f.get("cvss_vector")),
                "cve_ids": _join(f.get("cve_ids")),
                "kev_status": "yes" if f.get("known_exploited") else "no",
                "epss_score": _cell(f.get("epss_score")),
                "epss_percentile": _cell(f.get("epss_percentile")),
                "validation_status": _cell(f.get("validation_status")),
                "confidence": _cell(f.get("confidence")),
                "first_seen": _cell(f.get("first_seen_at")),
                "last_seen": _cell(f.get("last_seen_at")),
                "status": _cell(f.get("status")),
                "owner": "",
                "due_date": "",
                "remediation": _cell(f.get("remediation")),
                "references": _join(f.get("references")),
                "risk_acceptance_expiration": "",
            }
        )
    return _write_csv(FINDINGS_COLUMNS, rows)


def assets_csv(snapshot: dict[str, Any]) -> bytes:
    site = (snapshot.get("site") or {}).get("name", "")
    rows = []
    for a in snapshot.get("assets", []):
        rows.append(
            {
                "site": site,
                "asset_id": _cell(a.get("id")),
                "canonical_name": _cell(a.get("canonical_name")),
                "asset_type": _cell(a.get("asset_type")),
                "ip_addresses": _join(a.get("ip_addresses")),
                "mac_addresses": _join(a.get("mac_addresses")),
                "hostnames": _join(a.get("hostnames")),
                "operating_system": _cell(a.get("operating_system")),
                "manufacturer": _cell(a.get("manufacturer")),
                "criticality": "",
                "first_seen": _cell(a.get("first_seen_at")),
                "last_seen": _cell(a.get("last_seen_at")),
                "last_assessed": _cell(a.get("last_assessed_at")),
                "status": _cell(a.get("status")),
                "open_port_count": _cell(a.get("open_port_count")),
                "critical_finding_count": _cell(a.get("critical_finding_count")),
                "high_finding_count": _cell(a.get("high_finding_count")),
                "tags": _join(a.get("tags")),
            }
        )
    return _write_csv(ASSETS_COLUMNS, rows)


def services_csv(snapshot: dict[str, Any]) -> bytes:
    rows = []
    for s in snapshot.get("services", []):
        rows.append(
            {
                "asset_id": _cell(s.get("asset_id")),
                "asset_name": _cell(s.get("asset_name")),
                "ip_address": _cell(s.get("ip_address")),
                "transport": _cell(s.get("transport")),
                "port": _cell(s.get("port")),
                "service": _cell(s.get("service_name")),
                "product": _cell(s.get("product")),
                "version": _cell(s.get("version")),
                "cpe": _cell(s.get("cpe")),
                "first_seen": _cell(s.get("first_seen_at")),
                "last_seen": _cell(s.get("last_seen_at")),
                "state": _cell(s.get("state")),
            }
        )
    return _write_csv(SERVICES_COLUMNS, rows)


def cve_exposure_csv(snapshot: dict[str, Any]) -> bytes:
    rows = []
    for e in snapshot.get("cve_exposure", []):
        rows.append(
            {
                "cve_id": _cell(e.get("cve_id")),
                "asset_id": _cell(e.get("asset_id")),
                "asset_name": _cell(e.get("asset_name")),
                "confidence": _cell(e.get("confidence")),
                "cvss": _cell(e.get("cvss")),
                "kev": "yes" if e.get("kev") else "no",
                "kev_date_added": _cell(e.get("kev_date_added")),
                "ransomware_indicator": "yes" if e.get("ransomware") else "no",
                "epss": _cell(e.get("epss")),
                "epss_percentile": _cell(e.get("epss_percentile")),
                "first_detected": _cell(e.get("first_detected")),
                "validation_status": _cell(e.get("validation_status")),
                "remediation_status": _cell(e.get("remediation_status")),
            }
        )
    return _write_csv(CVE_EXPOSURE_COLUMNS, rows)


def json_bundle(snapshot: dict[str, Any]) -> bytes:
    """Wrap the snapshot in a versioned JSON bundle envelope."""
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": snapshot.get("generated_at"),
        "snapshot": snapshot,
    }
    return json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
