"""Unit tests for report exporters (CSV/JSON) and PDF rendering."""

from __future__ import annotations

import csv
import io
import json

from app.services.reports import exporters, pdf

SNAPSHOT = {
    "schema_version": 1,
    "generated_at": "2026-07-10T12:00:00+00:00",
    "organization": {"id": "o1", "name": "Acme", "slug": "acme"},
    "site": {"id": "s1", "name": "HQ", "code": "HQ"},
    "scan_job": {
        "id": "j1",
        "mode": "vulnerability_assessment",
        "status": "completed",
        "created_at": None,
        "started_at": "2026-07-10T10:00:00+00:00",
        "finished_at": "2026-07-10T10:30:00+00:00",
        "targets": ["10.0.0.0/24"],
        "workflow": [{"stage": "discovery", "plugin": "nmap"}],
    },
    "summary": {
        "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        "kev_count": 1,
        "exploitable_count": 0,
        "asset_count": 1,
        "service_count": 1,
        "finding_count": 1,
        "change_count": 1,
    },
    "assets": [
        {
            "id": "a1",
            "canonical_name": "web01",
            "asset_type": "server",
            "status": "active",
            "operating_system": "Linux",
            "manufacturer": None,
            "ip_addresses": ["10.0.0.5"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "hostnames": ["web01.example.com"],
            "first_seen_at": None,
            "last_seen_at": None,
            "last_assessed_at": None,
            "tags": ["prod"],
            "open_port_count": 1,
            "critical_finding_count": 1,
            "high_finding_count": 0,
        }
    ],
    "services": [
        {
            "id": "sv1",
            "asset_id": "a1",
            "asset_name": "web01",
            "ip_address": "10.0.0.5",
            "transport": "tcp",
            "port": 443,
            "service_name": "https",
            "product": "nginx",
            "version": "1.18.0",
            "cpe": None,
            "state": "open",
            "first_seen_at": None,
            "last_seen_at": None,
        }
    ],
    "findings": [
        {
            "id": "f1",
            "asset_id": "a1",
            "asset_name": "web01",
            "service_id": "sv1",
            "scanner_name": "nuclei",
            "finding_type": "vulnerability",
            "title": "Log4Shell — RCE ✓",  # em dash + check mark (non-latin-1)
            "description": "Remote code execution via JNDI — patch now.",
            "severity": "critical",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cve_ids": ["CVE-2021-44228"],
            "cwe_ids": ["CWE-502"],
            "known_exploited": True,
            "epss_score": 0.975,
            "epss_percentile": 0.999,
            "confidence": 80,
            "validation_status": "unvalidated",
            "status": "new",
            "first_seen_at": None,
            "last_seen_at": None,
            "remediation": "Upgrade Log4j to 2.17+.",
            "references": ["https://logging.apache.org/"],
        }
    ],
    "cve_exposure": [
        {
            "cve_id": "CVE-2021-44228",
            "asset_id": "a1",
            "asset_name": "web01",
            "finding_id": "f1",
            "confidence": 80,
            "cvss": 10.0,
            "kev": True,
            "kev_date_added": "2021-12-10",
            "ransomware": True,
            "epss": 0.975,
            "epss_percentile": 0.999,
            "first_detected": None,
            "validation_status": "unvalidated",
            "remediation_status": "new",
            "in_local_db": True,
        }
    ],
    "changes": [
        {
            "timestamp": "2026-07-10T11:00:00+00:00",
            "site_id": "s1",
            "asset_id": "a1",
            "event_type": "new_finding",
            "severity": "critical",
            "summary": "New critical finding: Log4Shell",
            "before": {},
            "after": {},
            "scan_job_id": "j1",
        }
    ],
}


def _rows(data: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(data.decode("utf-8"))))


def test_findings_csv_stable_columns_and_values() -> None:
    data = exporters.findings_csv(SNAPSHOT)
    reader = csv.reader(io.StringIO(data.decode("utf-8")))
    header = next(reader)
    assert header == exporters.FINDINGS_COLUMNS
    rows = _rows(data)
    assert len(rows) == 1
    row = rows[0]
    assert row["organization"] == "Acme"
    assert row["port"] == "443"
    assert row["protocol"] == "tcp"
    assert row["cve_ids"] == "CVE-2021-44228"
    assert row["kev_status"] == "yes"
    assert row["severity"] == "critical"
    # Placeholder columns for later phases exist but are empty.
    assert row["owner"] == "" and row["due_date"] == "" and row["priority"] == ""


def test_assets_and_services_csv_columns() -> None:
    a = _rows(exporters.assets_csv(SNAPSHOT))
    assert list(a[0].keys()) == exporters.ASSETS_COLUMNS
    assert a[0]["ip_addresses"] == "10.0.0.5"
    assert a[0]["mac_addresses"] == "00:11:22:33:44:55"

    s = _rows(exporters.services_csv(SNAPSHOT))
    assert list(s[0].keys()) == exporters.SERVICES_COLUMNS
    assert s[0]["product"] == "nginx" and s[0]["port"] == "443"


def test_cve_exposure_csv() -> None:
    rows = _rows(exporters.cve_exposure_csv(SNAPSHOT))
    assert list(rows[0].keys()) == exporters.CVE_EXPOSURE_COLUMNS
    assert rows[0]["cve_id"] == "CVE-2021-44228"
    assert rows[0]["kev"] == "yes"
    assert rows[0]["ransomware_indicator"] == "yes"


def test_json_bundle_roundtrips() -> None:
    bundle = json.loads(exporters.json_bundle(SNAPSHOT).decode("utf-8"))
    assert bundle["bundle_version"] == exporters.BUNDLE_VERSION
    assert bundle["snapshot"]["summary"]["finding_count"] == 1
    assert bundle["snapshot"]["findings"][0]["cve_ids"] == ["CVE-2021-44228"]


def test_executive_pdf_is_valid_pdf() -> None:
    data = pdf.executive_pdf(SNAPSHOT)
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000


def test_technical_pdf_handles_non_latin1_text() -> None:
    # The finding title/description contain an em dash and a check mark; rendering
    # must not raise on the core-font (Latin-1) encoder.
    data = pdf.technical_pdf(SNAPSHOT)
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000


def test_pdf_renders_with_empty_snapshot() -> None:
    empty = {"summary": {}, "scan_job": {}, "findings": [], "services": [], "assets": []}
    assert pdf.executive_pdf(empty)[:5] == b"%PDF-"
    assert pdf.technical_pdf(empty)[:5] == b"%PDF-"
