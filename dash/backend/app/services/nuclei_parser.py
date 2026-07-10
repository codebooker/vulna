"""Parse Nuclei JSONL output into normalized findings.

Nuclei emits one JSON object per line. Output is untrusted: malformed lines are
skipped, and callers bound the input size.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from app.models.enums import FindingType, ServiceTransport, Severity
from app.services.findings import ParsedFinding

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _extract_ip_port(entry: dict[str, Any]) -> tuple[str | None, int | None]:
    ip = entry.get("ip") if isinstance(entry.get("ip"), str) else None
    host = entry.get("host") or entry.get("matched-at") or ""
    port: int | None = None
    if isinstance(host, str) and host:
        parsed = urlsplit(host if "://" in host else f"//{host}")
        if ip is None and parsed.hostname:
            ip = parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None:
            port = {"https": 443, "http": 80}.get(parsed.scheme)
    return ip, port


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_nuclei_jsonl(data: bytes) -> list[ParsedFinding]:
    """Parse Nuclei JSONL bytes into findings."""
    findings: list[ParsedFinding] = []
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue

        template_id = entry.get("template-id") or entry.get("templateID") or "unknown"
        info = _as_dict(entry.get("info"))
        severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        classification = _as_dict(info.get("classification"))

        cvss_score: float | None = None
        raw_cvss = classification.get("cvss-score")
        if raw_cvss is not None:
            try:
                cvss_score = float(raw_cvss)
            except (TypeError, ValueError):
                cvss_score = None

        ip, port = _extract_ip_port(entry)
        matcher = entry.get("matcher-name") or ""
        weakness_key = f"{template_id}:{matcher}" if matcher else str(template_id)
        finding_type = (
            FindingType.WEB_APPLICATION_ISSUE
            if entry.get("type") == "http"
            else FindingType.VULNERABILITY
        )
        cvss_vector = _opt_str(classification.get("cvss-metrics"))

        findings.append(
            ParsedFinding(
                scanner="nuclei",
                weakness_key=weakness_key,
                finding_type=finding_type,
                title=str(info.get("name") or template_id),
                severity=severity,
                target_ip=ip,
                port=port,
                transport=ServiceTransport.TCP,
                description=_opt_str(info.get("description")),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector[:128] if cvss_vector else None,
                cve_ids=_str_list(classification.get("cve-id")),
                cwe_ids=_str_list(classification.get("cwe-id")),
                references=_str_list(info.get("reference")),
                remediation=_opt_str(info.get("remediation")),
                evidence={
                    "matched_at": entry.get("matched-at"),
                    "matcher": matcher,
                    "extracted": entry.get("extracted-results"),
                },
                scanner_finding_id=str(template_id),
            )
        )
    return findings
