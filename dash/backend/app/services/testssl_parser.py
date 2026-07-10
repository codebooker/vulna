"""Parse testssl.sh JSON output into normalized findings.

testssl.sh ``--json`` emits a flat list of check results. Only results at LOW
severity or above become findings; OK/INFO/WARN/DEBUG are ignored. Output is
untrusted; malformed entries are skipped and the input size is bounded by the
caller.
"""

from __future__ import annotations

import json
from typing import Any

from app.models.enums import FindingType, ServiceTransport, Severity
from app.services.findings import ParsedFinding

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class TestsslParseError(ValueError):
    """Raised when testssl.sh JSON is malformed."""

    __test__ = False  # not a pytest test class despite the "Test" prefix


def _target_ip(entry: dict[str, Any]) -> str | None:
    raw = entry.get("ip") or entry.get("fqdn/ip") or ""
    if not isinstance(raw, str) or not raw:
        return None
    # testssl reports "fqdn/ip"; take the address portion.
    return raw.split("/")[-1] or None


def parse_testssl_json(data: bytes) -> list[ParsedFinding]:
    """Parse testssl.sh JSON bytes into findings."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as exc:
        raise TestsslParseError(f"Invalid testssl JSON: {exc}") from exc

    # The flat --json format is a list; some builds wrap it in {"scanResult": [...]}
    if isinstance(parsed, dict):
        parsed = parsed.get("scanResult") or parsed.get("results") or []
    if not isinstance(parsed, list):
        raise TestsslParseError("Unexpected testssl JSON structure")

    findings: list[ParsedFinding] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        severity = _SEVERITY.get(str(entry.get("severity", "")).upper())
        if severity is None:
            continue
        check_id = str(entry.get("id") or "unknown")
        finding_text = str(entry.get("finding") or "")
        port: int | None = None
        try:
            port = int(entry["port"]) if entry.get("port") else None
        except (TypeError, ValueError):
            port = None
        cve = entry.get("cve")
        cve_ids = cve.split() if isinstance(cve, str) and cve else []

        findings.append(
            ParsedFinding(
                scanner="testssl",
                weakness_key=check_id,
                finding_type=FindingType.WEAK_PROTOCOL,
                title=(finding_text[:200] or check_id),
                severity=severity,
                target_ip=_target_ip(entry),
                port=port,
                transport=ServiceTransport.TCP,
                description=finding_text or None,
                cve_ids=cve_ids,
                evidence={"id": check_id, "finding": finding_text},
                scanner_finding_id=check_id,
            )
        )
    return findings
