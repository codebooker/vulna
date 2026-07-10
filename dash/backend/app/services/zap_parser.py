"""Parse OWASP ZAP ``traditional-json`` reports into normalized findings.

ZAP groups alerts per site; each alert becomes one web-application finding. The
report is untrusted output: malformed structure is skipped rather than raising,
and HTML in descriptions/solutions is reduced to plain text.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.models.enums import FindingType, ServiceTransport, Severity
from app.services.findings import ParsedFinding


class ZapParseError(ValueError):
    """Raised when the ZAP report is not valid JSON."""

    __test__ = False


# ZAP riskcode: 0 informational, 1 low, 2 medium, 3 high.
_RISK = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s<>\"]+")


def _text(value: Any) -> str | None:
    """Strip HTML tags/entities from a ZAP field to plain text."""
    if not isinstance(value, str) or not value:
        return None
    stripped = _TAG_RE.sub(" ", value)
    stripped = stripped.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    stripped = " ".join(stripped.split())
    return stripped or None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _urls(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return _URL_RE.findall(value)


def _port(site: dict[str, Any]) -> int | None:
    raw = site.get("@port")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def parse_zap_json(data: bytes) -> list[ParsedFinding]:
    """Parse a ZAP traditional-json report into findings."""
    try:
        report = json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ZapParseError(f"invalid ZAP JSON: {exc}") from exc

    findings: list[ParsedFinding] = []
    for site in _as_list(_as_dict(report).get("site")):
        s = _as_dict(site)
        host = s.get("@host") if isinstance(s.get("@host"), str) else None
        port = _port(s)
        for alert in _as_list(s.get("alerts")):
            a = _as_dict(alert)
            plugin_id = str(a.get("pluginid") or a.get("alertRef") or "unknown")
            name = a.get("name") or a.get("alert") or plugin_id
            severity = _RISK.get(str(a.get("riskcode", "0")), Severity.INFO)

            cwe_ids: list[str] = []
            cweid = a.get("cweid")
            if cweid not in (None, "", "-1", "0"):
                cwe_ids = [f"CWE-{cweid}"]

            instances = _as_list(a.get("instances"))
            first = _as_dict(instances[0]) if instances else {}

            findings.append(
                ParsedFinding(
                    scanner="zap",
                    weakness_key=plugin_id,
                    finding_type=FindingType.WEB_APPLICATION_ISSUE,
                    title=str(name),
                    severity=severity,
                    target_ip=host,
                    port=port,
                    transport=ServiceTransport.TCP,
                    description=_text(a.get("desc")),
                    cwe_ids=cwe_ids,
                    references=_urls(a.get("reference")),
                    remediation=_text(a.get("solution")),
                    evidence={
                        "uri": first.get("uri"),
                        "method": first.get("method"),
                        "param": first.get("param"),
                        "attack": first.get("attack"),
                        "evidence": first.get("evidence"),
                        "instance_count": len(instances),
                    },
                    scanner_finding_id=plugin_id,
                )
            )
    return findings
