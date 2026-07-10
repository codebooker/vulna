"""Parser for the NVD CVE API 2.0 response.

Defensive by design: malformed entries are skipped rather than aborting a sync,
mirroring the scanner parsers. Only the fields VulnaWatch needs are extracted;
the full CVSS metric objects are kept verbatim so no scoring detail is lost.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CveData:
    """A CVE parsed from NVD, ready to upsert into ``CveRecord``."""

    cve_id: str
    published_at: datetime | None = None
    modified_at: datetime | None = None
    description: str | None = None
    cvss_v2: dict[str, Any] | None = None
    cvss_v3: dict[str, Any] | None = None
    cvss_v4: dict[str, Any] | None = None
    cwe_ids: list[str] = field(default_factory=list)
    cpe_matches: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    rejected: bool = False


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _english_description(descriptions: list[Any]) -> str | None:
    for d in descriptions:
        dd = _as_dict(d)
        value = dd.get("value")
        if dd.get("lang") == "en" and isinstance(value, str):
            return value
    for d in descriptions:  # fall back to the first with any value
        value = _as_dict(d).get("value")
        if isinstance(value, str):
            return value
    return None


def _first_cvss_data(metrics: list[Any]) -> dict[str, Any] | None:
    """Return the ``cvssData`` object of the primary metric, else the first."""
    primary: dict[str, Any] | None = None
    fallback: dict[str, Any] | None = None
    for m in metrics:
        md = _as_dict(m)
        data = _as_dict(md.get("cvssData"))
        if not data:
            continue
        if fallback is None:
            fallback = data
        if md.get("type") == "Primary" and primary is None:
            primary = data
    return primary or fallback


def _cwe_ids(weaknesses: list[Any]) -> list[str]:
    ids: list[str] = []
    for w in weaknesses:
        for d in _as_list(_as_dict(w).get("description")):
            val = _as_dict(d).get("value")
            if isinstance(val, str) and val.startswith("CWE-") and val not in ids:
                ids.append(val)
    return ids


def _cpe_matches(configurations: list[Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for cfg in configurations:
        for node in _as_list(_as_dict(cfg).get("nodes")):
            for cm in _as_list(_as_dict(node).get("cpeMatch")):
                cmd = _as_dict(cm)
                criteria = cmd.get("criteria")
                if not isinstance(criteria, str):
                    continue
                matches.append(
                    {
                        "criteria": criteria,
                        "vulnerable": bool(cmd.get("vulnerable", True)),
                        "versionStartIncluding": cmd.get("versionStartIncluding"),
                        "versionStartExcluding": cmd.get("versionStartExcluding"),
                        "versionEndIncluding": cmd.get("versionEndIncluding"),
                        "versionEndExcluding": cmd.get("versionEndExcluding"),
                    }
                )
    return matches


def _references(refs: list[Any]) -> list[str]:
    urls: list[str] = []
    for r in refs:
        url = _as_dict(r).get("url")
        if isinstance(url, str) and url not in urls:
            urls.append(url)
    return urls


def parse_nvd(raw: bytes | str) -> list[CveData]:
    """Parse an NVD CVE API 2.0 payload into a list of :class:`CveData`."""
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"invalid NVD JSON: {exc}") from exc
    out: list[CveData] = []
    for item in _as_list(_as_dict(doc).get("vulnerabilities")):
        cve = _as_dict(_as_dict(item).get("cve"))
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        metrics = _as_dict(cve.get("metrics"))
        out.append(
            CveData(
                cve_id=cve_id,
                published_at=_parse_ts(cve.get("published")),
                modified_at=_parse_ts(cve.get("lastModified")),
                description=_english_description(_as_list(cve.get("descriptions"))),
                cvss_v2=_first_cvss_data(_as_list(metrics.get("cvssMetricV2"))),
                cvss_v3=_first_cvss_data(
                    _as_list(metrics.get("cvssMetricV31")) or _as_list(metrics.get("cvssMetricV30"))
                ),
                cvss_v4=_first_cvss_data(_as_list(metrics.get("cvssMetricV40"))),
                cwe_ids=_cwe_ids(_as_list(cve.get("weaknesses"))),
                cpe_matches=_cpe_matches(_as_list(cve.get("configurations"))),
                references=_references(_as_list(cve.get("references"))),
                rejected=cve.get("vulnStatus") == "Rejected",
            )
        )
    return out


def cvss_base_score(cvss: dict[str, Any] | None) -> float | None:
    """Extract the numeric base score from a stored ``cvssData`` object."""
    if not cvss:
        return None
    score = cvss.get("baseScore")
    if isinstance(score, int | float):
        return float(score)
    return None


def cvss_vector(cvss: dict[str, Any] | None) -> str | None:
    if not cvss:
        return None
    vec = cvss.get("vectorString")
    return vec if isinstance(vec, str) else None
