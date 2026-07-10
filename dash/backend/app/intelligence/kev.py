"""Parser for the CISA Known Exploited Vulnerabilities (KEV) catalog JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from typing import Any


@dataclass
class KevEntry:
    """One CISA KEV catalog entry, ready to upsert into enrichment."""

    cve_id: str
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = None
    known_ransomware_use: bool = False


@dataclass
class KevCatalog:
    """A parsed KEV catalog with its source version/date for feed health."""

    catalog_version: str | None
    date_released: str | None
    entries: list[KevEntry]


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def parse_kev(raw: bytes | str) -> KevCatalog:
    """Parse the CISA KEV catalog JSON into :class:`KevCatalog`."""
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"invalid KEV JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("KEV catalog must be a JSON object")
    entries: list[KevEntry] = []
    vulns = doc.get("vulnerabilities")
    for item in vulns if isinstance(vulns, list) else []:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        ransomware = item.get("knownRansomwareCampaignUse")
        entries.append(
            KevEntry(
                cve_id=cve_id,
                date_added=_parse_date(item.get("dateAdded")),
                due_date=_parse_date(item.get("dueDate")),
                required_action=(
                    item.get("requiredAction")
                    if isinstance(item.get("requiredAction"), str)
                    else None
                ),
                known_ransomware_use=isinstance(ransomware, str)
                and ransomware.strip().lower() == "known",
            )
        )
    return KevCatalog(
        catalog_version=(
            doc.get("catalogVersion") if isinstance(doc.get("catalogVersion"), str) else None
        ),
        date_released=(
            doc.get("dateReleased") if isinstance(doc.get("dateReleased"), str) else None
        ),
        entries=entries,
    )
