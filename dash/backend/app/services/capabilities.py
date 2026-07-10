"""Scanner capability manager (Phase 21).

Reports the status of each known scanner component on a Scout so the preset
preview can explain what will run and what will be skipped. Statuses:

* ``installed``   — the Scout reports the scanner present.
* ``missing``     — not reported by the Scout.
* ``unhealthy``   — reported but flagged unhealthy in the Scout's health.
* ``unsupported`` — known scanner not available for this platform (future use).

The report is derived from what the Scout self-reports (never invoked here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.presets import KNOWN_SCANNERS


@dataclass
class ScannerStatus:
    scanner: str
    status: str
    detail: str


def capability_report(
    capabilities: list[str] | None, health: dict[str, Any] | None = None
) -> list[ScannerStatus]:
    """Return per-scanner status from the Scout's reported capabilities/health."""
    have = {c.lower() for c in (capabilities or [])}
    unhealthy = set()
    if health:
        raw = health.get("unhealthy_scanners")
        if isinstance(raw, list):
            unhealthy = {str(s).lower() for s in raw}

    report: list[ScannerStatus] = []
    for scanner in KNOWN_SCANNERS:
        if scanner in unhealthy:
            report.append(ScannerStatus(scanner, "unhealthy", "reported but not healthy"))
        elif scanner in have:
            report.append(ScannerStatus(scanner, "installed", "available"))
        else:
            report.append(ScannerStatus(scanner, "missing", "not reported by the Scout"))
    return report


def installed_scanners(capabilities: list[str] | None) -> set[str]:
    """Return the set of installed scanner names (for stage resolution)."""
    return {c.lower() for c in (capabilities or [])}
