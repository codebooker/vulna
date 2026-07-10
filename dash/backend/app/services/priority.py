"""Plain-language priority model for findings (Phase 22).

Maps formal severity/CVSS/KEV/EPSS/validation and detection confidence to one of
four everyday buckets — **fix now**, **plan a fix**, **watch**, **informational** —
while preserving the underlying formal data. The overriding rule (a security
constraint) is that an *uncertain* match is never presented as a confirmed,
fix-now vulnerability: low-confidence findings are capped at "watch".
"""

from __future__ import annotations

from app.models.enums import Severity, ValidationStatus

FIX_NOW = "fix_now"
PLAN = "plan"
WATCH = "watch"
INFORMATIONAL = "informational"

# Sort weight (lower = more urgent) for dashboards and lists.
PRIORITY_ORDER = {FIX_NOW: 0, PLAN: 1, WATCH: 2, INFORMATIONAL: 3}

# Below this detection confidence a match is treated as uncertain and never
# escalated above "watch", no matter how severe the underlying issue is.
UNCERTAIN_BELOW = 45


def confidence_label(confidence: int) -> str:
    """Human label for a 0–100 detection-confidence score."""
    if confidence >= 75:
        return "high"
    if confidence >= UNCERTAIN_BELOW:
        return "medium"
    return "low"


def classify(
    *,
    severity: Severity,
    confidence: int,
    known_exploited: bool,
    epss_score: float | None,
    validation_status: ValidationStatus,
) -> tuple[str, str]:
    """Return ``(priority, rationale)`` for a finding.

    Uncertain matches (low confidence) are capped at "watch" so a friendly label
    never overstates them as confirmed. Only confident findings can be "fix now".
    """
    epss = epss_score or 0.0

    if severity == Severity.INFO:
        return INFORMATIONAL, "Informational; no action needed."

    # Explicit validation is authoritative in both directions.
    if validation_status == ValidationStatus.CONFIRMED_EXPLOITABLE:
        return FIX_NOW, "Confirmed exploitable on this system."
    if validation_status == ValidationStatus.CONFIRMED_NON_EXPLOIT:
        return WATCH, "Checked and found not exploitable here."

    if confidence < UNCERTAIN_BELOW:
        return WATCH, "Uncertain match (low detection confidence) — verify before acting."

    # From here the detection is at least reasonably confident.
    if known_exploited and severity in (Severity.HIGH, Severity.CRITICAL):
        return FIX_NOW, "Known to be exploited in the wild (CISA KEV)."
    if severity == Severity.CRITICAL:
        return FIX_NOW, "Critical severity with confident detection."
    if severity == Severity.HIGH:
        if epss >= 0.5:
            return FIX_NOW, "High severity with elevated exploit probability (EPSS)."
        return PLAN, "High severity — plan a fix."
    if severity == Severity.MEDIUM:
        if known_exploited or epss >= 0.5:
            return PLAN, "Medium severity with exploit signals — plan a fix."
        return WATCH, "Medium severity — keep an eye on it."
    return WATCH, "Low severity — watch."
