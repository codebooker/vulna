"""Versioned explainable risk, remediation grouping, and bounded decisions."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.enums import (
    AssetCriticality,
    FindingDecisionStatus,
    FindingDecisionType,
    FindingStatus,
    RemediationKeyType,
    RemediationSuggestionStatus,
    RemediationUnitStatus,
    Severity,
    ValidationStatus,
)
from app.models.finding import Finding
from app.models.risk import (
    FindingDecision,
    FindingScoreSnapshot,
    RemediationSuggestion,
    RemediationUnit,
    RemediationUnitFinding,
    RiskProfile,
)
from app.models.service import Service

FACTOR_KEYS = frozenset(
    {
        "severity",
        "cvss",
        "known_exploited",
        "epss",
        "confidence",
        "validation",
        "internet_exposure",
        "asset_criticality",
    }
)
DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": 30.0,
    "cvss": 20.0,
    "known_exploited": 20.0,
    "epss": 10.0,
    "confidence": 10.0,
    "validation": 15.0,
    "internet_exposure": 10.0,
    "asset_criticality": 15.0,
}

_SEVERITY = {
    Severity.INFO: -1.0,
    Severity.LOW: -0.5,
    Severity.MEDIUM: 0.0,
    Severity.HIGH: 0.5,
    Severity.CRITICAL: 1.0,
}
_VALIDATION = {
    ValidationStatus.CONFIRMED_NON_EXPLOIT: -1.0,
    ValidationStatus.NOT_APPLICABLE: -1.0,
    ValidationStatus.INCONCLUSIVE: -0.25,
    ValidationStatus.UNVALIDATED: 0.0,
    ValidationStatus.LIKELY: 0.5,
    ValidationStatus.CONFIRMED_EXPLOITABLE: 1.0,
}
_CRITICALITY = {
    AssetCriticality.UNKNOWN: 0.0,
    AssetCriticality.LOW: -1.0,
    AssetCriticality.MODERATE: -0.25,
    AssetCriticality.HIGH: 0.5,
    AssetCriticality.MISSION_CRITICAL: 1.0,
}
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.+-]+")


class RiskError(ValueError):
    """A safe validation error for risk/remediation workflows."""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _clamp(value: float, low: float = -1.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def validate_weights(weights: dict[str, float]) -> dict[str, float]:
    if set(weights) != FACTOR_KEYS:
        missing = sorted(FACTOR_KEYS - set(weights))
        unknown = sorted(set(weights) - FACTOR_KEYS)
        raise RiskError(
            f"Weights must contain the exact factor catalogue; missing={missing}, unknown={unknown}"
        )
    normalized = {key: float(value) for key, value in weights.items()}
    if any(not -1000.0 <= value <= 1000.0 for value in normalized.values()):
        raise RiskError("Factor weights must be between -1000 and 1000")
    if sum(abs(value) for value in normalized.values()) <= 0:
        raise RiskError("At least one factor weight must be non-zero")
    return normalized


def priority_from_score(score: float) -> tuple[str, str]:
    """Keep the friendly four-bucket label as a score-derived presentation."""
    if score >= 75:
        return "fix_now", "Explainable risk score is 75 or higher."
    if score >= 50:
        return "plan", "Explainable risk score is between 50 and 74."
    if score >= 25:
        return "watch", "Explainable risk score is between 25 and 49."
    return "informational", "Explainable risk score is below 25."


async def default_profile(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    create: bool = True,
    created_by_user_id: uuid.UUID | None = None,
) -> RiskProfile | None:
    profile = await session.scalar(
        select(RiskProfile)
        .where(
            RiskProfile.organization_id == organization_id,
            RiskProfile.is_default.is_(True),
        )
        .order_by(RiskProfile.version.desc())
    )
    if profile is not None or not create:
        return profile
    profile = RiskProfile(
        organization_id=organization_id,
        name="Vulna default",
        version=1,
        description="Balanced local-first risk profile",
        weights_json=DEFAULT_WEIGHTS,
        is_default=True,
        created_by_user_id=created_by_user_id,
    )
    session.add(profile)
    await session.flush()
    return profile


async def create_profile_version(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    name: str,
    description: str | None,
    weights: dict[str, float],
    created_by_user_id: uuid.UUID | None,
    make_default: bool,
) -> RiskProfile:
    clean_name = " ".join(name.split())
    if not clean_name:
        raise RiskError("Profile name is required")
    current = await session.scalar(
        select(RiskProfile)
        .where(RiskProfile.organization_id == organization_id, RiskProfile.name == clean_name)
        .order_by(RiskProfile.version.desc())
    )
    version = (current.version + 1) if current else 1
    if make_default:
        existing = (
            await session.execute(
                select(RiskProfile).where(
                    RiskProfile.organization_id == organization_id,
                    RiskProfile.is_default.is_(True),
                )
            )
        ).scalars()
        for profile in existing:
            profile.is_default = False
    profile = RiskProfile(
        organization_id=organization_id,
        name=clean_name,
        version=version,
        description=description,
        weights_json=validate_weights(weights),
        is_default=make_default,
        created_by_user_id=created_by_user_id,
    )
    session.add(profile)
    await session.flush()
    return profile


async def activate_profile(session: AsyncSession, profile: RiskProfile) -> None:
    rows = (
        await session.execute(
            select(RiskProfile).where(
                RiskProfile.organization_id == profile.organization_id,
                RiskProfile.is_default.is_(True),
            )
        )
    ).scalars()
    for row in rows:
        row.is_default = row.id == profile.id
    profile.is_default = True


async def _score_inputs(
    session: AsyncSession, finding: Finding
) -> tuple[dict[str, Any], dict[str, float]]:
    asset = await session.get(Asset, finding.asset_id) if finding.asset_id else None
    sources: dict[str, Any] = {
        "severity": finding.severity.value,
        "cvss": finding.cvss_score,
        "known_exploited": finding.known_exploited,
        "epss": finding.epss_score,
        "confidence": finding.confidence,
        "validation": finding.validation_status.value,
        "internet_exposure": asset.internet_exposed if asset else None,
        "asset_criticality": asset.criticality.value if asset else None,
    }
    normalized = {
        "severity": _SEVERITY[finding.severity],
        "cvss": _clamp((finding.cvss_score / 5.0) - 1.0) if finding.cvss_score is not None else 0.0,
        "known_exploited": 1.0 if finding.known_exploited else -1.0,
        "epss": _clamp((finding.epss_score * 2.0) - 1.0) if finding.epss_score is not None else 0.0,
        "confidence": _clamp((finding.confidence / 50.0) - 1.0),
        "validation": _VALIDATION[finding.validation_status],
        "internet_exposure": (1.0 if asset.internet_exposed else -1.0) if asset else 0.0,
        "asset_criticality": _CRITICALITY[asset.criticality] if asset else 0.0,
    }
    return sources, normalized


async def score_finding(
    session: AsyncSession,
    finding: Finding,
    *,
    profile: RiskProfile | None = None,
    created_by_user_id: uuid.UUID | None = None,
    force: bool = False,
    now: datetime | None = None,
) -> FindingScoreSnapshot:
    """Calculate and persist an immutable explainable score snapshot."""
    profile = profile or await default_profile(session, finding.organization_id)
    if profile is None:  # pragma: no cover - create=True above
        raise RiskError("No active risk profile")
    weights = validate_weights(profile.weights_json)
    source_values, normalized = await _score_inputs(session, finding)
    input_document = {
        "profile_id": str(profile.id),
        "profile_version": profile.version,
        "source_values": source_values,
        "normalized": normalized,
        "weights": weights,
    }
    input_hash = hashlib.sha256(
        json.dumps(input_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if not force and finding.current_score_snapshot_id and finding.risk_input_hash == input_hash:
        existing = await session.get(FindingScoreSnapshot, finding.current_score_snapshot_id)
        if existing is not None:
            return existing

    factors: list[dict[str, Any]] = []
    weighted_sum = 0.0
    for key in sorted(FACTOR_KEYS):
        contribution = normalized[key] * weights[key]
        weighted_sum += contribution
        factors.append(
            {
                "factor": key,
                "source_value": source_values[key],
                "normalized_value": round(normalized[key], 6),
                "weight": weights[key],
                "contribution": round(contribution, 6),
            }
        )
    positive_maximum = sum(abs(value) for value in weights.values())
    score = round(max(0.0, min(100.0, (weighted_sum / positive_maximum) * 100.0)), 2)
    snapshot = FindingScoreSnapshot(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        risk_profile_id=profile.id,
        profile_version=profile.version,
        score=score,
        weighted_sum=round(weighted_sum, 6),
        positive_maximum=round(positive_maximum, 6),
        source_values_json=source_values,
        factors_json=factors,
        input_hash=input_hash,
        created_by_user_id=created_by_user_id,
    )
    session.add(snapshot)
    await session.flush()
    finding.current_score_snapshot_id = snapshot.id
    finding.risk_score = score
    finding.risk_profile_version = profile.version
    finding.risk_input_hash = input_hash
    finding.risk_scored_at = now or datetime.now(UTC)
    return snapshot


def _normalize_exact(value: str) -> str:
    return " ".join(value.casefold().split())


async def exact_remediation_keys(
    session: AsyncSession, finding: Finding
) -> list[tuple[RemediationKeyType, str, str]]:
    """Return only keys safe for automatic grouping; no fuzzy inference."""
    keys: list[tuple[RemediationKeyType, str, str]] = []
    for cve in sorted({str(value).upper() for value in finding.cve_ids_json if value}):
        keys.append((RemediationKeyType.CVE, cve, f"Remediate {cve}"))
    package = (
        finding.evidence_json.get("package") if isinstance(finding.evidence_json, dict) else None
    )
    if isinstance(package, str) and _normalize_exact(package):
        key = _normalize_exact(package)
        keys.append((RemediationKeyType.PACKAGE, key, f"Update package {package.strip()}"))
    service = await session.get(Service, finding.service_id) if finding.service_id else None
    if service is not None and service.product and _normalize_exact(service.product):
        key = _normalize_exact(service.product)
        keys.append((RemediationKeyType.PRODUCT, key, f"Remediate {service.product.strip()}"))
    if finding.remediation and _normalize_exact(finding.remediation):
        normalized = _normalize_exact(finding.remediation)
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        keys.append((RemediationKeyType.REMEDIATION, digest, finding.remediation[:512]))
    return list(dict.fromkeys(keys))


async def auto_group_findings(
    session: AsyncSession,
    findings: list[Finding],
    *,
    actor_user_id: uuid.UUID | None,
) -> tuple[int, int]:
    created = 0
    memberships = 0
    for finding in findings:
        for key_type, exact_key, title in await exact_remediation_keys(session, finding):
            unit = await session.scalar(
                select(RemediationUnit).where(
                    RemediationUnit.organization_id == finding.organization_id,
                    RemediationUnit.site_id == finding.site_id,
                    RemediationUnit.key_type == key_type,
                    RemediationUnit.exact_key == exact_key,
                )
            )
            if unit is None:
                unit = RemediationUnit(
                    organization_id=finding.organization_id,
                    site_id=finding.site_id,
                    key_type=key_type,
                    exact_key=exact_key,
                    title=title,
                    status=RemediationUnitStatus.OPEN,
                    automatically_created=True,
                    created_by_user_id=actor_user_id,
                )
                session.add(unit)
                await session.flush()
                created += 1
            existing = await session.scalar(
                select(RemediationUnitFinding).where(
                    RemediationUnitFinding.remediation_unit_id == unit.id,
                    RemediationUnitFinding.finding_id == finding.id,
                )
            )
            if existing is None:
                session.add(
                    RemediationUnitFinding(
                        organization_id=finding.organization_id,
                        remediation_unit_id=unit.id,
                        finding_id=finding.id,
                        match_basis_json={
                            "method": "exact",
                            "key_type": key_type.value,
                            "key": exact_key,
                        },
                        added_by_user_id=actor_user_id,
                    )
                )
                memberships += 1
    return created, memberships


def _tokens(value: str) -> set[str]:
    return set(_TOKEN.findall(value.casefold()))


async def suggest_fuzzy_memberships(
    session: AsyncSession,
    *,
    unit: RemediationUnit,
    findings: list[Finding],
    threshold: float = 0.5,
) -> list[RemediationSuggestion]:
    """Create review-only suggestions; never creates memberships."""
    base = _tokens(f"{unit.title} {unit.description or ''}")
    if not base:
        return []
    created: list[RemediationSuggestion] = []
    for finding in findings:
        candidate = _tokens(f"{finding.title} {finding.remediation or ''}")
        union = base | candidate
        similarity = len(base & candidate) / len(union) if union else 0.0
        if similarity < threshold:
            continue
        membership = await session.scalar(
            select(RemediationUnitFinding).where(
                RemediationUnitFinding.remediation_unit_id == unit.id,
                RemediationUnitFinding.finding_id == finding.id,
            )
        )
        existing = await session.scalar(
            select(RemediationSuggestion).where(
                RemediationSuggestion.remediation_unit_id == unit.id,
                RemediationSuggestion.finding_id == finding.id,
            )
        )
        if membership is not None or existing is not None:
            continue
        suggestion = RemediationSuggestion(
            organization_id=unit.organization_id,
            site_id=unit.site_id,
            remediation_unit_id=unit.id,
            finding_id=finding.id,
            similarity=round(similarity, 4),
            explanation_json={
                "method": "token_jaccard",
                "shared_tokens": sorted(base & candidate),
                "requires_review": True,
            },
            status=RemediationSuggestionStatus.PENDING,
        )
        session.add(suggestion)
        created.append(suggestion)
    await session.flush()
    return created


async def review_suggestion(
    session: AsyncSession,
    suggestion: RemediationSuggestion,
    *,
    accept: bool,
    reviewer_user_id: uuid.UUID,
    now: datetime | None = None,
) -> None:
    if suggestion.status != RemediationSuggestionStatus.PENDING:
        raise RiskError("Suggestion has already been reviewed")
    suggestion.status = (
        RemediationSuggestionStatus.ACCEPTED if accept else RemediationSuggestionStatus.REJECTED
    )
    suggestion.reviewed_by_user_id = reviewer_user_id
    suggestion.reviewed_at = now or datetime.now(UTC)
    if accept:
        membership = await session.scalar(
            select(RemediationUnitFinding).where(
                RemediationUnitFinding.remediation_unit_id == suggestion.remediation_unit_id,
                RemediationUnitFinding.finding_id == suggestion.finding_id,
            )
        )
        if membership is None:
            session.add(
                RemediationUnitFinding(
                    organization_id=suggestion.organization_id,
                    remediation_unit_id=suggestion.remediation_unit_id,
                    finding_id=suggestion.finding_id,
                    match_basis_json={
                        "method": "reviewed_fuzzy_suggestion",
                        "suggestion_id": str(suggestion.id),
                        "similarity": suggestion.similarity,
                    },
                    added_by_user_id=reviewer_user_id,
                )
            )


_DECISION_STATUS = {
    FindingDecisionType.FALSE_POSITIVE: FindingStatus.FALSE_POSITIVE,
    FindingDecisionType.DUPLICATE: FindingStatus.DUPLICATE,
    FindingDecisionType.SUPPRESSION: FindingStatus.SUPPRESSED,
}


async def create_finding_decision(
    session: AsyncSession,
    *,
    finding: Finding,
    decision_type: FindingDecisionType,
    reason: str,
    evidence: list[dict[str, Any]],
    expires_at: datetime,
    duplicate_of: Finding | None,
    actor_user_id: uuid.UUID,
    now: datetime | None = None,
) -> FindingDecision:
    now = now or datetime.now(UTC)
    if _aware(expires_at) <= _aware(now):
        raise RiskError("Decision expiry must be in the future")
    if not reason.strip():
        raise RiskError("A decision reason is required")
    if not evidence or any(not isinstance(item, dict) or not item for item in evidence):
        raise RiskError("At least one structured evidence reference is required")
    if decision_type == FindingDecisionType.DUPLICATE:
        if duplicate_of is None or duplicate_of.id == finding.id:
            raise RiskError("A duplicate decision requires a different canonical finding")
        if duplicate_of.organization_id != finding.organization_id:
            raise RiskError("Duplicate target must belong to the same organization")
    elif duplicate_of is not None:
        raise RiskError("duplicate_of_finding_id is valid only for duplicate decisions")
    existing = await session.scalar(
        select(FindingDecision).where(
            FindingDecision.finding_id == finding.id,
            FindingDecision.status == FindingDecisionStatus.ACTIVE,
        )
    )
    if existing is not None:
        raise RiskError("Revoke the active decision before creating another")
    decision = FindingDecision(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        decision_type=decision_type,
        status=FindingDecisionStatus.ACTIVE,
        reason=reason.strip(),
        evidence_json=evidence,
        expires_at=expires_at,
        duplicate_of_finding_id=duplicate_of.id if duplicate_of else None,
        previous_status=finding.status,
        created_by_user_id=actor_user_id,
    )
    session.add(decision)
    finding.status = _DECISION_STATUS[decision_type]
    if decision_type == FindingDecisionType.FALSE_POSITIVE:
        finding.false_positive_reason = reason.strip()
    await session.flush()
    return decision


def _restore_decision_projection(finding: Finding, decision: FindingDecision) -> None:
    if finding.status == _DECISION_STATUS[decision.decision_type]:
        finding.status = decision.previous_status
    if decision.decision_type == FindingDecisionType.FALSE_POSITIVE:
        finding.false_positive_reason = None


async def revoke_finding_decision(
    session: AsyncSession,
    decision: FindingDecision,
    *,
    actor_user_id: uuid.UUID,
    now: datetime | None = None,
) -> None:
    if decision.status != FindingDecisionStatus.ACTIVE:
        raise RiskError("Only an active decision can be revoked")
    decision.status = FindingDecisionStatus.REVOKED
    decision.revoked_by_user_id = actor_user_id
    decision.revoked_at = now or datetime.now(UTC)
    finding = await session.get(Finding, decision.finding_id)
    if finding is not None:
        _restore_decision_projection(finding, decision)


async def expire_finding_decisions(
    session: AsyncSession,
    now: datetime,
    *,
    organization_id: uuid.UUID | None = None,
) -> int:
    query = select(FindingDecision).where(
        FindingDecision.status == FindingDecisionStatus.ACTIVE,
        FindingDecision.expires_at <= now,
    )
    if organization_id is not None:
        query = query.where(FindingDecision.organization_id == organization_id)
    rows = (await session.execute(query)).scalars()
    count = 0
    for decision in rows:
        decision.status = FindingDecisionStatus.EXPIRED
        finding = await session.get(Finding, decision.finding_id)
        if finding is not None:
            _restore_decision_projection(finding, decision)
        count += 1
    return count


@dataclass(frozen=True)
class UnitSummary:
    unit: RemediationUnit
    finding_count: int
    projected_risk_reduction: float
