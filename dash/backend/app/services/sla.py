"""Deterministic SLA policy evaluation, immutable deadlines, and guidance."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models.enums import (
    FindingStatus,
    FindingType,
    RemediationClassification,
    Severity,
    SlaCalculationSource,
    SlaExceptionStatus,
    SlaHistoryEvent,
)
from app.models.finding import Finding
from app.models.sla import (
    FindingSlaCalculation,
    RemediationGuidance,
    SlaException,
    SlaHistory,
    SlaPolicy,
)

DEFAULT_DUE_DAYS: dict[str, int] = {
    Severity.CRITICAL.value: 7,
    Severity.HIGH.value: 30,
    Severity.MEDIUM.value: 60,
    Severity.LOW.value: 90,
    Severity.INFO.value: 180,
}
MATCH_KEYS = {"severities", "finding_types", "known_exploited", "site_ids", "min_risk_score"}
TERMINAL_STATUSES = {
    FindingStatus.RESOLVED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.DUPLICATE,
    FindingStatus.SUPPRESSED,
}


class SlaError(ValueError):
    """A policy, deadline, or guidance request is invalid."""


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def validate_due_days(value: dict[str, Any]) -> dict[str, int]:
    if not isinstance(value, dict):
        raise SlaError("due_days must be an object keyed by severity")
    unknown = set(value) - set(DEFAULT_DUE_DAYS)
    if unknown:
        raise SlaError(f"unsupported due_days severities: {sorted(unknown)}")
    normalized = dict(DEFAULT_DUE_DAYS)
    for severity, days in value.items():
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
            raise SlaError(f"due_days.{severity} must be an integer from 1 to 3650")
        normalized[severity] = days
    return normalized


def validate_match(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SlaError("match must be an object")
    unknown = set(value) - MATCH_KEYS
    if unknown:
        raise SlaError(f"unsupported match fields: {sorted(unknown)}")
    normalized: dict[str, Any] = {}
    if "severities" in value:
        try:
            normalized["severities"] = sorted(
                {Severity(str(item)).value for item in value["severities"]}
            )
        except (TypeError, ValueError) as exc:
            raise SlaError("match.severities must contain supported severities") from exc
        if not normalized["severities"]:
            raise SlaError("match.severities cannot be empty")
    if "finding_types" in value:
        try:
            normalized["finding_types"] = sorted(
                {FindingType(str(item)).value for item in value["finding_types"]}
            )
        except (TypeError, ValueError) as exc:
            raise SlaError("match.finding_types must contain supported finding types") from exc
        if not normalized["finding_types"]:
            raise SlaError("match.finding_types cannot be empty")
    if "known_exploited" in value:
        if not isinstance(value["known_exploited"], bool):
            raise SlaError("match.known_exploited must be boolean")
        normalized["known_exploited"] = value["known_exploited"]
    if "site_ids" in value:
        try:
            normalized["site_ids"] = sorted(
                {str(uuid.UUID(str(item))) for item in value["site_ids"]}
            )
        except (TypeError, ValueError) as exc:
            raise SlaError("match.site_ids must contain UUIDs") from exc
        if not normalized["site_ids"]:
            raise SlaError("match.site_ids cannot be empty")
    if "min_risk_score" in value:
        score = value["min_risk_score"]
        if isinstance(score, bool) or not isinstance(score, int | float) or not 0 <= score <= 100:
            raise SlaError("match.min_risk_score must be from 0 to 100")
        normalized["min_risk_score"] = float(score)
    return normalized


def policy_matches(policy: SlaPolicy, finding: Finding) -> bool:
    match = policy.match_json
    if "severities" in match and finding.severity.value not in match["severities"]:
        return False
    if "finding_types" in match and finding.finding_type.value not in match["finding_types"]:
        return False
    if "known_exploited" in match and finding.known_exploited is not match["known_exploited"]:
        return False
    if "site_ids" in match and str(finding.site_id) not in match["site_ids"]:
        return False
    return not (
        "min_risk_score" in match
        and (finding.risk_score or 0) < match["min_risk_score"]
    )


async def matching_policy(session: AsyncSession, finding: Finding) -> SlaPolicy | None:
    policies = list(
        (
            await session.execute(
                select(SlaPolicy)
                .where(
                    SlaPolicy.organization_id == finding.organization_id,
                    SlaPolicy.enabled.is_(True),
                )
                .order_by(SlaPolicy.priority.asc())
            )
        ).scalars()
    )
    return next((policy for policy in policies if policy_matches(policy, finding)), None)


def _history(
    session: AsyncSession,
    finding: Finding,
    event: SlaHistoryEvent,
    *,
    actor_user_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    session.add(
        SlaHistory(
            organization_id=finding.organization_id,
            site_id=finding.site_id,
            finding_id=finding.id,
            event=event,
            actor_user_id=actor_user_id,
            metadata_json=metadata or {},
        )
    )


async def calculate_deadline(
    session: AsyncSession,
    finding: Finding,
    *,
    now: datetime | None = None,
    created_by_user_id: uuid.UUID | None = None,
    recalculate: bool = False,
) -> FindingSlaCalculation:
    """Establish the first immutable deadline; existing deadlines are preserved."""

    if finding.current_sla_calculation_id is not None and not recalculate:
        existing = await session.get(FindingSlaCalculation, finding.current_sla_calculation_id)
        if existing is not None:
            return existing
    now = _aware(now or datetime.now(UTC))
    started_at = _aware(finding.first_seen_at or finding.created_at or now)
    policy = await matching_policy(session, finding)
    due_days = validate_due_days(policy.due_days_json if policy else {})
    days = due_days[finding.severity.value]
    source = SlaCalculationSource.POLICY if policy else SlaCalculationSource.SEVERITY_FALLBACK
    calculation = FindingSlaCalculation(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        policy_id=policy.id if policy else None,
        previous_calculation_id=(
            finding.current_sla_calculation_id if recalculate else None
        ),
        source=source,
        started_at=started_at,
        due_at=started_at + timedelta(days=days),
        calculation_json={
            "severity": finding.severity.value,
            "days": days,
            "policy_priority": policy.priority if policy else None,
            "policy_match": policy.match_json if policy else {},
            "pause_on_risk_acceptance": policy.pause_on_risk_acceptance if policy else False,
        },
        created_by_user_id=created_by_user_id,
    )
    session.add(calculation)
    await session.flush()
    finding.current_sla_calculation_id = calculation.id
    finding.sla_started_at = finding.sla_started_at or started_at
    finding.due_at = calculation.due_at
    _history(
        session,
        finding,
        SlaHistoryEvent.CALCULATED,
        actor_user_id=created_by_user_id,
        metadata={
            "calculation_id": str(calculation.id),
            "source": source.value,
            "due_at": calculation.due_at.isoformat(),
        },
    )
    return calculation


async def request_exception(
    session: AsyncSession,
    finding: Finding,
    *,
    requested_due_at: datetime,
    reason: str,
    requested_by_user_id: uuid.UUID | None,
) -> SlaException:
    if finding.current_sla_calculation_id is None or finding.due_at is None:
        raise SlaError("calculate the finding SLA before requesting an exception")
    requested_due_at = _aware(requested_due_at)
    if requested_due_at <= _aware(finding.due_at):
        raise SlaError("an exception must extend the current deadline")
    if requested_due_at > datetime.now(UTC) + timedelta(days=3650):
        raise SlaError("an exception cannot extend more than ten years")
    exception = SlaException(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        requested_due_at=requested_due_at,
        reason=reason.strip(),
        requested_by_user_id=requested_by_user_id,
    )
    session.add(exception)
    await session.flush()
    _history(
        session,
        finding,
        SlaHistoryEvent.EXCEPTION_REQUESTED,
        actor_user_id=requested_by_user_id,
        metadata={
            "exception_id": str(exception.id),
            "requested_due_at": requested_due_at.isoformat(),
        },
    )
    return exception


async def decide_exception(
    session: AsyncSession,
    finding: Finding,
    exception: SlaException,
    *,
    approve: bool,
    reviewed_by_user_id: uuid.UUID | None,
    review_notes: str | None,
    now: datetime | None = None,
) -> None:
    if exception.status != SlaExceptionStatus.PENDING:
        raise SlaError("SLA exception is not pending")
    now = _aware(now or datetime.now(UTC))
    exception.reviewed_by_user_id = reviewed_by_user_id
    exception.reviewed_at = now
    exception.review_notes = review_notes
    if not approve:
        exception.status = SlaExceptionStatus.REJECTED
        _history(
            session,
            finding,
            SlaHistoryEvent.EXCEPTION_REJECTED,
            actor_user_id=reviewed_by_user_id,
            metadata={"exception_id": str(exception.id)},
        )
        return
    previous = finding.current_sla_calculation_id
    if previous is None:
        raise SlaError("finding does not have an SLA calculation")
    calculation = FindingSlaCalculation(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        policy_id=None,
        previous_calculation_id=previous,
        source=SlaCalculationSource.EXCEPTION,
        started_at=_aware(finding.sla_started_at or now),
        due_at=_aware(exception.requested_due_at),
        calculation_json={
            "exception_id": str(exception.id),
            "reason": exception.reason,
            "previous_due_at": _aware(finding.due_at).isoformat() if finding.due_at else None,
        },
        created_by_user_id=reviewed_by_user_id,
    )
    session.add(calculation)
    await session.flush()
    exception.status = SlaExceptionStatus.APPROVED
    exception.resulting_calculation_id = calculation.id
    finding.current_sla_calculation_id = calculation.id
    finding.due_at = calculation.due_at
    _history(
        session,
        finding,
        SlaHistoryEvent.EXCEPTION_APPROVED,
        actor_user_id=reviewed_by_user_id,
        metadata={
            "exception_id": str(exception.id),
            "calculation_id": str(calculation.id),
            "due_at": calculation.due_at.isoformat(),
        },
    )


async def _pause_allowed(session: AsyncSession, finding: Finding) -> bool:
    calculation = (
        await session.get(FindingSlaCalculation, finding.current_sla_calculation_id)
        if finding.current_sla_calculation_id
        else None
    )
    while calculation is not None:
        if calculation.policy_id is not None:
            policy = await session.get(SlaPolicy, calculation.policy_id)
            return bool(policy and policy.pause_on_risk_acceptance)
        calculation = (
            await session.get(FindingSlaCalculation, calculation.previous_calculation_id)
            if calculation.previous_calculation_id
            else None
        )
    return False


async def pause_for_risk_acceptance(
    session: AsyncSession, finding: Finding, *, now: datetime | None = None
) -> bool:
    if finding.sla_paused_at is not None or not await _pause_allowed(session, finding):
        return False
    finding.sla_paused_at = _aware(now or datetime.now(UTC))
    _history(
        session,
        finding,
        SlaHistoryEvent.PAUSED,
        metadata={"paused_at": finding.sla_paused_at.isoformat()},
    )
    return True


async def resume_after_risk_acceptance(
    session: AsyncSession, finding: Finding, *, now: datetime | None = None
) -> bool:
    if finding.sla_paused_at is None or finding.due_at is None:
        return False
    now = _aware(now or datetime.now(UTC))
    paused_at = _aware(finding.sla_paused_at)
    pause_seconds = max(0, int((now - paused_at).total_seconds()))
    previous = finding.current_sla_calculation_id
    if previous is None:
        return False
    calculation = FindingSlaCalculation(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        policy_id=None,
        previous_calculation_id=previous,
        source=SlaCalculationSource.RISK_ACCEPTANCE_RESUME,
        started_at=_aware(finding.sla_started_at or now),
        due_at=_aware(finding.due_at) + timedelta(seconds=pause_seconds),
        calculation_json={"paused_at": paused_at.isoformat(), "pause_seconds": pause_seconds},
    )
    session.add(calculation)
    await session.flush()
    finding.current_sla_calculation_id = calculation.id
    finding.due_at = calculation.due_at
    finding.sla_paused_at = None
    _history(
        session,
        finding,
        SlaHistoryEvent.RESUMED,
        metadata={
            "calculation_id": str(calculation.id),
            "pause_seconds": pause_seconds,
            "due_at": calculation.due_at.isoformat(),
        },
    )
    return True


async def sweep_sla_status(
    session: AsyncSession,
    now: datetime,
    *,
    organization_id: uuid.UUID | None = None,
) -> dict[str, int]:
    filters: list[ColumnElement[bool]] = [Finding.current_sla_calculation_id.is_not(None)]
    if organization_id is not None:
        filters.append(Finding.organization_id == organization_id)
    findings = list((await session.execute(select(Finding).where(*filters))).scalars())
    breached = 0
    completed = 0
    for finding in findings:
        if finding.status in TERMINAL_STATUSES:
            if finding.sla_completed_at is None:
                finding.sla_completed_at = _aware(finding.resolved_at or now)
                _history(session, finding, SlaHistoryEvent.COMPLETED)
                completed += 1
            continue
        if (
            finding.due_at is not None
            and finding.sla_paused_at is None
            and _aware(finding.due_at) < _aware(now)
        ):
            prior = await session.scalar(
                select(SlaHistory.id).where(
                    SlaHistory.finding_id == finding.id,
                    SlaHistory.event == SlaHistoryEvent.BREACHED,
                )
            )
            if prior is None:
                _history(
                    session,
                    finding,
                    SlaHistoryEvent.BREACHED,
                    metadata={"due_at": _aware(finding.due_at).isoformat()},
                )
                breached += 1
    await session.flush()
    return {"breached": breached, "completed": completed}


async def complete_finding(
    session: AsyncSession, finding: Finding, *, now: datetime | None = None
) -> bool:
    if finding.current_sla_calculation_id is None or finding.sla_completed_at is not None:
        return False
    finding.sla_completed_at = _aware(now or finding.resolved_at or datetime.now(UTC))
    _history(
        session,
        finding,
        SlaHistoryEvent.COMPLETED,
        metadata={"completed_at": finding.sla_completed_at.isoformat()},
    )
    return True


async def metrics(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: datetime | None = None,
    site_ids: set[uuid.UUID] | None = None,
) -> dict[str, Any]:
    now = _aware(now or datetime.now(UTC))
    filters: list[ColumnElement[bool]] = [
        Finding.organization_id == organization_id,
        Finding.due_at.is_not(None),
    ]
    if site_ids is not None:
        filters.append(Finding.site_id.in_(site_ids))
    findings = list((await session.execute(select(Finding).where(*filters))).scalars())
    open_findings = [finding for finding in findings if finding.status not in TERMINAL_STATUSES]
    overdue = [
        finding
        for finding in open_findings
        if finding.sla_paused_at is None and finding.due_at and _aware(finding.due_at) < now
    ]
    due_soon = [
        finding
        for finding in open_findings
        if finding.due_at and now <= _aware(finding.due_at) <= now + timedelta(days=7)
    ]
    completed = [finding for finding in findings if finding.sla_completed_at is not None]
    completed_on_time = [
        finding
        for finding in completed
        if finding.due_at
        and _aware(cast(datetime, finding.sla_completed_at)) <= _aware(finding.due_at)
    ]
    return {
        "total_with_sla": len(findings),
        "open": len(open_findings),
        "overdue": len(overdue),
        "due_within_7_days": len(due_soon),
        "completed": len(completed),
        "completed_on_time": len(completed_on_time),
        "on_time_percentage": (
            round(len(completed_on_time) * 100 / len(completed), 2) if completed else None
        ),
        "by_severity": {
            severity.value: sum(1 for finding in open_findings if finding.severity == severity)
            for severity in Severity
        },
        "generated_at": now.isoformat(),
    }


def validate_guidance_steps(value: list[dict[str, Any]], field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise SlaError(f"{field} must contain 1-50 steps")
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"title", "instruction"}:
            raise SlaError(f"each {field} item requires only title and instruction")
        title = str(item["title"]).strip()
        instruction = str(item["instruction"]).strip()
        if not title or not instruction or len(title) > 255 or len(instruction) > 4000:
            raise SlaError(f"{field} contains an invalid step")
        result.append({"title": title, "instruction": instruction})
    return result


async def create_guidance(
    session: AsyncSession,
    finding: Finding,
    *,
    classification: RemediationClassification,
    summary: str,
    steps: list[dict[str, Any]],
    validation_steps: list[dict[str, Any]],
    references: list[str],
    source: str,
    created_by_user_id: uuid.UUID | None,
) -> RemediationGuidance:
    clean_refs = sorted({item.strip() for item in references if item.strip()})
    if len(clean_refs) > 25 or any(len(item) > 2048 for item in clean_refs):
        raise SlaError("references must contain at most 25 bounded URLs or identifiers")
    guidance = RemediationGuidance(
        organization_id=finding.organization_id,
        site_id=finding.site_id,
        finding_id=finding.id,
        classification=classification,
        summary=summary.strip(),
        steps_json=validate_guidance_steps(steps, "steps"),
        validation_steps_json=validate_guidance_steps(validation_steps, "validation_steps"),
        references_json=clean_refs,
        source=source.strip(),
        created_by_user_id=created_by_user_id,
    )
    session.add(guidance)
    await session.flush()
    return guidance
