"""Guided first-run (onboarding) endpoints (Phase 19).

These endpoints back a resumable wizard that walks a new operator from first login
to a first safe assessment. They are deliberately thin: scope approval and job
launch still go through the ordinary, audited ``/scopes`` and ``/jobs`` paths, so
the wizard cannot bypass any signature, scope, approval, or least-privilege
control. Detected ranges are advisory only and are never saved automatically.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ProbeStatus
from app.models.probe import Probe
from app.schemas.onboarding import (
    CompleteStepRequest,
    DemoTargetResponse,
    NetworkCandidatesResponse,
    OnboardingStateRead,
    RecoveryCodesResponse,
    ScanPreset,
    ScanPresetsResponse,
    ScanSummaryRequest,
    ScanSummaryResponse,
    ScopePreviewRequest,
    ScopePreviewResponse,
)
from app.services import onboarding as ob
from app.services.scopes import ScopeValidationError

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


def _unprocessable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


@router.get("/state", response_model=OnboardingStateRead, summary="Get first-run state")
async def get_state(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OnboardingStateRead:
    state = await ob.get_or_create_state(session, current_user.organization_id)
    await session.commit()
    return OnboardingStateRead.model_validate(state)


@router.post(
    "/state/complete-step",
    response_model=OnboardingStateRead,
    summary="Advance the wizard",
)
async def complete_step(
    payload: CompleteStepRequest,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OnboardingStateRead:
    state = await ob.get_or_create_state(session, current_user.organization_id)
    try:
        state = await ob.complete_step(
            session,
            state,
            payload.step,
            site_id=payload.site_id,
            scope_id=payload.scope_id,
            first_job_id=payload.first_job_id,
            demo_used=payload.demo_used,
        )
    except ValueError as exc:
        raise _unprocessable(exc) from exc
    await session.commit()
    return OnboardingStateRead.model_validate(state)


@router.post(
    "/state/dismiss",
    response_model=OnboardingStateRead,
    summary="Dismiss the setup checklist",
)
async def dismiss(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OnboardingStateRead:
    state = await ob.get_or_create_state(session, current_user.organization_id)
    state.dismissed = True
    session.add(state)
    await session.commit()
    return OnboardingStateRead.model_validate(state)


@router.post(
    "/recovery-codes",
    response_model=RecoveryCodesResponse,
    summary="Generate one-time recovery codes",
)
async def generate_recovery_codes(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RecoveryCodesResponse:
    """Generate fresh recovery codes for the current user. The plaintext codes are
    returned exactly once; only Argon2 hashes are stored."""
    codes = await ob.generate_recovery_codes(session, current_user)
    generated_at = current_user.recovery_codes_generated_at or datetime.now(UTC)
    await session.commit()
    return RecoveryCodesResponse(codes=codes, generated_at=generated_at)


@router.get(
    "/network-candidates",
    response_model=NetworkCandidatesResponse,
    summary="Advisory local network ranges",
)
async def network_candidates(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> NetworkCandidatesResponse:
    """Suggest private ranges the local Scout can see. Advisory only — nothing is
    saved or scanned until the operator explicitly approves a scope."""
    result = await session.execute(
        select(Probe).where(
            Probe.organization_id == current_user.organization_id,
            Probe.name == settings.local_scout_name,
        )
    )
    probe = result.scalar_one_or_none()
    if probe is None:
        result = await session.execute(
            select(Probe).where(
                Probe.organization_id == current_user.organization_id,
                Probe.status == ProbeStatus.ENROLLED,
            )
        )
        probe = result.scalars().first()
    candidates = ob.network_candidates_from_health(probe.health_json if probe else None)
    return NetworkCandidatesResponse(
        candidates=candidates,
        source=probe.name if probe else "none",
        note=(
            "These are suggestions from the local Scout. They are NOT approved. "
            "Only ranges you explicitly approve will ever be scanned."
        ),
    )


@router.post(
    "/scope-preview",
    response_model=ScopePreviewResponse,
    summary="Preview a proposed scope (no save)",
)
async def scope_preview(
    payload: ScopePreviewRequest,
    current_user: CurrentUser,
) -> ScopePreviewResponse:
    try:
        preview = ob.scope_preview(payload.cidr, allow_public=payload.allow_public)
    except ScopeValidationError as exc:
        raise _unprocessable(exc) from exc
    return ScopePreviewResponse(**preview)


@router.get(
    "/scan-presets",
    response_model=ScanPresetsResponse,
    summary="Available scan presets",
)
async def scan_presets(current_user: CurrentUser) -> ScanPresetsResponse:
    return ScanPresetsResponse(presets=[ScanPreset(**p) for p in ob.SCAN_PRESETS])


@router.post(
    "/scan-summary",
    response_model=ScanSummaryResponse,
    summary="Pre-scan summary",
)
async def scan_summary(
    payload: ScanSummaryRequest,
    current_user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScanSummaryResponse:
    try:
        summary = ob.scan_summary(
            payload.preset,
            payload.targets,
            retention_days=settings.report_ttl_days,
            demo=payload.demo,
        )
    except ScopeValidationError as exc:
        raise _unprocessable(exc) from exc
    except ValueError as exc:
        raise _unprocessable(exc) from exc
    return ScanSummaryResponse(**summary)


@router.get(
    "/demo-target",
    response_model=DemoTargetResponse,
    summary="Isolated demo target",
)
async def demo_target(current_user: CurrentUser) -> DemoTargetResponse:
    return DemoTargetResponse(
        cidr=ob.DEMO_TARGET,
        note=(
            "The demo assessment scans only the local Scout itself over loopback "
            f"({ob.DEMO_TARGET}). It cannot reach any other host and is never "
            "exposed publicly. Approve it like any scope to try the full workflow."
        ),
    )
