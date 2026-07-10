"""Scan-preset endpoints (Phase 21).

Presets are a convenience layer over the same signed-job and local-policy
controls. These endpoints expose the versioned built-in presets, a per-Scout
capability report, a preview that explains exactly which stages will run and why
any are skipped, and validation for expert custom presets (validated choices
only — never raw commands).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.db.session import get_session
from app.models.probe import Probe
from app.schemas.presets import (
    CapabilityReportResponse,
    CustomValidateRequest,
    PresetOut,
    PresetsListResponse,
    PreviewRequest,
    PreviewResponse,
    RateOut,
    ScannerStatusOut,
    SkippedStageOut,
    StageOut,
)
from app.services import presets as presetsvc
from app.services.capabilities import capability_report, installed_scanners
from app.services.presets import KNOWN_SCANNERS, PresetError

router = APIRouter(prefix="/presets", tags=["presets"])


def _serialize(preset: presetsvc.Preset) -> PresetOut:
    return PresetOut(
        key=preset.key,
        version=preset.version,
        name=preset.name,
        use_case=preset.use_case,
        description=preset.description,
        stages=[
            StageOut(key=s.key, scanner=s.scanner, classification=s.classification, label=s.label)
            for s in preset.stages()
        ],
        rate=RateOut(
            packets_per_second=preset.rate.packets_per_second, concurrency=preset.rate.concurrency
        ),
        workload_class=preset.workload_class,
        duration_class=preset.duration_class,
        mode=preset.mode,
        web_profile=preset.web_profile,
        intrusive=preset.intrusive,
        active_web=preset.active_web,
        uses_credentials=preset.uses_credentials,
    )


@router.get("", response_model=PresetsListResponse, summary="List built-in scan presets")
async def list_presets(current_user: CurrentUser) -> PresetsListResponse:
    return PresetsListResponse(presets=[_serialize(p) for p in presetsvc.list_presets()])


@router.get(
    "/capabilities",
    response_model=CapabilityReportResponse,
    summary="Scanner capability report for a Scout",
)
async def capabilities(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    probe_id: str | None = None,
) -> CapabilityReportResponse:
    probe = None
    if probe_id is not None:
        probe = await session.get(Probe, probe_id)
        if probe is None or probe.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")
    caps = probe.capabilities_json if probe else None
    health = probe.health_json if probe else None
    return CapabilityReportResponse(
        probe_id=probe.id if probe else None,
        scanners=[
            ScannerStatusOut(scanner=s.scanner, status=s.status, detail=s.detail)
            for s in capability_report(caps, health)
        ],
    )


@router.post("/preview", response_model=PreviewResponse, summary="Preview a preset")
async def preview(
    payload: PreviewRequest,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PreviewResponse:
    try:
        preset = presetsvc.get_preset(payload.preset_key, payload.version)
    except PresetError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    probe = None
    if payload.probe_id is not None:
        probe = await session.get(Probe, payload.probe_id)
        if probe is None or probe.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")

    if probe is not None:
        available = installed_scanners(probe.capabilities_json)
    else:
        # No probe context: assume the standard pack is available for the preview.
        available = set(KNOWN_SCANNERS)

    resolution = presetsvc.resolve_stages(
        preset, available, allow_downgrade=payload.allow_downgrade
    )
    est = presetsvc.estimate(preset, payload.host_count)

    cpu_count = 2
    memory_bytes = 0
    if probe is not None and isinstance(probe.health_json, dict):
        cpu_count = int(probe.health_json.get("cpu_count", cpu_count) or cpu_count)
        memory_bytes = int(probe.health_json.get("memory_bytes", 0) or 0)
    tuning = presetsvc.recommend_tuning(
        preset,
        cpu_count=cpu_count,
        memory_bytes=memory_bytes,
        max_pps=None,
        max_concurrency=None,
    )

    return PreviewResponse(
        preset=preset.key,
        preset_version=preset.version,
        stages_to_run=[
            StageOut(key=s.key, scanner=s.scanner, classification=s.classification, label=s.label)
            for s in resolution.run
        ],
        skipped=[
            SkippedStageOut(stage=s.stage, scanner=s.scanner, reason=s.reason)
            for s in resolution.skipped
        ],
        blocked=resolution.blocked,
        estimate=est,
        tuning=RateOut(
            packets_per_second=tuning.packets_per_second, concurrency=tuning.concurrency
        ),
        scanners=[
            ScannerStatusOut(scanner=s.scanner, status=s.status, detail=s.detail)
            for s in capability_report(
                probe.capabilities_json if probe else list(available),
                probe.health_json if probe else None,
            )
        ],
    )


@router.get("/{key}", response_model=PresetOut, summary="Get a preset (optionally pinned)")
async def get_preset(
    key: str,
    current_user: CurrentUser,
    version: int | None = None,
) -> PresetOut:
    try:
        return _serialize(presetsvc.get_preset(key, version))
    except PresetError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/custom/validate",
    response_model=PresetOut,
    summary="Validate an expert custom preset (validated choices only)",
)
async def validate_custom(
    payload: CustomValidateRequest,
    current_user: CurrentUser,
) -> PresetOut:
    spec: dict[str, object] = {
        "name": payload.name,
        "stage_keys": payload.stage_keys,
        "packets_per_second": payload.packets_per_second,
        "concurrency": payload.concurrency,
    }
    if payload.severities is not None:
        spec["severities"] = payload.severities
    try:
        preset = presetsvc.validate_custom(spec)
    except PresetError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return _serialize(preset)
