"""Scan-preset schemas (Phase 21)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class StageOut(BaseModel):
    key: str
    scanner: str
    classification: str
    label: str


class RateOut(BaseModel):
    packets_per_second: int
    concurrency: int


class PresetOut(BaseModel):
    key: str
    version: int
    name: str
    use_case: str
    description: str
    stages: list[StageOut]
    rate: RateOut
    workload_class: str
    duration_class: str
    mode: str
    web_profile: str | None
    intrusive: bool
    active_web: bool
    uses_credentials: bool


class PresetsListResponse(BaseModel):
    presets: list[PresetOut]


class ScannerStatusOut(BaseModel):
    scanner: str
    status: str
    detail: str


class CapabilityReportResponse(BaseModel):
    probe_id: uuid.UUID | None
    scanners: list[ScannerStatusOut]


class SkippedStageOut(BaseModel):
    stage: str
    scanner: str
    reason: str


class PreviewRequest(BaseModel):
    preset_key: str = "standard"
    version: int | None = None
    probe_id: uuid.UUID | None = None
    host_count: int = Field(default=1, ge=1)
    allow_downgrade: bool = False


class PreviewResponse(BaseModel):
    preset: str
    preset_version: int
    stages_to_run: list[StageOut]
    skipped: list[SkippedStageOut]
    blocked: bool
    estimate: dict[str, str]
    tuning: RateOut
    scanners: list[ScannerStatusOut]


class CustomValidateRequest(BaseModel):
    name: str
    stage_keys: list[str]
    packets_per_second: int = 100
    concurrency: int = 2
    severities: list[str] | None = None
