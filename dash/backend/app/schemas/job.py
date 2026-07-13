"""Scan-job schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import CredentialProtocol, JobMode, JobStatus, WebScanProfile


class WebScanRequest(BaseModel):
    """Optional OWASP ZAP web-assessment stage to attach to a job."""

    profile: WebScanProfile = WebScanProfile.PASSIVE_BASELINE
    start_urls: list[str] = Field(min_length=1, max_length=50)


class JobCreate(BaseModel):
    """Operator request to create (and sign) a scan job for a probe."""

    probe_id: uuid.UUID
    network_id: uuid.UUID | None = None
    targets: list[str] = Field(min_length=1)
    mode: JobMode = JobMode.VULNERABILITY_ASSESSMENT
    not_before: datetime | None = None
    expires_at: datetime | None = None
    web_scan: WebScanRequest | None = None
    asset_id: uuid.UUID | None = None
    authenticated_protocols: list[CredentialProtocol] = Field(default_factory=list, max_length=2)
    preset_key: str | None = Field(default=None, max_length=128)


class JobRead(BaseModel):
    """A scan job as returned by the API (excludes the raw signed envelope)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    probe_id: uuid.UUID
    asset_id: uuid.UUID | None
    network_id: uuid.UUID | None
    mode: JobMode
    status: JobStatus
    requested_targets_json: list[str]
    policy_version: int
    not_before: datetime
    expires_at: datetime
    created_by: uuid.UUID | None
    offered_at: datetime | None
    accepted_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None
    error_code: str | None
    error_message: str | None
    summary_json: dict[str, Any]
    progress_percent: int
    progress_json: dict[str, Any]
    estimated_completion_at: datetime | None
    last_progress_at: datetime | None
    credential_protocols_json: list[str]
    created_at: datetime
    updated_at: datetime


class JobProgressUpdate(BaseModel):
    """Bounded, non-secret execution statistics reported by a Scout."""

    percent: int = Field(ge=0, le=99)
    current_stage: str | None = Field(default=None, max_length=128)
    current_plugin: str | None = Field(default=None, max_length=128)
    stages_total: int = Field(ge=0, le=10_000)
    stages_completed: int = Field(ge=0, le=10_000)
    stages_run: int = Field(ge=0, le=10_000)
    stages_failed: int = Field(ge=0, le=10_000)
    stages_skipped: int = Field(ge=0, le=10_000)
    target_groups: int = Field(ge=0, le=1_000_000)
    target_addresses: int = Field(ge=0, le=1_000_000_000)
    elapsed_seconds: int = Field(ge=0, le=31_536_000)
    eta_seconds: int | None = Field(default=None, ge=0, le=31_536_000)

    @model_validator(mode="after")
    def validate_counters(self) -> JobProgressUpdate:
        if (self.current_stage is None) != (self.current_plugin is None):
            raise ValueError("current_stage and current_plugin must be reported together")
        if self.stages_completed != self.stages_run + self.stages_failed + self.stages_skipped:
            raise ValueError("stages_completed must equal run + failed + skipped")
        if self.stages_completed > self.stages_total:
            raise ValueError("stages_completed cannot exceed stages_total")
        expected_percent = (
            min(99, self.stages_completed * 100 // self.stages_total) if self.stages_total else 0
        )
        if self.percent != expected_percent:
            raise ValueError("percent must match completed workflow stages")
        if self.eta_seconds is not None and not (0 < self.stages_completed < self.stages_total):
            raise ValueError("eta_seconds requires a partially completed workflow")
        return self


class JobFailureDetail(BaseModel):
    """One structured Scout failure entry; the API sanitizes it before storage."""

    code: str = Field(min_length=1, max_length=64)
    stage: str | None = Field(default=None, max_length=128)
    plugin: str | None = Field(default=None, max_length=128)
    message: str = Field(min_length=1, max_length=2048)


class JobStatusUpdate(BaseModel):
    """Status report from a probe about a job it was offered."""

    status: JobStatus
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=2048)
    summary: dict[str, Any] | None = None
    progress: JobProgressUpdate | None = None
    failure_details: list[JobFailureDetail] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def validate_status_payload(self) -> JobStatusUpdate:
        if self.progress is not None and self.status != JobStatus.RUNNING:
            raise ValueError("progress may only be reported while a job is running")
        if self.failure_details and self.status not in (
            JobStatus.FAILED,
            JobStatus.REJECTED_BY_PROBE,
        ):
            raise ValueError("failure_details require a failed or rejected job")
        return self


class JobFailureLogEntry(BaseModel):
    code: str
    stage: str | None = None
    plugin: str | None = None
    message: str
    received_at: datetime


class JobDiagnosticsRead(BaseModel):
    """Operator-only, sanitized scan failure diagnostics."""

    job_id: uuid.UUID
    status: JobStatus
    error_code: str | None
    error_message: str | None
    failures: list[JobFailureLogEntry]


class ResultIngestSummary(BaseModel):
    """Summary returned after ingesting a scanner result upload."""

    hosts_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    services_upserted: int = 0
    change_events: int = 0
    findings_seen: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    findings_reopened: int = 0
    packages_seen: int = 0
    packages_added: int = 0
    packages_updated: int = 0
    packages_removed: int = 0
    duplicate: bool = False
