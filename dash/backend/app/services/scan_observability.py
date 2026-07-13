"""Durable, bounded scan progress and sanitized failure diagnostics."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta

from app.models.scan_job import ScanJob
from app.schemas.job import JobFailureDetail, JobProgressUpdate

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")
_WHITESPACE = re.compile(r"\s+")
_PEM = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.IGNORECASE | re.DOTALL)
_AUTH = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|authorization|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL_USERINFO = re.compile(r"(https?://)[^/@\s]+@", re.IGNORECASE)
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9_.:-]+")


def sanitize_failure_message(value: str | None, *, limit: int = 2048) -> str | None:
    """Remove common secret forms and control characters from Scout messages."""
    if value is None:
        return None
    cleaned = _PEM.sub("[REDACTED PEM]", value)
    cleaned = _AUTH.sub(lambda match: f"{match.group(1)} [REDACTED]", cleaned)
    cleaned = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", cleaned)
    cleaned = _URL_USERINFO.sub(r"\1[REDACTED]@", cleaned)
    cleaned = _CONTROL.sub(" ", cleaned)
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()
    return cleaned[:limit] or "Scan failed without a diagnostic message"


def sanitize_label(value: str | None, *, fallback: str = "scanner_error") -> str | None:
    if value is None:
        return None
    cleaned = _SAFE_LABEL.sub("_", value.strip())[:128].strip("_")
    return cleaned or fallback


def apply_progress(job: ScanJob, progress: JobProgressUpdate, now: datetime) -> None:
    """Apply monotonic Scout progress and calculate the absolute ETA."""
    previous = job.progress_json or {}
    previous_completed = int(previous.get("stages_completed", 0))
    previous_elapsed = int(previous.get("elapsed_seconds", 0))
    if (
        progress.percent < job.progress_percent
        or progress.stages_completed < previous_completed
        or progress.elapsed_seconds < previous_elapsed
    ):
        raise ValueError("scan progress cannot move backwards")
    if progress.stages_total != len(job.workflow_json):
        raise ValueError("stage total does not match the signed job workflow")
    if progress.target_groups != len(job.requested_targets_json):
        raise ValueError("target group count does not match the signed job")
    if progress.target_addresses != _target_address_count(job.requested_targets_json):
        raise ValueError("target address count does not match the signed job")
    if progress.current_stage is not None:
        allowed_stages = {
            (str(item.get("stage", "")), str(item.get("plugin", ""))) for item in job.workflow_json
        }
        if (progress.current_stage, progress.current_plugin or "") not in allowed_stages:
            raise ValueError("current stage does not match the signed job workflow")
    job.progress_percent = progress.percent
    job.progress_json = progress.model_dump(exclude_none=True)
    job.last_progress_at = now
    job.estimated_completion_at = None
    if progress.eta_seconds is not None:
        estimate = now + timedelta(seconds=progress.eta_seconds)
        expires_at = job.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        job.estimated_completion_at = min(estimate, expires_at)


def _target_address_count(targets: list[str]) -> int:
    maximum = 1_000_000_000
    total = 0
    for target in targets:
        try:
            count = ipaddress.ip_network(target, strict=False).num_addresses
        except ValueError:
            count = 1
        total += count
        if total >= maximum:
            return maximum
    return total


def build_failure_log(
    details: list[JobFailureDetail],
    *,
    now: datetime,
    fallback_code: str | None,
    fallback_message: str | None,
) -> list[dict[str, str | None]]:
    """Return a server-timestamped, sanitized, bounded diagnostic log."""
    entries = details
    if not entries and fallback_message:
        entries = [
            JobFailureDetail(
                code=fallback_code or "scanner_error",
                message=fallback_message,
            )
        ]
    result: list[dict[str, str | None]] = []
    for detail in entries[:50]:
        result.append(
            {
                "code": sanitize_label(detail.code) or "scanner_error",
                "stage": sanitize_label(detail.stage, fallback="unknown_stage"),
                "plugin": sanitize_label(detail.plugin, fallback="unknown_plugin"),
                "message": sanitize_failure_message(detail.message, limit=2048),
                "received_at": now.isoformat(),
            }
        )
    return result
