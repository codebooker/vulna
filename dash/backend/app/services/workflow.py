"""Full-spectrum workflow engine (build plan Section 13.3).

A small, deterministic state machine over the assessment stages. Stage execution
itself (scanning, validation, report generation) is driven externally — a caller
advances the run as each stage completes, fails, or is denied — but the engine
owns the ordering, conditional skipping, the approval pause, safe continuation
after a denied/failed stage, and the guarantee that cleanup (when validation ran),
verification, and reporting always run.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.enums import WorkflowRunStatus, WorkflowStageStatus
from app.models.workflow_run import WorkflowRun

# The ordered full-spectrum stages. Tail stages always run (cleanup only when a
# validation actually ran), so a denial or a mid-workflow failure never skips
# cleanup/verification/reporting.
STAGE_ORDER: list[str] = [
    "authorization_precheck",
    "discovery",
    "vulnerability_assessment",
    "web_and_tls",
    "candidate_validation_plan",
    "approval_gate",
    "allowlisted_validation",
    "evidence_collection",
    "cleanup",
    "verification_scan",
    "reporting",
]
_APPROVAL_GATE = "approval_gate"
_TAIL = {"cleanup", "verification_scan", "reporting"}


class WorkflowError(ValueError):
    """Raised when a workflow action is invalid for the run's state."""


def _applicable(name: str, run: WorkflowRun) -> bool:
    if name == "web_and_tls":
        return run.include_web
    if name in ("candidate_validation_plan", "approval_gate"):
        return run.include_intrusive
    if name in ("allowlisted_validation", "evidence_collection", "cleanup"):
        return run.include_intrusive and run.intrusive_approved
    return True  # always-run stages


def _stage(run: WorkflowRun, name: str) -> dict[str, Any]:
    for s in run.stages_json:
        if s["name"] == name:
            return s
    raise WorkflowError(f"unknown stage '{name}'")


def _current(run: WorkflowRun) -> dict[str, Any] | None:
    for s in run.stages_json:
        if s["status"] in (
            WorkflowStageStatus.RUNNING.value,
            WorkflowStageStatus.AWAITING_APPROVAL.value,
        ):
            return s
    return None


def current_stage_name(run: WorkflowRun) -> str | None:
    """Name of the stage currently running or awaiting approval, if any."""
    current = _current(run)
    return current["name"] if current else None


def _has_failure(run: WorkflowRun) -> bool:
    return any(s["status"] == WorkflowStageStatus.FAILED.value for s in run.stages_json)


def _finalize(run: WorkflowRun) -> None:
    run.status = (
        WorkflowRunStatus.FAILED if _has_failure(run) else WorkflowRunStatus.COMPLETED
    )


def _activate_next(run: WorkflowRun, from_index: int, now: datetime) -> None:
    """Skip inapplicable stages and start the next applicable one, pausing at the
    approval gate. Finalizes the run when no stages remain."""
    for i in range(from_index + 1, len(STAGE_ORDER)):
        stage = _stage(run, STAGE_ORDER[i])
        if stage["status"] not in (
            WorkflowStageStatus.PENDING.value,
            WorkflowStageStatus.RUNNING.value,
        ):
            continue  # already skipped/denied/completed
        if not _applicable(stage["name"], run):
            stage["status"] = WorkflowStageStatus.SKIPPED.value
            continue
        if stage["name"] == _APPROVAL_GATE:
            stage["status"] = WorkflowStageStatus.AWAITING_APPROVAL.value
            stage["started_at"] = now.isoformat()
            run.status = WorkflowRunStatus.AWAITING_APPROVAL
        else:
            stage["status"] = WorkflowStageStatus.RUNNING.value
            stage["started_at"] = now.isoformat()
            run.status = WorkflowRunStatus.RUNNING
        return
    _finalize(run)


def create_run(
    *,
    include_web: bool,
    include_intrusive: bool,
) -> list[dict[str, Any]]:
    """Build the initial stages_json (all pending). The engine activates the
    first stage in :func:`start`."""
    return [
        {"name": name, "status": WorkflowStageStatus.PENDING.value, "detail": None,
         "started_at": None, "ended_at": None}
        for name in STAGE_ORDER
    ]


def start(run: WorkflowRun, now: datetime) -> None:
    """Activate the first stage of a freshly created run."""
    _activate_next(run, -1, now)


def advance(
    run: WorkflowRun, *, outcome: WorkflowStageStatus, detail: str | None, now: datetime
) -> None:
    """Complete (or fail) the current running stage and move on.

    On failure, remaining non-tail stages are skipped so the run proceeds straight
    to cleanup/verification/reporting — those always run when applicable.
    """
    current = _current(run)
    if current is None:
        raise WorkflowError("no active stage to advance")
    if current["name"] == _APPROVAL_GATE:
        raise WorkflowError("approval gate must be decided, not advanced")
    if outcome not in (WorkflowStageStatus.COMPLETED, WorkflowStageStatus.FAILED):
        raise WorkflowError("advance outcome must be completed or failed")

    current["status"] = outcome.value
    current["detail"] = detail
    current["ended_at"] = now.isoformat()
    current_index = STAGE_ORDER.index(current["name"])

    if outcome == WorkflowStageStatus.FAILED:
        for name in STAGE_ORDER[current_index + 1 :]:
            if name not in _TAIL:
                s = _stage(run, name)
                if s["status"] == WorkflowStageStatus.PENDING.value:
                    s["status"] = WorkflowStageStatus.SKIPPED.value

    _activate_next(run, current_index, now)


# The scanning stages, each realized by its own single-stage scan job (nmap
# discovery, nuclei vulnerability, testssl TLS). The workflow dispatches one job
# per stage and advances that stage on the job's terminal result (see
# services/workflow_dispatch).
SCAN_STAGES = ("discovery", "vulnerability_assessment", "web_and_tls")


def scanning_stage_active(run: WorkflowRun) -> bool:
    """True when the run is waiting on the dispatched scan job to finish."""
    return current_stage_name(run) in SCAN_STAGES


def fail_scanning(run: WorkflowRun, *, detail: str, now: datetime) -> None:
    """Fail the active scanning stage when the dispatched scan job does not
    complete; the engine then skips to cleanup/verification/reporting."""
    if scanning_stage_active(run):
        advance(run, outcome=WorkflowStageStatus.FAILED, detail=detail, now=now)


def decide_intrusive(run: WorkflowRun, *, approve: bool, now: datetime) -> None:
    """Approve or deny the intrusive stage at the approval gate. Denial continues
    the workflow safely (validation/evidence/cleanup are skipped, verification and
    reporting still run)."""
    gate = _stage(run, _APPROVAL_GATE)
    if gate["status"] != WorkflowStageStatus.AWAITING_APPROVAL.value:
        raise WorkflowError("run is not awaiting approval")
    gate["ended_at"] = now.isoformat()
    if approve:
        gate["status"] = WorkflowStageStatus.COMPLETED.value
        run.intrusive_approved = True
    else:
        gate["status"] = WorkflowStageStatus.DENIED.value
        run.intrusive_approved = False
    _activate_next(run, STAGE_ORDER.index(_APPROVAL_GATE), now)
