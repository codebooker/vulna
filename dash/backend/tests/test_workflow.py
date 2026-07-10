"""Full-spectrum workflow engine state machine and API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.models.enums import UserRole, WorkflowRunStatus, WorkflowStageStatus
from app.models.workflow_run import WorkflowRun
from app.services import workflow as engine
from httpx import AsyncClient

from tests.conftest import UserFactory, auth_headers

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


def _run(*, web: bool, intrusive: bool) -> WorkflowRun:
    run = WorkflowRun(
        include_web=web,
        include_intrusive=intrusive,
        intrusive_approved=False,
        status=WorkflowRunStatus.PENDING,
        stages_json=engine.create_run(include_web=web, include_intrusive=intrusive),
    )
    engine.start(run, NOW)
    return run


def _status(run: WorkflowRun, name: str) -> str:
    return next(s["status"] for s in run.stages_json if s["name"] == name)


def _drive_to_gate_or_end(run: WorkflowRun) -> None:
    """Advance completing each running stage until the gate or the end."""
    while True:
        name = engine.current_stage_name(run)
        if name is None or name == "approval_gate":
            return
        engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)


def test_full_workflow_completes() -> None:
    run = _run(web=True, intrusive=False)
    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    assert _status(run, "reporting") == "completed"
    assert _status(run, "verification_scan") == "completed"
    # No intrusive requested -> validation stages skipped.
    assert _status(run, "approval_gate") == "skipped"
    assert _status(run, "allowlisted_validation") == "skipped"


def test_intrusive_denied_but_reports_still_generate() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    assert engine.current_stage_name(run) == "approval_gate"
    assert run.status == WorkflowRunStatus.AWAITING_APPROVAL

    engine.decide_intrusive(run, approve=False, now=NOW)
    assert _status(run, "approval_gate") == "denied"
    # Validation is skipped; verification + reporting still run.
    assert _status(run, "allowlisted_validation") == "skipped"
    assert engine.current_stage_name(run) == "verification_scan"

    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    assert _status(run, "verification_scan") == "completed"
    assert _status(run, "reporting") == "completed"


def test_intrusive_approved_runs_validation_and_cleanup() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    engine.decide_intrusive(run, approve=True, now=NOW)
    assert engine.current_stage_name(run) == "allowlisted_validation"
    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    for stage in ("allowlisted_validation", "evidence_collection", "cleanup", "reporting"):
        assert _status(run, stage) == "completed", stage


def test_stage_failure_is_reflected_and_tail_still_runs() -> None:
    run = _run(web=False, intrusive=True)
    # Complete precheck + discovery, then fail vulnerability assessment.
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    engine.advance(run, outcome=WorkflowStageStatus.FAILED, detail="scanner crashed", now=NOW)

    # Intrusive validation stages are skipped after the failure...
    assert _status(run, "vulnerability_assessment") == "failed"
    assert _status(run, "candidate_validation_plan") == "skipped"
    # ...but verification + reporting still run.
    assert engine.current_stage_name(run) == "verification_scan"
    _drive_to_gate_or_end(run)
    assert _status(run, "verification_scan") == "completed"
    assert _status(run, "reporting") == "completed"
    assert run.status == WorkflowRunStatus.FAILED  # a stage failed


def test_cannot_advance_the_approval_gate() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    try:
        engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    except engine.WorkflowError:
        return
    raise AssertionError("advancing the approval gate should raise")


# --- API E2E ---------------------------------------------------------------
async def _site(client: AsyncClient, admin_headers: dict[str, str]) -> str:
    resp = await client.post(
        "/api/v1/sites", json={"name": "HQ", "code": "HQ"}, headers=admin_headers
    )
    return resp.json()["id"]


async def test_workflow_api_deny_flow(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    site_id = await _site(client, admin_headers)
    created = await client.post(
        "/api/v1/workflows",
        json={"site_id": site_id, "include_intrusive": True},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]

    # Operator advances non-gate stages; an operator cannot approve.
    operator = await make_user(UserRole.SECURITY_OPERATOR)
    op_headers = auth_headers(operator)
    for _ in range(4):  # precheck, discovery, vuln, candidate_validation_plan
        r = await client.post(
            f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=op_headers
        )
        assert r.status_code == 200
        if r.json()["status"] == "awaiting_approval":
            break

    detail = await client.get(f"/api/v1/workflows/{run_id}", headers=op_headers)
    assert detail.json()["status"] == "awaiting_approval"

    # Operator cannot approve.
    denied = await client.post(
        f"/api/v1/workflows/{run_id}/approval", json={"approve": True}, headers=op_headers
    )
    assert denied.status_code == 403

    # Approver denies; workflow continues to reporting.
    approver = await make_user(UserRole.PENTEST_APPROVER)
    dec = await client.post(
        f"/api/v1/workflows/{run_id}/approval",
        json={"approve": False},
        headers=auth_headers(approver),
    )
    assert dec.status_code == 200
    # Finish verification + reporting.
    while True:
        cur = await client.get(f"/api/v1/workflows/{run_id}", headers=op_headers)
        if cur.json()["status"] in ("completed", "failed"):
            break
        await client.post(
            f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=op_headers
        )
    final = await client.get(f"/api/v1/workflows/{run_id}", headers=op_headers)
    stages = {s["name"]: s["status"] for s in final.json()["stages_json"]}
    assert final.json()["status"] == "completed"
    assert stages["allowlisted_validation"] == "skipped"
    assert stages["reporting"] == "completed"
