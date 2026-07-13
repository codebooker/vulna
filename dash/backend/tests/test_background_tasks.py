"""Durable scheduler/worker queue, operations API, and isolation coverage."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.background_task import BackgroundTask, WorkerHeartbeat
from app.models.enums import BackgroundTaskStatus
from app.models.organization import Organization
from app.services import background_tasks
from app.tasks import runner
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.release_gate


async def test_idempotency_leasing_retry_dead_letter_cancellation_and_reclaim(
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    now = datetime.now(UTC)
    task, created = await background_tasks.enqueue_task(
        db_session,
        task_type="test.fail",
        idempotency_key="test:one",
        organization_id=organization.id,
        max_attempts=2,
        scheduled_at=now,
    )
    duplicate, duplicate_created = await background_tasks.enqueue_task(
        db_session,
        task_type="test.fail",
        idempotency_key="test:one",
        organization_id=organization.id,
    )
    assert created is True
    assert duplicate_created is False
    assert duplicate.id == task.id

    claimed = await background_tasks.claim_next_task(
        db_session, worker_id="worker-a", lease_seconds=30, now=now
    )
    assert claimed is not None
    assert claimed.status == BackgroundTaskStatus.RUNNING
    assert claimed.attempts == 1
    await background_tasks.fail_task(db_session, claimed, RuntimeError("temporary"), now=now)
    assert claimed.status == BackgroundTaskStatus.RETRY
    reclaimed = await background_tasks.claim_next_task(
        db_session, worker_id="worker-b", lease_seconds=30, now=now + timedelta(seconds=3)
    )
    assert reclaimed is not None
    await background_tasks.fail_task(db_session, reclaimed, RuntimeError("permanent"), now=now)
    assert reclaimed.status == BackgroundTaskStatus.DEAD_LETTER
    assert reclaimed.dead_lettered_at == now

    await background_tasks.retry_task(db_session, reclaimed, now=now)
    assert reclaimed.status == BackgroundTaskStatus.QUEUED
    assert reclaimed.max_attempts == 3
    await background_tasks.request_cancellation(db_session, reclaimed, now=now)
    assert reclaimed.status == BackgroundTaskStatus.CANCELLED

    leased, _ = await background_tasks.enqueue_task(
        db_session,
        task_type="test.lease",
        idempotency_key="test:lease",
        scheduled_at=now,
    )
    first = await background_tasks.claim_next_task(
        db_session, worker_id="worker-a", lease_seconds=1, now=now
    )
    assert first is not None and first.id == leased.id
    assert await background_tasks.renew_lease(
        db_session,
        task_id=leased.id,
        worker_id="worker-a",
        lease_seconds=10,
        now=now,
    )
    assert (
        await background_tasks.claim_next_task(
            db_session, worker_id="worker-b", lease_seconds=30, now=now + timedelta(seconds=2)
        )
        is None
    )
    second = await background_tasks.claim_next_task(
        db_session, worker_id="worker-b", lease_seconds=30, now=now + timedelta(seconds=11)
    )
    assert second is not None and second.id == leased.id
    assert second.lease_owner == "worker-b"
    assert second.attempts == 2


async def test_scheduler_is_idempotent_and_worker_executes_durable_dispatch(
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)
    settings = get_settings()
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)

    first = await runner.run_scheduler_once(settings, "scheduler-test", now=now)
    second = await runner.run_scheduler_once(settings, "scheduler-test", now=now)
    assert first == 2
    assert second == 0

    tasks = list((await db_session.execute(select(BackgroundTask))).scalars())
    assert {task.task_type for task in tasks} == {"system.sweep", "notifications.dispatch"}
    assert {task.organization_id for task in tasks} == {organization.id}
    worked = await runner.run_worker_once(settings, "worker-test")
    assert worked is True
    db_session.expire_all()
    completed = await db_session.scalar(
        select(BackgroundTask).where(BackgroundTask.status == BackgroundTaskStatus.COMPLETED)
    )
    assert completed is not None
    heartbeat = await db_session.scalar(
        select(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == "worker-test")
    )
    assert heartbeat is not None
    assert heartbeat.status == "idle"


async def test_cancellation_requested_during_handler_wins_over_completion(
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task, _ = await background_tasks.enqueue_task(
        db_session,
        task_type="test.cancel-during-run",
        idempotency_key="test:cancel-during-run",
    )
    task_id = task.id
    await db_session.commit()
    handler_started = asyncio.Event()
    handler_resume = asyncio.Event()

    async def wait_while_cancel_is_requested(
        session: AsyncSession,
        claimed: BackgroundTask,
        settings: object,
    ) -> dict[str, bool]:
        del session, claimed, settings
        handler_started.set()
        await handler_resume.wait()
        return {"handler_completed": True}

    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)
    monkeypatch.setattr(runner, "execute_task", wait_while_cancel_is_requested)
    worker = asyncio.create_task(runner.run_worker_once(get_settings(), "worker-cancel"))
    await handler_started.wait()
    async with sessionmaker() as other_session:
        await other_session.execute(
            update(BackgroundTask)
            .where(BackgroundTask.id == task_id)
            .values(cancel_requested_at=datetime.now(UTC))
        )
        await other_session.commit()
    handler_resume.set()
    assert await worker is True

    db_session.expire_all()
    cancelled = await db_session.get(BackgroundTask, task_id)
    assert cancelled is not None
    assert cancelled.status == BackgroundTaskStatus.CANCELLED
    assert cancelled.cancelled_at is not None


async def test_worker_that_loses_lease_rolls_back_handler_completion(
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task, _ = await background_tasks.enqueue_task(
        db_session,
        task_type="test.lease-loss",
        idempotency_key="test:lease-loss",
    )
    task_id = task.id
    await db_session.commit()
    handler_started = asyncio.Event()
    handler_resume = asyncio.Event()

    async def wait_while_lease_changes(
        session: AsyncSession,
        claimed: BackgroundTask,
        settings: object,
    ) -> dict[str, bool]:
        del session, claimed, settings
        handler_started.set()
        await handler_resume.wait()
        return {"handler_completed": True}

    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)
    monkeypatch.setattr(runner, "execute_task", wait_while_lease_changes)
    worker = asyncio.create_task(runner.run_worker_once(get_settings(), "worker-original"))
    await handler_started.wait()
    async with sessionmaker() as other_session:
        await other_session.execute(
            update(BackgroundTask)
            .where(BackgroundTask.id == task_id)
            .values(lease_owner="worker-replacement")
        )
        await other_session.commit()
    handler_resume.set()
    assert await worker is True

    db_session.expire_all()
    still_running = await db_session.get(BackgroundTask, task_id)
    assert still_running is not None
    assert still_running.status == BackgroundTaskStatus.RUNNING
    assert still_running.lease_owner == "worker-replacement"
    assert still_running.result_json == {}


async def test_task_operations_api_is_permissioned_audited_and_org_scoped(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    task, _ = await background_tasks.enqueue_task(
        db_session,
        task_type="test.api",
        idempotency_key="test:api",
        organization_id=organization.id,
    )
    task_id = task.id
    foreign = Organization(name="Foreign tasks", slug="foreign-tasks", default_timezone="UTC")
    db_session.add(foreign)
    await db_session.flush()
    await background_tasks.enqueue_task(
        db_session,
        task_type="test.foreign",
        idempotency_key="test:foreign",
        organization_id=foreign.id,
    )
    await db_session.commit()

    listing = await client.get("/api/v1/tasks", headers=admin_headers)
    assert listing.status_code == 200
    assert [value["id"] for value in listing.json()["items"]] == [str(task.id)]
    assert (await client.get("/api/v1/tasks", headers=viewer_headers)).status_code == 403
    assert (await client.get("/api/v1/tasks/health", headers=viewer_headers)).status_code == 403
    cancelled = await client.post(f"/api/v1/tasks/{task.id}/cancel", headers=admin_headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == BackgroundTaskStatus.CANCELLED.value
    retried = await client.post(f"/api/v1/tasks/{task.id}/retry", headers=admin_headers)
    assert retried.status_code == 200
    assert retried.json()["status"] == BackgroundTaskStatus.QUEUED.value
    assert (await client.get("/api/v1/tasks/health", headers=admin_headers)).status_code == 200

    db_session.expire_all()
    audit_actions = set(
        (
            await db_session.execute(
                select(AuditEvent.action).where(AuditEvent.target_id == str(task_id))
            )
        ).scalars()
    )
    assert {"background_task.cancel_requested", "background_task.retried"} <= audit_actions

    schema = (await client.get("/openapi.json")).json()
    assert "/api/v1/tasks/{task_id}/retry" in schema["paths"]
    assert "/api/v1/reports/tasks" in schema["paths"]
    assert "/api/v1/feeds/{source}/tasks" in schema["paths"]


async def test_feed_queue_namespaces_client_idempotency_and_audits_replay(
    client: AsyncClient,
    admin_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    headers = {**admin_headers, "Idempotency-Key": "same-caller-key"}
    first = await client.post("/api/v1/feeds/nvd/tasks", headers=headers)
    replay = await client.post("/api/v1/feeds/nvd/tasks", headers=headers)
    other_operation = await client.post("/api/v1/feeds/kev/tasks", headers=headers)

    assert first.status_code == 202
    assert replay.status_code == 202
    assert other_operation.status_code == 202
    assert replay.json()["id"] == first.json()["id"]
    assert other_operation.json()["id"] != first.json()["id"]
    assert first.json()["organization_id"] == str(organization.id)
    assert "same-caller-key" not in first.json()["idempotency_key"]

    db_session.expire_all()
    queued_audits = list(
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.action == "feed.sync_queued")
            )
        ).scalars()
    )
    assert len(queued_audits) == 3
    assert any(event.metadata_json["idempotent_replay"] is True for event in queued_audits)
