"""Dedicated worker and scheduler process loops."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_sessionmaker
from app.models.background_task import BackgroundTask
from app.models.enums import BackgroundTaskStatus
from app.models.organization import Organization
from app.services import background_tasks
from app.tasks.handlers import execute_task

logger = logging.getLogger(__name__)
_SCHEDULER_LOCK_ID = 0x56554C4E41  # stable "VULNA" advisory-lock key


async def _lease_heartbeat(
    settings: Settings,
    worker_id: str,
    task_id: uuid.UUID,
    stop: asyncio.Event,
) -> None:
    factory = get_sessionmaker()
    interval = max(1.0, settings.background_task_lease_seconds / 3)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except TimeoutError:
            pass
        async with factory() as session:
            renewed = await background_tasks.renew_lease(
                session,
                task_id=task_id,
                worker_id=worker_id,
                lease_seconds=settings.background_task_lease_seconds,
            )
            await background_tasks.update_heartbeat(
                session,
                worker_id=worker_id,
                kind="worker",
                status="running" if renewed else "lease_lost",
                current_task_id=task_id if renewed else None,
            )
            await session.commit()
        if not renewed:
            return


async def run_worker_once(settings: Settings, worker_id: str) -> bool:
    factory = get_sessionmaker()
    async with factory() as session:
        await background_tasks.update_heartbeat(
            session, worker_id=worker_id, kind="worker", status="claiming"
        )
        task = await background_tasks.claim_next_task(
            session,
            worker_id=worker_id,
            lease_seconds=settings.background_task_lease_seconds,
        )
        await background_tasks.update_heartbeat(
            session,
            worker_id=worker_id,
            kind="worker",
            status="running" if task else "idle",
            current_task_id=task.id if task else None,
        )
        await session.commit()
    if task is None:
        return False

    lease_stop = asyncio.Event()
    lease_task = asyncio.create_task(_lease_heartbeat(settings, worker_id, task.id, lease_stop))
    async with factory() as session:
        claimed = await session.get(BackgroundTask, task.id)
        if claimed is None:
            lease_stop.set()
            await lease_task
            return True
        try:
            result = await execute_task(session, claimed, settings)
        except asyncio.CancelledError:
            await session.rollback()
            claimed = await session.get(BackgroundTask, task.id)
            if (
                claimed is not None
                and claimed.status == BackgroundTaskStatus.RUNNING
                and claimed.lease_owner == worker_id
            ):
                await background_tasks.fail_task(
                    session, claimed, RuntimeError("worker shutting down")
                )
                await session.commit()
            raise
        except background_tasks.PersistedTaskFailure as exc:
            # Unlike an ordinary exception, this signal means the handler wrote
            # append-only failure history that must survive. Fence it against the
            # current lease before committing it with the retry/dead-letter state.
            current = await session.scalar(
                select(BackgroundTask)
                .where(BackgroundTask.id == task.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if (
                current is None
                or current.status != BackgroundTaskStatus.RUNNING
                or current.lease_owner != worker_id
            ):
                await session.rollback()
                logger.warning("background task %s lost its lease while recording failure", task.id)
            else:
                await background_tasks.fail_task(session, current, exc)
                await session.commit()
                logger.warning("background task %s will retry: %s", task.id, exc)
        except Exception as exc:  # noqa: BLE001 - durable retry/dead-letter boundary
            await session.rollback()
            claimed = await session.get(BackgroundTask, task.id)
            if (
                claimed is not None
                and claimed.status == BackgroundTaskStatus.RUNNING
                and claimed.lease_owner == worker_id
            ):
                await background_tasks.fail_task(session, claimed, exc)
                await session.commit()
            logger.exception("background task %s failed", task.id)
        else:
            # Fence completion on the current lease. ``populate_existing`` makes
            # cancellation and lease transfers committed by another process
            # visible; the row lock makes this decision linearizable. If this
            # worker lost its lease, rolling back also discards handler writes.
            current = await session.scalar(
                select(BackgroundTask)
                .where(BackgroundTask.id == task.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if (
                current is None
                or current.status != BackgroundTaskStatus.RUNNING
                or current.lease_owner != worker_id
            ):
                await session.rollback()
                logger.warning("background task %s lease was lost before completion", task.id)
            elif current.cancel_requested_at is not None:
                # Roll back database work performed by the handler, then retain
                # the independently committed cancellation in a fresh transaction.
                await session.rollback()
                current = await session.get(BackgroundTask, task.id)
                if (
                    current is not None
                    and current.status == BackgroundTaskStatus.RUNNING
                    and current.lease_owner == worker_id
                    and current.cancel_requested_at is not None
                ):
                    await background_tasks.complete_task(session, current)
                    await session.commit()
            else:
                await background_tasks.complete_task(session, current, result)
                await session.commit()
        finally:
            lease_stop.set()
            await lease_task

    async with factory() as session:
        await background_tasks.update_heartbeat(
            session, worker_id=worker_id, kind="worker", status="idle"
        )
        await session.commit()
    return True


async def worker_loop(settings: Settings, worker_id: str) -> None:
    try:
        while True:
            worked = await run_worker_once(settings, worker_id)
            if not worked:
                await asyncio.sleep(settings.background_worker_poll_seconds)
    finally:
        factory = get_sessionmaker()
        async with factory() as session:
            await background_tasks.update_heartbeat(
                session, worker_id=worker_id, kind="worker", status="stopped"
            )
            await session.commit()


async def _try_scheduler_lock(session: AsyncSession) -> bool:
    # A transaction-scoped advisory lock serializes scheduler replicas and is
    # released automatically by commit/rollback even if the process fails.
    # SQLite is used only by tests/development and has a single process.
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return True
    return bool(
        await session.scalar(
            text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
            {"lock_id": _SCHEDULER_LOCK_ID},
        )
    )


async def run_scheduler_once(
    settings: Settings,
    scheduler_id: str,
    *,
    now: datetime | None = None,
) -> int:
    factory = get_sessionmaker()
    async with factory() as session:
        if not settings.scheduler_enabled:
            await background_tasks.update_heartbeat(
                session, worker_id=scheduler_id, kind="scheduler", status="disabled"
            )
            await session.commit()
            return 0
        await background_tasks.update_heartbeat(
            session, worker_id=scheduler_id, kind="scheduler", status="electing"
        )
        if not await _try_scheduler_lock(session):
            await background_tasks.update_heartbeat(
                session, worker_id=scheduler_id, kind="scheduler", status="standby"
            )
            await session.commit()
            return 0
        depth = await background_tasks.queue_depth(session)
        if depth >= settings.background_task_backpressure_limit:
            await background_tasks.update_heartbeat(
                session,
                worker_id=scheduler_id,
                kind="scheduler",
                status="backpressure",
                metadata={"queue_depth": depth},
            )
            await session.commit()
            return 0
        now = now or datetime.now(UTC)
        bucket = int(now.timestamp()) // settings.scheduler_interval_seconds
        created = 0
        organization_ids = list((await session.execute(select(Organization.id))).scalars())
        for organization_id in organization_ids:
            _, was_created = await background_tasks.enqueue_task(
                session,
                task_type="system.sweep",
                idempotency_key=f"scheduler:system-sweep:{organization_id}:{bucket}",
                organization_id=organization_id,
                priority=10,
                max_attempts=settings.background_task_max_attempts,
            )
            created += int(was_created)
            _, was_created = await background_tasks.enqueue_task(
                session,
                task_type="notifications.dispatch",
                idempotency_key=f"scheduler:notifications:{organization_id}:{bucket}",
                organization_id=organization_id,
                priority=50,
                max_attempts=settings.background_task_max_attempts,
            )
            created += int(was_created)
        await background_tasks.update_heartbeat(
            session,
            worker_id=scheduler_id,
            kind="scheduler",
            status="leader",
            metadata={"queue_depth": depth, "enqueued": created},
        )
        await session.commit()
        return created


async def scheduler_loop(settings: Settings, scheduler_id: str) -> None:
    try:
        while True:
            await run_scheduler_once(settings, scheduler_id)
            await asyncio.sleep(settings.scheduler_interval_seconds)
    finally:
        factory = get_sessionmaker()
        async with factory() as session:
            await background_tasks.update_heartbeat(
                session, worker_id=scheduler_id, kind="scheduler", status="stopped"
            )
            await session.commit()
