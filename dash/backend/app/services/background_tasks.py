"""Durable database-leased task queue primitives."""

from __future__ import annotations

import hashlib
import os
import socket
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.background_task import BackgroundTask, WorkerHeartbeat
from app.models.enums import BackgroundTaskStatus

CLAIMABLE = (BackgroundTaskStatus.QUEUED, BackgroundTaskStatus.RETRY)
TERMINAL = (
    BackgroundTaskStatus.COMPLETED,
    BackgroundTaskStatus.CANCELLED,
    BackgroundTaskStatus.DEAD_LETTER,
)


class PersistedTaskFailure(RuntimeError):
    """Retry a task while retaining handler-written failure history.

    Ordinary handler exceptions roll back all handler writes. Connector handlers
    use this signal only after recording a bounded, non-secret attempt result; the
    runner then fences the lease and commits that history atomically with the task's
    retry/dead-letter transition.
    """


def utcnow() -> datetime:
    return datetime.now(UTC)


def scoped_idempotency_key(namespace: str, client_key: str) -> str:
    """Namespace and hash an untrusted client key into a bounded storage key."""
    digest = hashlib.sha256(client_key.encode("utf-8")).hexdigest()
    key = f"{namespace}:{digest}"
    if len(key) > 255:
        raise ValueError("idempotency key namespace is too long")
    return key


async def enqueue_task(
    session: AsyncSession,
    *,
    task_type: str,
    idempotency_key: str,
    payload: dict[str, Any] | None = None,
    organization_id: uuid.UUID | None = None,
    created_by_user_id: uuid.UUID | None = None,
    scheduled_at: datetime | None = None,
    priority: int = 100,
    max_attempts: int = 5,
) -> tuple[BackgroundTask, bool]:
    """Insert once by idempotency key and return ``(task, created)``."""
    if not idempotency_key or len(idempotency_key) > 255:
        raise ValueError("idempotency_key must contain 1-255 characters")
    existing = await session.scalar(
        select(BackgroundTask).where(BackgroundTask.idempotency_key == idempotency_key)
    )
    if existing is not None:
        return existing, False
    task = BackgroundTask(
        organization_id=organization_id,
        task_type=task_type,
        payload_json=payload or {},
        idempotency_key=idempotency_key,
        status=BackgroundTaskStatus.QUEUED,
        priority=priority,
        scheduled_at=scheduled_at or utcnow(),
        max_attempts=max_attempts,
        created_by_user_id=created_by_user_id,
    )
    try:
        async with session.begin_nested():
            session.add(task)
            await session.flush()
    except IntegrityError:
        existing = await session.scalar(
            select(BackgroundTask).where(BackgroundTask.idempotency_key == idempotency_key)
        )
        if existing is None:
            raise
        return existing, False
    return task, True


async def queue_depth(session: AsyncSession) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(BackgroundTask)
            .where(
                BackgroundTask.status.in_(
                    [
                        BackgroundTaskStatus.QUEUED,
                        BackgroundTaskStatus.RETRY,
                        BackgroundTaskStatus.RUNNING,
                    ]
                )
            )
        )
        or 0
    )


async def claim_next_task(
    session: AsyncSession,
    *,
    worker_id: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> BackgroundTask | None:
    """Atomically claim one due task; expired leases are recoverable."""
    now = now or utcnow()
    stmt = (
        select(BackgroundTask)
        .where(
            or_(
                (BackgroundTask.status.in_(CLAIMABLE) & (BackgroundTask.scheduled_at <= now)),
                (
                    (BackgroundTask.status == BackgroundTaskStatus.RUNNING)
                    & (BackgroundTask.lease_expires_at <= now)
                ),
            )
        )
        .order_by(
            BackgroundTask.priority.asc(),
            BackgroundTask.scheduled_at.asc(),
            BackgroundTask.created_at.asc(),
        )
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    task = await session.scalar(stmt)
    if task is None:
        return None
    if task.cancel_requested_at is not None:
        task.status = BackgroundTaskStatus.CANCELLED
        task.cancelled_at = now
        task.lease_owner = None
        task.lease_expires_at = None
        return None
    task.status = BackgroundTaskStatus.RUNNING
    task.attempts += 1
    task.started_at = task.started_at or now
    task.lease_owner = worker_id
    task.lease_expires_at = now + timedelta(seconds=lease_seconds)
    task.last_error = None
    await session.flush()
    return task


async def renew_lease(
    session: AsyncSession,
    *,
    task_id: uuid.UUID,
    worker_id: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> bool:
    task = await session.scalar(
        select(BackgroundTask).where(
            BackgroundTask.id == task_id,
            BackgroundTask.status == BackgroundTaskStatus.RUNNING,
            BackgroundTask.lease_owner == worker_id,
        )
    )
    if task is None:
        return False
    task.lease_expires_at = (now or utcnow()) + timedelta(seconds=lease_seconds)
    await session.flush()
    return True


async def complete_task(
    session: AsyncSession,
    task: BackgroundTask,
    result: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> None:
    now = now or utcnow()
    if task.cancel_requested_at is not None:
        task.status = BackgroundTaskStatus.CANCELLED
        task.cancelled_at = now
    else:
        task.status = BackgroundTaskStatus.COMPLETED
        task.completed_at = now
        task.result_json = result or {}
    task.lease_owner = None
    task.lease_expires_at = None
    await session.flush()


async def fail_task(
    session: AsyncSession,
    task: BackgroundTask,
    error: BaseException,
    *,
    now: datetime | None = None,
) -> None:
    now = now or utcnow()
    task.last_error = f"{type(error).__name__}: {error}"[:4096]
    task.lease_owner = None
    task.lease_expires_at = None
    if task.cancel_requested_at is not None:
        task.status = BackgroundTaskStatus.CANCELLED
        task.cancelled_at = now
    elif task.attempts >= task.max_attempts:
        task.status = BackgroundTaskStatus.DEAD_LETTER
        task.dead_lettered_at = now
    else:
        task.status = BackgroundTaskStatus.RETRY
        task.scheduled_at = now + timedelta(seconds=min(3600, 2 ** min(task.attempts, 10)))
    await session.flush()


async def request_cancellation(
    session: AsyncSession, task: BackgroundTask, *, now: datetime | None = None
) -> None:
    now = now or utcnow()
    task.cancel_requested_at = task.cancel_requested_at or now
    if task.status in CLAIMABLE:
        task.status = BackgroundTaskStatus.CANCELLED
        task.cancelled_at = now
        task.lease_owner = None
        task.lease_expires_at = None
    await session.flush()


async def retry_task(
    session: AsyncSession, task: BackgroundTask, *, now: datetime | None = None
) -> None:
    if task.status not in (BackgroundTaskStatus.DEAD_LETTER, BackgroundTaskStatus.CANCELLED):
        raise ValueError("Only dead-lettered or cancelled tasks can be retried")
    task.status = BackgroundTaskStatus.QUEUED
    task.scheduled_at = now or utcnow()
    if task.attempts >= task.max_attempts:
        # Preserve the historical attempt count while granting exactly one new
        # attempt for this audited manual retry.
        task.max_attempts = task.attempts + 1
    task.cancel_requested_at = None
    task.cancelled_at = None
    task.dead_lettered_at = None
    task.completed_at = None
    task.last_error = None
    task.result_json = {}
    task.lease_owner = None
    task.lease_expires_at = None
    await session.flush()


async def update_heartbeat(
    session: AsyncSession,
    *,
    worker_id: str,
    kind: str,
    status: str,
    current_task_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> WorkerHeartbeat:
    now = now or utcnow()
    heartbeat = await session.scalar(
        select(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == worker_id)
    )
    if heartbeat is None:
        heartbeat = WorkerHeartbeat(
            worker_id=worker_id,
            kind=kind,
            hostname=socket.gethostname(),
            process_id=os.getpid(),
            status=status,
            current_task_id=current_task_id,
            started_at=now,
            last_seen_at=now,
            metadata_json=metadata or {},
        )
        session.add(heartbeat)
    else:
        heartbeat.kind = kind
        heartbeat.status = status
        heartbeat.current_task_id = current_task_id
        heartbeat.last_seen_at = now
        heartbeat.metadata_json = metadata or heartbeat.metadata_json
    await session.flush()
    return heartbeat


def default_process_id(kind: str) -> str:
    return f"{kind}:{socket.gethostname()}:{os.getpid()}"
