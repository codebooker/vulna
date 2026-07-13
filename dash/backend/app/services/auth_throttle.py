"""Database-backed per-account and per-IP authentication throttling."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mfa import AuthenticationThrottle

WINDOW = timedelta(minutes=15)
FAILURES_BEFORE_BACKOFF = 5
MAX_BACKOFF_SECONDS = 15 * 60


def _hash(kind: str, value: str) -> str:
    normalized = value.strip().lower()
    return hashlib.sha256(f"vulna-auth-throttle-v1:{kind}:{normalized}".encode()).hexdigest()


def keys(email: str, source_ip: str | None) -> list[tuple[str, str]]:
    values = [("account", _hash("account", email))]
    if source_ip:
        values.append(("ip", _hash("ip", source_ip)))
    return values


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


async def retry_after(
    session: AsyncSession,
    email: str,
    source_ip: str | None,
    *,
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(UTC)
    maximum = 0
    for kind, key_hash in keys(email, source_ip):
        row = await session.scalar(
            select(AuthenticationThrottle).where(
                AuthenticationThrottle.key_type == kind,
                AuthenticationThrottle.key_hash == key_hash,
            )
        )
        if row and row.blocked_until and _aware(row.blocked_until) > now:
            maximum = max(maximum, int((_aware(row.blocked_until) - now).total_seconds()) + 1)
    return maximum


async def record_failure(
    session: AsyncSession,
    email: str,
    source_ip: str | None,
    *,
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(UTC)
    maximum = 0
    for kind, key_hash in keys(email, source_ip):
        row = await session.scalar(
            select(AuthenticationThrottle)
            .where(
                AuthenticationThrottle.key_type == kind,
                AuthenticationThrottle.key_hash == key_hash,
            )
            .with_for_update()
        )
        if row is None:
            row = AuthenticationThrottle(
                key_type=kind,
                key_hash=key_hash,
                failure_count=0,
                window_started_at=now,
            )
            session.add(row)
        elif now - _aware(row.window_started_at) > WINDOW:
            row.failure_count = 0
            row.window_started_at = now
        row.failure_count += 1
        row.last_failure_at = now
        if row.failure_count >= FAILURES_BEFORE_BACKOFF:
            delay = min(
                2 ** (row.failure_count - FAILURES_BEFORE_BACKOFF),
                MAX_BACKOFF_SECONDS,
            )
            row.blocked_until = now + timedelta(seconds=delay)
            maximum = max(maximum, delay)
    await session.flush()
    return maximum


async def reset_success(
    session: AsyncSession, email: str, source_ip: str | None
) -> None:
    for kind, key_hash in keys(email, source_ip):
        row = await session.scalar(
            select(AuthenticationThrottle).where(
                AuthenticationThrottle.key_type == kind,
                AuthenticationThrottle.key_hash == key_hash,
            )
        )
        if row is not None:
            await session.delete(row)
