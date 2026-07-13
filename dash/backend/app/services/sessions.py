"""Server-side session policy, rotation, expiry, and revocation invariants."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.session import SessionRefreshToken, UserSession
from app.models.user import User
from app.services.account_tokens import (
    AccountTokenPurpose,
    GeneratedAccountToken,
    generate_account_token,
)

REFRESH_COOKIE_NAME = "vulna_refresh"
ACCESS_TOKEN_MINUTES = 15


@dataclass(frozen=True)
class SessionPolicy:
    idle_timeout_hours: int = 12
    absolute_lifetime_days: int = 30
    privileged_window_minutes: int = 15
    max_concurrent_sessions: int = 10
    trusted_device_days: int = 30


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def session_policy(org: Organization) -> SessionPolicy:
    raw = (org.settings_json or {}).get("session_policy") or {}
    defaults = SessionPolicy()
    return SessionPolicy(
        idle_timeout_hours=int(raw.get("idle_timeout_hours", defaults.idle_timeout_hours)),
        absolute_lifetime_days=int(
            raw.get("absolute_lifetime_days", defaults.absolute_lifetime_days)
        ),
        privileged_window_minutes=int(
            raw.get("privileged_window_minutes", defaults.privileged_window_minutes)
        ),
        max_concurrent_sessions=int(
            raw.get("max_concurrent_sessions", defaults.max_concurrent_sessions)
        ),
        trusted_device_days=int(
            raw.get("trusted_device_days", defaults.trusted_device_days)
        ),
    )


def policy_dict(policy: SessionPolicy) -> dict[str, int]:
    return asdict(policy)


def update_session_policy(org: Organization, values: dict[str, int]) -> SessionPolicy:
    current = policy_dict(session_policy(org))
    current.update(values)
    policy = SessionPolicy(**current)
    settings: dict[str, Any] = dict(org.settings_json or {})
    settings["session_policy"] = policy_dict(policy)
    org.settings_json = settings
    return policy


def is_session_active(value: UserSession, *, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return (
        value.revoked_at is None
        and aware(value.idle_expires_at) > now
        and aware(value.absolute_expires_at) > now
    )


def touch_session(value: UserSession, *, now: datetime | None = None) -> None:
    now = now or utcnow()
    value.last_seen_at = now
    value.idle_expires_at = min(
        now + timedelta(seconds=value.idle_timeout_seconds),
        aware(value.absolute_expires_at),
    )


async def revoke_session(
    session: AsyncSession,
    value: UserSession,
    *,
    reason: str,
    now: datetime | None = None,
) -> None:
    now = now or utcnow()
    if value.revoked_at is None:
        value.revoked_at = now
        value.revocation_reason = reason[:255]
    await session.execute(
        update(SessionRefreshToken)
        .where(
            SessionRefreshToken.session_id == value.id,
            SessionRefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )


async def revoke_user_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    reason: str,
    exclude_session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    now = now or utcnow()
    filters = [UserSession.user_id == user_id, UserSession.revoked_at.is_(None)]
    if exclude_session_id is not None:
        filters.append(UserSession.id != exclude_session_id)
    rows = list((await session.execute(select(UserSession).where(*filters))).scalars())
    for value in rows:
        await revoke_session(session, value, reason=reason, now=now)
    return len(rows)


async def create_session(
    session: AsyncSession,
    *,
    user: User,
    org: Organization,
    master_secret: str,
    source_ip: str | None,
    user_agent: str | None,
    device_name: str | None,
    trust_device: bool,
    mfa_pending: bool = False,
    now: datetime | None = None,
) -> tuple[UserSession, GeneratedAccountToken]:
    now = now or utcnow()
    policy = session_policy(org)
    active = list(
        (
            await session.execute(
                select(UserSession)
                .where(
                    UserSession.user_id == user.id,
                    UserSession.revoked_at.is_(None),
                    UserSession.idle_expires_at > now,
                    UserSession.absolute_expires_at > now,
                )
                .order_by(UserSession.last_seen_at.asc())
            )
        ).scalars()
    )
    overflow = max(0, len(active) - policy.max_concurrent_sessions + 1)
    for old in active[:overflow]:
        await revoke_session(session, old, reason="concurrent session limit", now=now)

    absolute = now + timedelta(days=policy.absolute_lifetime_days)
    value = UserSession(
        organization_id=user.organization_id,
        user_id=user.id,
        auth_version=user.auth_version,
        last_seen_at=now,
        authenticated_at=now,
        idle_expires_at=min(now + timedelta(hours=policy.idle_timeout_hours), absolute),
        absolute_expires_at=absolute,
        idle_timeout_seconds=policy.idle_timeout_hours * 60 * 60,
        device_name=(device_name or "").strip()[:255] or None,
        source_ip=source_ip,
        user_agent=(user_agent or "")[:1024] or None,
        trusted_until=(
            now + timedelta(days=policy.trusted_device_days) if trust_device else None
        ),
        mfa_pending=mfa_pending,
        authentication_methods_json=["password"],
    )
    session.add(value)
    await session.flush()
    generated = generate_account_token(
        master_secret=master_secret, purpose=AccountTokenPurpose.SESSION_REFRESH
    )
    session.add(
        SessionRefreshToken(
            organization_id=user.organization_id,
            user_id=user.id,
            session_id=value.id,
            token_hash=generated.token_hash,
            expires_at=absolute,
        )
    )
    return value, generated
