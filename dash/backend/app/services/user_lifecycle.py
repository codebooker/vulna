"""Shared invariants and records for user administration."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import AccountStatus, AuthenticationSource, UserRole
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import (
    PasswordResetToken,
    UserInvitation,
    UserLifecycleEvent,
    UserSiteAssignment,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def lifecycle_event(
    session: AsyncSession,
    *,
    user: User,
    event_type: str,
    actor: User | None,
    previous_status: AccountStatus | None = None,
    new_status: AccountStatus | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> UserLifecycleEvent:
    event = UserLifecycleEvent(
        organization_id=user.organization_id,
        user_id=user.id,
        actor_user_id=actor.id if actor else None,
        event_type=event_type,
        previous_status=previous_status,
        new_status=new_status,
        reason=reason,
        metadata_json=metadata or {},
    )
    session.add(event)
    return event


async def active_admin_count(
    session: AsyncSession, organization_id: uuid.UUID, *, exclude_user_id: uuid.UUID | None = None
) -> int:
    stmt = select(func.count()).select_from(User).where(
        User.organization_id == organization_id,
        User.role == UserRole.ADMINISTRATOR,
        User.account_status == AccountStatus.ACTIVE,
        User.is_active.is_(True),
    )
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    return int(await session.scalar(stmt) or 0)


async def validate_site_ids(
    session: AsyncSession, organization_id: uuid.UUID, site_ids: set[uuid.UUID]
) -> None:
    if not site_ids:
        return
    found = set(
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.id.in_(site_ids)
                )
            )
        ).scalars()
    )
    if found != site_ids:
        raise ValueError("One or more sites do not belong to this organization")


async def replace_site_assignments(
    session: AsyncSession,
    *,
    user: User,
    site_ids: set[uuid.UUID],
    actor: User,
) -> None:
    await validate_site_ids(session, user.organization_id, site_ids)
    await session.execute(delete(UserSiteAssignment).where(UserSiteAssignment.user_id == user.id))
    session.add_all(
        [
            UserSiteAssignment(
                organization_id=user.organization_id,
                user_id=user.id,
                site_id=site_id,
                assigned_by_user_id=actor.id,
            )
            for site_id in sorted(site_ids, key=str)
        ]
    )


async def assigned_site_ids(
    session: AsyncSession, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[uuid.UUID]]:
    result: dict[uuid.UUID, list[uuid.UUID]] = {user_id: [] for user_id in user_ids}
    if not user_ids:
        return result
    rows = await session.execute(
        select(UserSiteAssignment.user_id, UserSiteAssignment.site_id)
        .where(UserSiteAssignment.user_id.in_(user_ids))
        .order_by(UserSiteAssignment.created_at.asc())
    )
    for user_id, site_id in rows:
        result[user_id].append(site_id)
    return result


async def revoke_pending_credentials(
    session: AsyncSession, user: User, *, now: datetime | None = None
) -> None:
    """Invalidate every credential type available through Phase 34."""
    now = now or utcnow()
    user.auth_version += 1
    user.recovery_codes_json = []
    user.recovery_codes_generated_at = None
    await session.execute(
        update(UserInvitation)
        .where(
            UserInvitation.user_id == user.id,
            UserInvitation.consumed_at.is_(None),
            UserInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )


def local_login_allowed(user: User) -> bool:
    return (
        user.authentication_source == AuthenticationSource.LOCAL
        and user.account_status == AccountStatus.ACTIVE
        and user.is_active
        and user.hashed_password is not None
    )
