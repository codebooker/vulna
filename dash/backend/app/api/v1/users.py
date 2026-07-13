"""Organization-scoped user lifecycle administration (Phase 34)."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import get_user_by_email, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.audit import AuditEvent
from app.models.enums import (
    AccountStatus,
    AuthenticationSource,
    SiteAccessMode,
    UserRole,
)
from app.models.organization import Organization
from app.models.session import UserSession
from app.models.user import User
from app.models.user_lifecycle import (
    PasswordResetToken,
    UserInvitation,
    UserLifecycleEvent,
)
from app.schemas.common import Page
from app.schemas.session import SessionRead
from app.schemas.user import (
    InvitationIssued,
    LifecycleEventRead,
    LoginHistoryRead,
    PasswordResetIssued,
    UserCreate,
    UserInvitationCreated,
    UserRead,
    UserSiteAccessUpdate,
    UserStatusUpdate,
    UserUpdate,
)
from app.services.account_tokens import AccountTokenPurpose, generate_account_token
from app.services.audit import record_audit
from app.services.sessions import (
    aware,
    is_session_active,
    revoke_session,
    revoke_user_sessions,
    session_policy,
)
from app.services.user_lifecycle import (
    active_admin_count,
    assigned_site_ids,
    lifecycle_event,
    replace_site_assignments,
    revoke_pending_credentials,
    utcnow,
)

router = APIRouter(prefix="/users", tags=["users"])


async def _get_owned_user(
    session: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID
) -> User:
    user = await session.scalar(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _read_user(user: User, site_ids: list[uuid.UUID]) -> UserRead:
    return UserRead(
        id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.account_status == AccountStatus.ACTIVE and user.is_active,
        account_status=user.account_status,
        authentication_source=user.authentication_source,
        site_access_mode=user.site_access_mode,
        site_ids=site_ids,
        mfa_status="planned",
        last_login_at=user.last_login_at,
        invited_at=user.invited_at,
        activated_at=user.activated_at,
        suspended_at=user.suspended_at,
        deactivated_at=user.deactivated_at,
        password_changed_at=user.password_changed_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


async def _read_one(session: AsyncSession, user: User) -> UserRead:
    assignments = await assigned_site_ids(session, [user.id])
    return _read_user(user, assignments[user.id])


def _admin_session_read(value: UserSession, privileged_minutes: int) -> SessionRead:
    return SessionRead(
        id=value.id,
        user_id=value.user_id,
        created_at=value.created_at,
        last_seen_at=value.last_seen_at,
        authenticated_at=value.authenticated_at,
        idle_expires_at=value.idle_expires_at,
        absolute_expires_at=value.absolute_expires_at,
        revoked_at=value.revoked_at,
        revocation_reason=value.revocation_reason,
        device_name=value.device_name,
        source_ip=value.source_ip,
        user_agent=value.user_agent,
        trusted_until=value.trusted_until,
        current=False,
        active=is_session_active(value),
        privileged_until=aware(value.authenticated_at)
        + timedelta(minutes=privileged_minutes),
    )


def _public_url(request: Request, settings: Settings, route: str, secret: str) -> str:
    base = (settings.public_base_url or str(request.base_url)).rstrip("/")
    return f"{base}/#{route}?token={quote(secret, safe='')}"


async def _issue_invitation(
    session: AsyncSession,
    *,
    user: User,
    actor: User,
    settings: Settings,
) -> tuple[str, UserInvitation]:
    now = utcnow()
    await session.execute(
        update(UserInvitation)
        .where(
            UserInvitation.user_id == user.id,
            UserInvitation.consumed_at.is_(None),
            UserInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    generated = generate_account_token(
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.INVITATION,
    )
    invitation = UserInvitation(
        organization_id=user.organization_id,
        user_id=user.id,
        created_by_user_id=actor.id,
        token_hash=generated.token_hash,
        expires_at=now + timedelta(hours=settings.invitation_token_ttl_hours),
        delivery_method="copy_link",
    )
    session.add(invitation)
    return generated.secret, invitation


async def _transition_status(
    session: AsyncSession,
    *,
    user: User,
    actor: User,
    new_status: AccountStatus,
    reason: str,
) -> None:
    previous = user.account_status
    if new_status == previous:
        return
    if user.id == actor.id and new_status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot suspend, lock, or deactivate your own account",
        )
    if (
        user.role == UserRole.ADMINISTRATOR
        and previous == AccountStatus.ACTIVE
        and new_status != AccountStatus.ACTIVE
        and await active_admin_count(
            session, user.organization_id, exclude_user_id=user.id
        )
        == 0
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The last active administrator cannot be deactivated",
        )
    if new_status == AccountStatus.ACTIVE and user.hashed_password is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Passwordless accounts must accept a new invitation before activation",
        )
    now = utcnow()
    if new_status != AccountStatus.ACTIVE:
        await revoke_pending_credentials(session, user, now=now)
    else:
        user.auth_version += 1
    user.set_account_status(new_status, now=now)
    lifecycle_event(
        session,
        user=user,
        actor=actor,
        event_type=f"user.{new_status.value}",
        previous_status=previous,
        new_status=new_status,
        reason=reason,
    )


@router.get("", response_model=Page[UserRead], summary="List users")
async def list_users(
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserRead]:
    total = await session.scalar(
        select(func.count()).select_from(User).where(
            User.organization_id == admin.organization_id
        )
    )
    users = list(
        (
            await session.execute(
                select(User)
                .where(User.organization_id == admin.organization_id)
                .order_by(User.created_at.asc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    assignments = await assigned_site_ids(session, [user.id for user in users])
    return Page[UserRead](
        items=[_read_user(user, assignments[user.id]) for user in users],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{user_id}", response_model=UserRead, summary="Get a user")
async def get_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> UserRead:
    return await _read_one(
        session, await _get_owned_user(session, user_id, admin.organization_id)
    )


@router.post(
    "",
    response_model=UserInvitationCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a user",
)
async def create_user(
    payload: UserCreate,
    request: Request,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserInvitationCreated:
    if payload.password is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Administrators cannot assign permanent passwords; send an invitation instead",
        )
    normalized_email = payload.email.strip().lower()
    if await get_user_by_email(session, normalized_email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that email already exists",
        )

    now = utcnow()
    initial_status = (
        AccountStatus.DEACTIVATED if payload.is_active is False else AccountStatus.INVITED
    )
    user = User(
        organization_id=admin.organization_id,
        email=normalized_email,
        hashed_password=None,
        full_name=payload.full_name,
        role=payload.role,
        is_active=False,
        account_status=initial_status,
        authentication_source=AuthenticationSource.LOCAL,
        site_access_mode=payload.site_access_mode,
        created_by_user_id=admin.id,
    )
    user.set_account_status(initial_status, now=now)
    session.add(user)
    await session.flush()
    try:
        await replace_site_assignments(
            session, user=user, site_ids=set(payload.site_ids), actor=admin
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    secret: str | None = None
    invitation: UserInvitation | None = None
    if initial_status == AccountStatus.INVITED:
        secret, invitation = await _issue_invitation(
            session, user=user, actor=admin, settings=settings
        )
    lifecycle_event(
        session,
        user=user,
        actor=admin,
        event_type="user.invited" if invitation else "user.created_deactivated",
        new_status=initial_status,
        metadata={
            "role": user.role.value,
            "site_access_mode": user.site_access_mode.value,
            "site_ids": sorted(str(value) for value in payload.site_ids),
        },
    )
    record_audit(
        session,
        action="user.invited" if invitation else "user.created_deactivated",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "email": normalized_email,
            "role": user.role.value,
            "delivery_method": "copy_link" if invitation else None,
        },
    )
    await session.flush()
    read = await _read_one(session, user)
    return UserInvitationCreated(
        **read.model_dump(),
        invitation_url=(
            _public_url(request, settings, "accept-invitation", secret) if secret else None
        ),
        invitation_expires_at=invitation.expires_at if invitation else None,
    )


@router.patch("/{user_id}", response_model=UserRead, summary="Update a user")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserRead:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("password") is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Use the expiring password-reset flow",
        )
    changes.pop("password", None)

    if "role" in changes and changes["role"] != user.role:
        if user.id == admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot change your own role",
            )
        if (
            user.role == UserRole.ADMINISTRATOR
            and user.account_status == AccountStatus.ACTIVE
            and await active_admin_count(
                session, user.organization_id, exclude_user_id=user.id
            )
            == 0
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The last active administrator cannot lose that role",
            )
        previous_role = user.role
        user.role = changes.pop("role")
        user.auth_version += 1
        await revoke_user_sessions(session, user.id, reason="role changed")
        lifecycle_event(
            session,
            user=user,
            actor=admin,
            event_type="user.role_changed",
            metadata={"old_role": previous_role.value, "new_role": user.role.value},
        )

    if "is_active" in changes:
        compatibility_status = (
            AccountStatus.ACTIVE if changes.pop("is_active") else AccountStatus.DEACTIVATED
        )
        await _transition_status(
            session,
            user=user,
            actor=admin,
            new_status=compatibility_status,
            reason="Compatibility API update",
        )
    if "full_name" in changes:
        user.full_name = changes.pop("full_name")
    await session.flush()
    record_audit(
        session,
        action="user.updated",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(payload.model_dump(exclude_unset=True))},
    )
    return await _read_one(session, user)


@router.put("/{user_id}/status", response_model=UserRead, summary="Change account status")
async def set_status(
    user_id: uuid.UUID,
    payload: UserStatusUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserRead:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    if payload.status == AccountStatus.INVITED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Use the invitation action to return an account to invited state",
        )
    await _transition_status(
        session,
        user=user,
        actor=admin,
        new_status=payload.status,
        reason=payload.reason,
    )
    record_audit(
        session,
        action=f"user.{payload.status.value}",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"reason": payload.reason},
    )
    await session.flush()
    return await _read_one(session, user)


@router.put("/{user_id}/site-access", response_model=UserRead, summary="Replace site access")
async def set_site_access(
    user_id: uuid.UUID,
    payload: UserSiteAccessUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> UserRead:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    site_ids = set(payload.site_ids) if payload.mode == SiteAccessMode.ASSIGNED else set()
    try:
        await replace_site_assignments(session, user=user, site_ids=site_ids, actor=admin)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    old_mode = user.site_access_mode
    user.site_access_mode = payload.mode
    user.auth_version += 1
    await revoke_user_sessions(session, user.id, reason="site access changed")
    lifecycle_event(
        session,
        user=user,
        actor=admin,
        event_type="user.site_access_changed",
        reason=payload.reason,
        metadata={
            "old_mode": old_mode.value,
            "new_mode": payload.mode.value,
            "site_ids": sorted(str(value) for value in site_ids),
        },
    )
    record_audit(
        session,
        action="user.site_access_changed",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "mode": payload.mode.value,
            "site_ids": sorted(str(value) for value in site_ids),
        },
    )
    await session.flush()
    return await _read_one(session, user)


@router.post(
    "/{user_id}/invitation",
    response_model=InvitationIssued,
    summary="Issue or replace an invitation",
)
async def issue_invitation(
    user_id: uuid.UUID,
    request: Request,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> InvitationIssued:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    if user.authentication_source != AuthenticationSource.LOCAL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Externally managed users cannot receive local invitations",
        )
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot replace your own active credentials with an invitation",
        )
    if (
        user.role == UserRole.ADMINISTRATOR
        and user.account_status == AccountStatus.ACTIVE
        and await active_admin_count(
            session, user.organization_id, exclude_user_id=user.id
        )
        == 0
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The last active administrator cannot be returned to invited state",
        )
    now = utcnow()
    previous = user.account_status
    await revoke_pending_credentials(session, user, now=now)
    user.hashed_password = None
    user.password_changed_at = None
    user.set_account_status(AccountStatus.INVITED, now=now)
    secret, invitation = await _issue_invitation(
        session, user=user, actor=admin, settings=settings
    )
    lifecycle_event(
        session,
        user=user,
        actor=admin,
        event_type="user.invitation_issued",
        previous_status=previous,
        new_status=AccountStatus.INVITED,
    )
    record_audit(
        session,
        action="user.invitation_issued",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"delivery_method": "copy_link"},
    )
    await session.flush()
    return InvitationIssued(
        user=await _read_one(session, user),
        invitation_url=_public_url(
            request, settings, "accept-invitation", secret
        ),
        expires_at=invitation.expires_at,
    )


@router.post(
    "/{user_id}/password-reset",
    response_model=PasswordResetIssued,
    summary="Issue an expiring password-reset link",
)
async def issue_password_reset(
    user_id: uuid.UUID,
    request: Request,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> PasswordResetIssued:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    if (
        user.authentication_source != AuthenticationSource.LOCAL
        or user.account_status != AccountStatus.ACTIVE
        or user.hashed_password is None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only active local accounts can receive a password-reset link",
        )
    now = utcnow()
    await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    generated = generate_account_token(
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.PASSWORD_RESET,
    )
    token = PasswordResetToken(
        organization_id=user.organization_id,
        user_id=user.id,
        created_by_user_id=admin.id,
        token_hash=generated.token_hash,
        expires_at=now + timedelta(minutes=settings.password_reset_token_ttl_minutes),
    )
    session.add(token)
    lifecycle_event(
        session,
        user=user,
        actor=admin,
        event_type="user.password_reset_issued",
    )
    record_audit(
        session,
        action="user.password_reset_issued",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.flush()
    return PasswordResetIssued(
        user_id=user.id,
        reset_url=_public_url(request, settings, "reset-password", generated.secret),
        expires_at=token.expires_at,
    )


@router.get(
    "/{user_id}/sessions",
    response_model=list[SessionRead],
    summary="List a user's sessions",
)
async def list_user_sessions(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SessionRead]:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    org = await session.get(Organization, admin.organization_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    rows = list(
        (
            await session.execute(
                select(UserSession)
                .where(
                    UserSession.user_id == user.id,
                    UserSession.organization_id == admin.organization_id,
                )
                .order_by(UserSession.last_seen_at.desc())
            )
        ).scalars()
    )
    privileged_minutes = session_policy(org).privileged_window_minutes
    return [_admin_session_read(value, privileged_minutes) for value in rows]


@router.delete(
    "/{user_id}/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Administratively revoke a user session",
)
async def revoke_user_session(
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    reason: Annotated[str, Query(min_length=1, max_length=255)] = "administrator revoked session",
) -> None:
    await _get_owned_user(session, user_id, admin.organization_id)
    value = await session.scalar(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.organization_id == admin.organization_id,
        )
    )
    if value is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    await revoke_session(session, value, reason=reason)
    record_audit(
        session,
        action="auth.session_revoked_by_admin",
        actor=admin,
        target_type="session",
        target_id=value.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"user_id": str(user_id), "reason": reason},
    )


@router.get(
    "/{user_id}/lifecycle",
    response_model=Page[LifecycleEventRead],
    summary="User lifecycle history",
)
async def lifecycle_history(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[LifecycleEventRead]:
    await _get_owned_user(session, user_id, admin.organization_id)
    filters = (
        UserLifecycleEvent.organization_id == admin.organization_id,
        UserLifecycleEvent.user_id == user_id,
    )
    total = await session.scalar(
        select(func.count()).select_from(UserLifecycleEvent).where(*filters)
    )
    events = (
        (
            await session.execute(
                select(UserLifecycleEvent)
                .where(*filters)
                .order_by(UserLifecycleEvent.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[LifecycleEventRead](
        items=[LifecycleEventRead.model_validate(event) for event in events],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{user_id}/login-history",
    response_model=Page[LoginHistoryRead],
    summary="User login history",
)
async def login_history(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[LoginHistoryRead]:
    await _get_owned_user(session, user_id, admin.organization_id)
    actions = (
        "auth.login_succeeded",
        "auth.login_failed",
        "auth.login_denied_inactive",
    )
    filters = (
        AuditEvent.organization_id == admin.organization_id,
        AuditEvent.target_type == "user",
        AuditEvent.target_id == str(user_id),
        AuditEvent.action.in_(actions),
    )
    total = await session.scalar(
        select(func.count()).select_from(AuditEvent).where(*filters)
    )
    events = (
        (
            await session.execute(
                select(AuditEvent)
                .where(*filters)
                .order_by(AuditEvent.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    outcomes = {
        "auth.login_succeeded": "succeeded",
        "auth.login_failed": "failed",
        "auth.login_denied_inactive": "denied",
    }
    return Page[LoginHistoryRead](
        items=[
            LoginHistoryRead(
                id=event.id,
                outcome=outcomes[event.action],
                source_ip=event.source_ip,
                user_agent=event.user_agent,
                occurred_at=event.created_at,
            )
            for event in events
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Deactivate a user (compatibility endpoint)",
)
async def delete_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    user = await _get_owned_user(session, user_id, admin.organization_id)
    await _transition_status(
        session,
        user=user,
        actor=admin,
        new_status=AccountStatus.DEACTIVATED,
        reason="Compatibility DELETE request; record retained for attribution",
    )
    record_audit(
        session,
        action="user.deactivated",
        actor=admin,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"compatibility_delete": True, "email": user.email},
    )
