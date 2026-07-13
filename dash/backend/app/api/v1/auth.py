"""Authentication endpoints: login and current-user profile."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, get_user_by_email
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.tokens import create_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import AccountStatus, ActorType
from app.models.user import User
from app.models.user_lifecycle import PasswordResetToken, UserInvitation
from app.schemas.auth import CurrentUserResponse, LoginRequest, TokenResponse
from app.schemas.user import AcceptInvitationRequest, CompletePasswordResetRequest
from app.services.account_tokens import AccountTokenPurpose, hash_account_token
from app.services.audit import record_audit
from app.services.user_lifecycle import (
    lifecycle_event,
    local_login_allowed,
    revoke_pending_credentials,
    utcnow,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, summary="Obtain an access token")
async def login(
    payload: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TokenResponse:
    """Authenticate with email and password and return a JWT access token.

    Both successful and failed attempts are recorded in the audit log. The same
    generic error is returned whether the email is unknown or the password is
    wrong, to avoid disclosing which accounts exist.
    """
    user = await get_user_by_email(session, payload.email)
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )

    if user is None or not verify_password(payload.password, user.hashed_password):
        record_audit(
            session,
            action="auth.login_failed",
            actor=user,
            actor_type=ActorType.USER if user else ActorType.SYSTEM,
            organization_id=user.organization_id if user else None,
            target_type="user",
            target_id=user.id if user else None,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"email": payload.email},
        )
        # Persist the audit record even though the request fails with 401.
        await session.commit()
        raise invalid

    if not local_login_allowed(user):
        record_audit(
            session,
            action="auth.login_denied_inactive",
            actor=user,
            organization_id=user.organization_id,
            target_type="user",
            target_id=user.id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
        )
        await session.commit()
        raise invalid

    # Opportunistically upgrade the stored hash if parameters have changed.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)

    user.last_login_at = datetime.now(UTC)
    record_audit(
        session,
        action="auth.login_succeeded",
        actor=user,
        organization_id=user.organization_id,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )

    token = create_access_token(
        settings,
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


def _not_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value > now


@router.post("/invitations/accept", summary="Accept a one-time user invitation")
async def accept_invitation(
    payload: AcceptInvitationRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, str]:
    """Set the invited user's own password and activate the preserved account."""
    token_hash = hash_account_token(
        payload.token,
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.INVITATION,
    )
    invitation = await session.scalar(
        select(UserInvitation)
        .where(UserInvitation.token_hash == token_hash)
        .with_for_update()
    )
    now = utcnow()
    if (
        invitation is None
        or invitation.consumed_at is not None
        or invitation.revoked_at is not None
        or not _not_expired(invitation.expires_at, now)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation is invalid, expired, or already used",
        )
    user = await session.get(User, invitation.user_id)
    if (
        user is None
        or user.organization_id != invitation.organization_id
        or user.account_status != AccountStatus.INVITED
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation is invalid, expired, or already used",
        )
    invitation.consumed_at = now
    await revoke_pending_credentials(session, user, now=now)
    user.hashed_password = hash_password(payload.password)
    user.password_changed_at = now
    if payload.full_name is not None:
        user.full_name = payload.full_name
    previous = user.account_status
    user.set_account_status(AccountStatus.ACTIVE, now=now)
    lifecycle_event(
        session,
        user=user,
        actor=user,
        event_type="user.invitation_accepted",
        previous_status=previous,
        new_status=AccountStatus.ACTIVE,
    )
    record_audit(
        session,
        action="user.invitation_accepted",
        actor=user,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    return {"status": "accepted"}


@router.post("/password-resets/complete", summary="Complete a one-time password reset")
async def complete_password_reset(
    payload: CompletePasswordResetRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, str]:
    token_hash = hash_account_token(
        payload.token,
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.PASSWORD_RESET,
    )
    reset = await session.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .with_for_update()
    )
    now = utcnow()
    if (
        reset is None
        or reset.consumed_at is not None
        or reset.revoked_at is not None
        or not _not_expired(reset.expires_at, now)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password-reset link is invalid, expired, or already used",
        )
    user = await session.get(User, reset.user_id)
    if (
        user is None
        or user.organization_id != reset.organization_id
        or not local_login_allowed(user)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password-reset link is invalid, expired, or already used",
        )
    reset.consumed_at = now
    await revoke_pending_credentials(session, user, now=now)
    user.hashed_password = hash_password(payload.password)
    user.password_changed_at = now
    lifecycle_event(
        session,
        user=user,
        actor=user,
        event_type="user.password_reset_completed",
    )
    record_audit(
        session,
        action="user.password_reset_completed",
        actor=user,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    return {"status": "password_updated"}


@router.get("/me", response_model=CurrentUserResponse, summary="Current user profile")
async def read_me(current_user: CurrentUser) -> CurrentUserResponse:
    """Return the authenticated user's own profile."""
    return CurrentUserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        organization_id=current_user.organization_id,
        is_active=current_user.is_active,
    )
