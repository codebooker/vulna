"""Authentication endpoints: login and current-user profile."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentIdentity, get_user_by_email
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.tokens import create_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import AccountStatus, ActorType, SsoPolicyMode
from app.models.organization import Organization
from app.models.session import SessionRefreshToken, UserSession
from app.models.user import User
from app.models.user_lifecycle import PasswordResetToken, UserInvitation
from app.schemas.auth import CurrentUserResponse, LoginRequest, TokenResponse
from app.schemas.session import (
    ReauthenticateRequest,
    ReauthenticationResult,
    SessionRead,
)
from app.schemas.user import AcceptInvitationRequest, CompletePasswordResetRequest
from app.services import auth_throttle, mfa, sso
from app.services.account_tokens import (
    AccountTokenPurpose,
    generate_account_token,
    hash_account_token,
)
from app.services.audit import record_audit
from app.services.sessions import (
    ACCESS_TOKEN_MINUTES,
    REFRESH_COOKIE_NAME,
    aware,
    create_session,
    is_session_active,
    revoke_session,
    revoke_user_sessions,
    session_policy,
    touch_session,
)
from app.services.user_lifecycle import (
    lifecycle_event,
    local_login_allowed,
    revoke_pending_credentials,
    utcnow,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh_cookie(
    response: Response,
    settings: Settings,
    secret: str,
    expires_at: datetime,
) -> None:
    max_age = max(0, int((aware(expires_at) - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        secret,
        max_age=max_age,
        expires=aware(expires_at),
        path="/api/v1/auth",
        secure=settings.env == "production",
        httponly=True,
        samesite="lax",
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        secure=settings.env == "production",
        httponly=True,
        samesite="lax",
    )


def _invalid_refresh(settings: Settings) -> HTTPException:
    response = Response()
    _clear_refresh_cookie(response, settings)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token is invalid, expired, or already used",
        headers={"Set-Cookie": response.headers["set-cookie"]},
    )


def _session_read(
    value: UserSession,
    *,
    current_session_id: uuid.UUID | None,
    privileged_window_minutes: int,
) -> SessionRead:
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
        current=value.id == current_session_id,
        active=is_session_active(value),
        privileged_until=aware(value.authenticated_at)
        + timedelta(minutes=privileged_window_minutes),
        mfa_pending=value.mfa_pending,
        mfa_authenticated_at=value.mfa_authenticated_at,
        authentication_methods=list(value.authentication_methods_json or []),
    )


@router.post("/login", response_model=TokenResponse, summary="Obtain an access token")
async def login(
    payload: LoginRequest,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TokenResponse:
    """Authenticate with email and password and return a JWT access token.

    Both successful and failed attempts are recorded in the audit log. The same
    generic error is returned whether the email is unknown or the password is
    wrong, to avoid disclosing which accounts exist.
    """
    retry_after = await auth_throttle.retry_after(
        session, payload.email, context.source_ip
    )
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Invalid email or password",
            headers={"Retry-After": str(retry_after)},
        )

    user = await get_user_by_email(session, payload.email)
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )

    if user is None or not verify_password(payload.password, user.hashed_password):
        delay = await auth_throttle.record_failure(
            session, payload.email, context.source_ip
        )
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
        if user is not None and delay:
            await mfa.emit_security_notification(
                session,
                user,
                title="Repeated sign-in failures",
                summary="Vulna temporarily throttled repeated failed sign-in attempts.",
            )
        # Persist the audit record even though the request fails with 401.
        await session.commit()
        raise invalid

    local_account_allowed = local_login_allowed(user)
    sso_policy_allowed = (
        await sso.local_login_permitted(session, user) if local_account_allowed else False
    )
    if not local_account_allowed or not sso_policy_allowed:
        await auth_throttle.record_failure(session, payload.email, context.source_ip)
        record_audit(
            session,
            action=(
                "auth.login_denied_sso_enforced"
                if local_account_allowed
                else "auth.login_denied_inactive"
            ),
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

    now = datetime.now(UTC)
    user.last_login_at = now
    org = await session.get(Organization, user.organization_id)
    if org is None:
        raise invalid
    policy = await mfa.get_policy(session, user.organization_id)
    enrolled_methods = await mfa.methods(session, user)
    strong_methods = [method for method in enrolled_methods if method in {"totp", "webauthn"}]
    enrollment_required = mfa.required_for_user(policy, user) and not strong_methods
    if enrollment_required and user.mfa_grace_expires_at is None:
        user.mfa_grace_expires_at = now + timedelta(days=policy.grace_period_days)
    grace_expired = bool(
        enrollment_required
        and user.mfa_grace_expires_at
        and aware(user.mfa_grace_expires_at) <= now
    )
    mfa_pending = bool(strong_methods) or grace_expired
    user_session, refresh = await create_session(
        session,
        user=user,
        org=org,
        master_secret=settings.require_secret_key(),
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        device_name=payload.device_name,
        trust_device=payload.trust_device,
        mfa_pending=mfa_pending,
        now=now,
    )
    await auth_throttle.reset_success(session, user.email, context.source_ip)
    record_audit(
        session,
        action="auth.password_verified" if mfa_pending else "auth.login_succeeded",
        actor=user,
        organization_id=user.organization_id,
        target_type="user",
        target_id=user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"session_id": str(user_session.id), "mfa_pending": mfa_pending},
    )
    sso_policy = await sso.get_policy(session, user.organization_id)
    if sso_policy.mode == SsoPolicyMode.ENFORCED and user.is_break_glass:
        record_audit(
            session,
            action="auth.break_glass_login",
            actor=user,
            organization_id=user.organization_id,
            target_type="session",
            target_id=user_session.id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
        )
        await mfa.emit_security_notification(
            session,
            user,
            title="Break-glass sign-in used",
            summary="A protected local administrator signed in while SSO enforcement was active.",
            severity="critical",
        )

    token = create_access_token(
        settings,
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
        session_id=user_session.id,
        authenticated_at=user_session.authenticated_at,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_MINUTES),
    )
    _set_refresh_cookie(response, settings, refresh.secret, user_session.absolute_expires_at)
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        session_id=user_session.id,
        mfa_required=mfa_pending,
        mfa_enrollment_required=enrollment_required,
        mfa_methods=(
            strong_methods
            + (["recovery_code"] if "recovery_code" in enrolled_methods else [])
        ),
        mfa_grace_expires_at=user.mfa_grace_expires_at,
    )


@router.post("/refresh", response_model=TokenResponse, summary="Rotate a refresh token")
async def refresh_session(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> TokenResponse:
    secret = request.cookies.get(REFRESH_COOKIE_NAME)
    if not secret:
        raise _invalid_refresh(settings)
    token_hash = hash_account_token(
        secret,
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.SESSION_REFRESH,
    )
    stored = await session.scalar(
        select(SessionRefreshToken)
        .where(SessionRefreshToken.token_hash == token_hash)
        .with_for_update()
    )
    if stored is None:
        raise _invalid_refresh(settings)

    now = datetime.now(UTC)
    user_session = await session.get(UserSession, stored.session_id)
    user = await session.get(User, stored.user_id)
    replayed = stored.used_at is not None or stored.revoked_at is not None
    expired = aware(stored.expires_at) <= now
    session_invalid = (
        user_session is None
        or user is None
        or user.account_status != AccountStatus.ACTIVE
        or not user.is_active
        or user.organization_id != stored.organization_id
        or user_session.user_id != stored.user_id
        or user_session.organization_id != stored.organization_id
        or user_session.auth_version != user.auth_version
        or user_session.mfa_pending
        or not is_session_active(user_session, now=now)
    )
    if replayed or expired or session_invalid:
        if user_session is not None:
            await revoke_session(
                session,
                user_session,
                reason=("refresh token reuse detected" if replayed else "session expired"),
                now=now,
            )
        record_audit(
            session,
            action=("auth.refresh_reuse_detected" if replayed else "auth.refresh_denied"),
            actor=user,
            actor_type=ActorType.USER if user else ActorType.SYSTEM,
            organization_id=stored.organization_id,
            target_type="session",
            target_id=stored.session_id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
        )
        if replayed and user is not None:
            await mfa.emit_security_notification(
                session,
                user,
                title="Refresh-token reuse detected",
                summary="Vulna revoked a session after an already-used refresh token reappeared.",
                severity="critical",
            )
        # Persist family revocation even though the response is an error.
        await session.commit()
        raise _invalid_refresh(settings)

    if user_session is None or user is None:  # narrowed after the guarded branch above
        raise _invalid_refresh(settings)
    stored.used_at = now
    touch_session(user_session, now=now)
    generated = generate_account_token(
        master_secret=settings.require_secret_key(),
        purpose=AccountTokenPurpose.SESSION_REFRESH,
    )
    replacement = SessionRefreshToken(
        organization_id=user.organization_id,
        user_id=user.id,
        session_id=user_session.id,
        token_hash=generated.token_hash,
        expires_at=user_session.absolute_expires_at,
    )
    session.add(replacement)
    await session.flush()
    stored.replaced_by_token_id = replacement.id
    record_audit(
        session,
        action="auth.session_refreshed",
        actor=user,
        target_type="session",
        target_id=user_session.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    _set_refresh_cookie(
        response, settings, generated.secret, user_session.absolute_expires_at
    )
    access = create_access_token(
        settings,
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
        session_id=user_session.id,
        authenticated_at=user_session.authenticated_at,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_MINUTES),
    )
    return TokenResponse(
        access_token=access,
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        session_id=user_session.id,
    )


@router.post(
    "/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke the current session"
)
async def logout_session(
    response: Response,
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    if identity.session is not None:
        await revoke_session(session, identity.session, reason="user logout")
        record_audit(
            session,
            action="auth.session_revoked",
            actor=identity.user,
            target_type="session",
            target_id=identity.session.id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"reason": "user logout"},
        )
    _clear_refresh_cookie(response, settings)


@router.post(
    "/logout-all", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke all sessions"
)
async def logout_all_sessions(
    response: Response,
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    count = await revoke_user_sessions(
        session, identity.user.id, reason="user requested logout from all devices"
    )
    record_audit(
        session,
        action="auth.sessions_revoked_all",
        actor=identity.user,
        target_type="user",
        target_id=identity.user.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"session_count": count},
    )
    _clear_refresh_cookie(response, settings)


@router.get("/sessions", response_model=list[SessionRead], summary="List my sessions")
async def list_my_sessions(
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SessionRead]:
    org = await session.get(Organization, identity.user.organization_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    policy = session_policy(org)
    rows = list(
        (
            await session.execute(
                select(UserSession)
                .where(
                    UserSession.user_id == identity.user.id,
                    UserSession.organization_id == identity.user.organization_id,
                )
                .order_by(UserSession.last_seen_at.desc())
            )
        ).scalars()
    )
    current_id = identity.session.id if identity.session else None
    return [
        _session_read(
            value,
            current_session_id=current_id,
            privileged_window_minutes=policy.privileged_window_minutes,
        )
        for value in rows
    ]


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one of my sessions",
)
async def revoke_my_session(
    session_id: uuid.UUID,
    response: Response,
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    value = await session.scalar(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == identity.user.id,
            UserSession.organization_id == identity.user.organization_id,
        )
    )
    if value is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    await revoke_session(session, value, reason="user revoked device session")
    if identity.session is not None and identity.session.id == value.id:
        _clear_refresh_cookie(response, settings)
    record_audit(
        session,
        action="auth.session_revoked",
        actor=identity.user,
        target_type="session",
        target_id=value.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"reason": "user revoked device session"},
    )


@router.post(
    "/reauthenticate",
    response_model=ReauthenticationResult,
    summary="Refresh the privileged authentication window",
)
async def reauthenticate(
    payload: ReauthenticateRequest,
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReauthenticationResult:
    if identity.session is None or not verify_password(
        payload.password, identity.user.hashed_password
    ):
        record_audit(
            session,
            action="auth.reauthentication_failed",
            actor=identity.user,
            target_type="session",
            target_id=identity.session.id if identity.session else None,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reauthentication failed",
        )
    now = datetime.now(UTC)
    identity.session.authenticated_at = now
    org = await session.get(Organization, identity.user.organization_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    privileged_until = now + timedelta(
        minutes=session_policy(org).privileged_window_minutes
    )
    record_audit(
        session,
        action="auth.reauthentication_succeeded",
        actor=identity.user,
        target_type="session",
        target_id=identity.session.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"privileged_until": privileged_until.isoformat()},
    )
    return ReauthenticationResult(
        authenticated_at=now, privileged_until=privileged_until
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
async def read_me(
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CurrentUserResponse:
    """Return the authenticated user's own profile."""
    current_user = identity.user
    enrolled = set(await mfa.methods(session, current_user)) & {"totp", "webauthn"}
    return CurrentUserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        organization_id=current_user.organization_id,
        is_active=current_user.is_active,
        mfa_status="enrolled" if enrolled else "not_enrolled",
        mfa_grace_expires_at=current_user.mfa_grace_expires_at,
        authentication_source=current_user.authentication_source.value,
        is_break_glass=current_user.is_break_glass,
    )
