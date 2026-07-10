"""Authentication endpoints: login and current-user profile."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, get_user_by_email
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.tokens import create_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ActorType
from app.schemas.auth import CurrentUserResponse, LoginRequest, TokenResponse
from app.services.audit import record_audit

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

    if not user.is_active:
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
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


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
