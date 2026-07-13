"""Authentication and authorization dependencies for FastAPI routes."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.permission_catalog import validate_permission_keys
from app.auth.tokens import TokenError, decode_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.authorization import ApiToken
from app.models.enums import AccountStatus, UserRole
from app.models.organization import Organization
from app.models.session import UserSession
from app.models.user import User
from app.services import authorization
from app.services.sessions import aware, is_session_active, session_policy, touch_session

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass(frozen=True)
class AuthenticatedIdentity:
    user: User
    session: UserSession | None
    claims: dict[str, object]
    api_token: ApiToken | None = None


async def get_authenticated_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AuthenticatedIdentity:
    return await _resolve_authenticated_identity(
        credentials, session, settings, context=context, allow_mfa_pending=False
    )


async def get_mfa_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AuthenticatedIdentity:
    """Resolve a session for MFA completion, including a pending MFA session."""
    return await _resolve_authenticated_identity(
        credentials, session, settings, context=context, allow_mfa_pending=True
    )


async def _resolve_authenticated_identity(
    credentials: HTTPAuthorizationCredentials | None,
    session: AsyncSession,
    settings: Settings,
    *,
    context: RequestContext,
    allow_mfa_pending: bool,
) -> AuthenticatedIdentity:
    """Resolve the authenticated user from a Bearer token.

    Raises 401 if the token is absent, invalid, expired, or the user no longer
    exists or has been deactivated.
    """
    if credentials is None or not credentials.credentials:
        raise _CREDENTIALS_EXCEPTION

    if credentials.credentials.startswith("vapi_"):
        try:
            principal, api_token = await authorization.authenticate_api_token(
                session, credentials.credentials, context.source_ip
            )
        except authorization.ApiTokenError as exc:
            raise _CREDENTIALS_EXCEPTION from exc
        return AuthenticatedIdentity(
            # Existing handlers consume a user-shaped principal. ServiceAccount
            # intentionally implements the shared id/org/role surface.
            user=cast(User, principal),
            session=None,
            claims={
                "sub": str(principal.id),
                "org": str(principal.organization_id),
                "credential_type": "api_token",
                "token_id": str(api_token.id),
            },
            api_token=api_token,
        )

    try:
        claims = decode_access_token(settings, credentials.credentials)
    except TokenError as exc:
        raise _CREDENTIALS_EXCEPTION from exc

    subject = claims.get("sub")
    if not subject:
        raise _CREDENTIALS_EXCEPTION
    try:
        user_id = uuid.UUID(subject)
    except (ValueError, TypeError) as exc:
        raise _CREDENTIALS_EXCEPTION from exc
    try:
        token_auth_version = int(claims.get("ver", 1))
    except (TypeError, ValueError) as exc:
        raise _CREDENTIALS_EXCEPTION from exc

    user = await session.get(User, user_id)
    if (
        user is None
        or not user.is_active
        or user.account_status != AccountStatus.ACTIVE
        or str(claims.get("org")) != str(user.organization_id)
        or token_auth_version != user.auth_version
    ):
        raise _CREDENTIALS_EXCEPTION

    session_id_claim = claims.get("sid")
    if session_id_claim is None:
        # Existing unit fixtures mint direct JWTs. Runtime-issued tokens always
        # carry a session id; every non-test environment rejects stateless JWTs.
        if settings.env != "test":
            raise _CREDENTIALS_EXCEPTION
        return AuthenticatedIdentity(user=user, session=None, claims=claims)
    try:
        session_id = uuid.UUID(str(session_id_claim))
    except (TypeError, ValueError) as exc:
        raise _CREDENTIALS_EXCEPTION from exc
    user_session = await session.scalar(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user.id,
            UserSession.organization_id == user.organization_id,
        )
    )
    if (
        user_session is None
        or user_session.auth_version != user.auth_version
        or not is_session_active(user_session)
        or (user_session.mfa_pending and not allow_mfa_pending)
    ):
        raise _CREDENTIALS_EXCEPTION
    touch_session(user_session)
    return AuthenticatedIdentity(user=user, session=user_session, claims=claims)


async def get_current_user(
    identity: Annotated[AuthenticatedIdentity, Depends(get_authenticated_identity)],
) -> User:
    return identity.user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentIdentity = Annotated[AuthenticatedIdentity, Depends(get_authenticated_identity)]
MfaIdentity = Annotated[AuthenticatedIdentity, Depends(get_mfa_identity)]


async def require_recent_step_up(
    identity: CurrentIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticatedIdentity:
    """Require a recent password or MFA assertion for a high-risk operation."""
    if identity.api_token is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "interactive_step_up_required",
                "message": "This operation requires an interactive session",
            },
        )
    if identity.session is None:
        # Legacy stateless test fixtures remain usable only inside the test
        # environment. Runtime environments rejected them in Phase 35.
        if settings.env == "test":
            return identity
        raise _CREDENTIALS_EXCEPTION
    org = await session.get(Organization, identity.user.organization_id)
    if org is None:
        raise _CREDENTIALS_EXCEPTION
    window = session_policy(org).privileged_window_minutes
    strongest = aware(identity.session.authenticated_at)
    if identity.session.mfa_authenticated_at is not None:
        strongest = max(strongest, aware(identity.session.mfa_authenticated_at))
    if datetime.now(UTC) - strongest > timedelta(minutes=window):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "step_up_required",
                "message": "Recent authentication is required for this operation",
            },
        )
    return identity


StepUpIdentity = Annotated[AuthenticatedIdentity, Depends(require_recent_step_up)]


def require_roles(*roles: UserRole) -> Callable[[User], Awaitable[User]]:
    """Return a dependency that requires the current user to hold one of ``roles``.

    Unauthenticated requests receive 401 (from :func:`get_current_user`); an
    authenticated user without a permitted role receives 403.
    """
    allowed = set(roles)

    async def _dependency(current_user: CurrentUser) -> User:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return _dependency


def require_permission(permission_key: str) -> Callable[..., Awaitable[User]]:
    """Return a dependency that evaluates database grants for one permission."""
    validate_permission_keys({permission_key})

    async def _dependency(
        identity: CurrentIdentity,
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> User:
        if not await authorization.has_permission(session, identity.user, permission_key):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return identity.user

    return _dependency


def require_any_permission(*permission_keys: str) -> Callable[..., Awaitable[User]]:
    """Return a dependency that accepts any one code-defined permission."""
    validate_permission_keys(set(permission_keys))

    async def _dependency(
        identity: CurrentIdentity,
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> User:
        effective = await authorization.effective_permissions(session, identity.user)
        if not effective.intersection(permission_keys):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return identity.user

    return _dependency


def require_step_up_permission(
    permission_key: str,
) -> Callable[..., Awaitable[AuthenticatedIdentity]]:
    """Require both an effective permission and a recent interactive assertion."""
    validate_permission_keys({permission_key})

    async def _dependency(
        identity: StepUpIdentity,
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> AuthenticatedIdentity:
        if not await authorization.has_permission(session, identity.user, permission_key):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return identity

    return _dependency


# Deprecated API compatibility only. Phase 39 routes use domain permissions.
require_admin = require_permission("system.admin")


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Return the user with the given email (case-insensitive), if any."""
    normalized = email.strip().lower()
    result = await session.execute(select(User).where(User.email == normalized))
    return result.scalar_one_or_none()
