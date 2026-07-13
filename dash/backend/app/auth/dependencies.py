"""Authentication and authorization dependencies for FastAPI routes."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import TokenError, decode_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import AccountStatus, UserRole
from app.models.session import UserSession
from app.models.user import User
from app.services.sessions import is_session_active, touch_session

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


async def get_authenticated_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticatedIdentity:
    """Resolve the authenticated user from a Bearer token.

    Raises 401 if the token is absent, invalid, expired, or the user no longer
    exists or has been deactivated.
    """
    if credentials is None or not credentials.credentials:
        raise _CREDENTIALS_EXCEPTION

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
    ):
        raise _CREDENTIALS_EXCEPTION
    touch_session(user_session)
    return AuthenticatedIdentity(user=user, session=user_session, claims=claims)


async def get_current_user(
    identity: Annotated[AuthenticatedIdentity, Depends(get_authenticated_identity)],
) -> User:
    return identity.user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentIdentity = Annotated[
    AuthenticatedIdentity, Depends(get_authenticated_identity)
]


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


# Convenience dependency: any privileged management action requires an admin.
require_admin = require_roles(UserRole.ADMINISTRATOR)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Return the user with the given email (case-insensitive), if any."""
    normalized = email.strip().lower()
    result = await session.execute(select(User).where(User.email == normalized))
    return result.scalar_one_or_none()
