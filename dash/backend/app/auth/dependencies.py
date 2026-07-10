"""Authentication and authorization dependencies for FastAPI routes."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import TokenError, decode_access_token
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
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

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXCEPTION
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


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
