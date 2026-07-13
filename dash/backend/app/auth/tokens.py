"""JWT access-token creation and verification.

Tokens are signed with the application secret (``VULNA_SECRET_KEY``) using
HS256. The token carries the subject (user id), the user's role, and their
organization so authorization checks avoid a database round-trip for the common
case, while still allowing a lookup when needed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.config import Settings


class TokenError(Exception):
    """Raised when a token is missing, malformed, or expired."""


def create_access_token(
    settings: Settings,
    *,
    user_id: uuid.UUID,
    role: str,
    organization_id: uuid.UUID,
    auth_version: int = 1,
    session_id: uuid.UUID | None = None,
    authenticated_at: datetime | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token for a user."""
    now = datetime.now(UTC)
    expire = now + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "org": str(organization_id),
        "ver": auth_version,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    if session_id is not None:
        payload["sid"] = str(session_id)
    if authenticated_at is not None:
        payload["auth_time"] = int(authenticated_at.timestamp())
    return jwt.encode(payload, settings.require_secret_key(), algorithm=settings.jwt_algorithm)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token, returning its claims.

    Raises :class:`TokenError` if the token is invalid or expired.
    """
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.require_secret_key(),
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:  # invalid signature, expiry, malformed, etc.
        raise TokenError(str(exc)) from exc
    if claims.get("typ") != "access":
        raise TokenError("Unexpected token type")
    return claims
