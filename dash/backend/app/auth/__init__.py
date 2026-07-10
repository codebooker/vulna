"""Authentication and authorization: password hashing, JWTs, RBAC dependencies."""

from app.auth.dependencies import (
    CurrentUser,
    get_current_user,
    get_user_by_email,
    require_admin,
    require_roles,
)
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.tokens import TokenError, create_access_token, decode_access_token

__all__ = [
    "CurrentUser",
    "TokenError",
    "create_access_token",
    "decode_access_token",
    "get_current_user",
    "get_user_by_email",
    "hash_password",
    "needs_rehash",
    "require_admin",
    "require_roles",
    "verify_password",
]
