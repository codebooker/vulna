"""Authentication and authorization: password hashing, JWTs, RBAC dependencies."""

from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentIdentity,
    CurrentUser,
    get_authenticated_identity,
    get_current_user,
    get_user_by_email,
    require_admin,
    require_roles,
)
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.site_scope import (
    accessible_site_ids,
    can_access_site,
    get_accessible_site,
    has_all_site_access,
    optional_site_scope_clause,
    require_site_access,
    site_scope_clause,
)
from app.auth.tokens import TokenError, create_access_token, decode_access_token

__all__ = [
    "accessible_site_ids",
    "AuthenticatedIdentity",
    "CurrentIdentity",
    "CurrentUser",
    "TokenError",
    "create_access_token",
    "decode_access_token",
    "get_current_user",
    "get_authenticated_identity",
    "get_user_by_email",
    "hash_password",
    "needs_rehash",
    "require_admin",
    "require_roles",
    "can_access_site",
    "get_accessible_site",
    "has_all_site_access",
    "optional_site_scope_clause",
    "require_site_access",
    "site_scope_clause",
    "verify_password",
]
