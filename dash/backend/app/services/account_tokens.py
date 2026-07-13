"""Purpose-bound one-time tokens for local account lifecycle operations.

Only a keyed digest is persisted. Invitation and password-reset digests use
different HKDF contexts so a token from one protocol can never authenticate to
the other, even if a caller accidentally reuses a raw value.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AccountTokenPurpose(StrEnum):
    INVITATION = "invitation"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - protocol purpose, not a secret
    SESSION_REFRESH = "session_refresh"  # noqa: S105 - protocol purpose


_PREFIX = {
    AccountTokenPurpose.INVITATION: "vui",
    AccountTokenPurpose.PASSWORD_RESET: "vpr",
    AccountTokenPurpose.SESSION_REFRESH: "vsr",
}
_CONTEXT = {
    AccountTokenPurpose.INVITATION: b"vulna-user-invitation-token-v1",
    AccountTokenPurpose.PASSWORD_RESET: b"vulna-password-reset-token-v1",
    AccountTokenPurpose.SESSION_REFRESH: b"vulna-session-refresh-token-v1",
}


@dataclass(frozen=True)
class GeneratedAccountToken:
    secret: str
    token_hash: str


@lru_cache(maxsize=16)
def _key(master_secret: str, purpose: AccountTokenPurpose) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_CONTEXT[purpose],
    ).derive(master_secret.encode("utf-8"))


def hash_account_token(
    secret: str, *, master_secret: str, purpose: AccountTokenPurpose
) -> str:
    """Return the purpose-bound HMAC digest stored in the database."""
    return hmac.new(
        _key(master_secret, purpose), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def generate_account_token(
    *, master_secret: str, purpose: AccountTokenPurpose
) -> GeneratedAccountToken:
    """Generate a 256-bit URL-safe secret and its purpose-bound digest."""
    secret = f"{_PREFIX[purpose]}_{secrets.token_urlsafe(32)}"
    return GeneratedAccountToken(
        secret=secret,
        token_hash=hash_account_token(
            secret, master_secret=master_secret, purpose=purpose
        ),
    )
