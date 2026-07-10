"""Enrollment-token generation and hashing.

Token secrets are high-entropy and shown to the operator exactly once; only the
SHA-256 hash is persisted. A short code is generated alongside for out-of-band
display/verification.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

_TOKEN_PREFIX = "vscout"  # noqa: S105  (identifying prefix, not a secret)


@dataclass(frozen=True)
class GeneratedToken:
    """A freshly generated enrollment token."""

    secret: str  # shown to the operator once; never stored
    token_hash: str  # persisted
    short_code: str  # persisted; safe to display


def hash_token(secret: str) -> str:
    """Return the SHA-256 hex digest used to look up a token secret."""
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()


def generate_token() -> GeneratedToken:
    """Generate a new enrollment token (secret + stored hash + short code)."""
    secret = f"{_TOKEN_PREFIX}_{secrets.token_urlsafe(32)}"
    short_code = secrets.token_hex(4).upper()  # 8 hex chars
    return GeneratedToken(
        secret=secret,
        token_hash=hash_token(secret),
        short_code=short_code,
    )
