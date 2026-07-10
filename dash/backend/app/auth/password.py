"""Password hashing using Argon2id.

Argon2id is the OWASP-recommended default for password storage. We use
``argon2-cffi`` directly rather than a wrapper so the algorithm and parameters
are explicit and easy to audit.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Library defaults are sensible for interactive logins; kept centralized so the
# cost parameters can be tuned in one place.
_hasher = PasswordHasher()


def hash_password(plaintext: str) -> str:
    """Return an Argon2id hash for ``plaintext``."""
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Return whether ``plaintext`` matches the stored Argon2 ``hashed`` value.

    Returns ``False`` (rather than raising) on any mismatch or malformed hash so
    callers can treat verification as a simple boolean check.
    """
    try:
        return _hasher.verify(hashed, plaintext)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(hashed: str) -> bool:
    """Return whether ``hashed`` should be re-computed with current parameters."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except (InvalidHashError, ValueError):
        return True
