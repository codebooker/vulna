"""Encryption of sensitive evidence (raw scanner output) at rest.

Raw scanner output can contain sensitive details about a customer's environment
(hostnames, banners, versions, sometimes secrets in a response body). When a
master key is configured (``VULNA_MASTER_KEY``), artifacts are encrypted before
they touch the database and decrypted on read; without a key (local dev) they
fall back to plaintext, and each artifact records which form it is in.

A Fernet key is *derived* from the configured master key via HKDF-SHA256, so the
operator may supply any sufficiently random string rather than a Fernet key.
"""

from __future__ import annotations

import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HKDF_INFO = b"vulna-evidence-v1"


class EvidenceDecryptionError(RuntimeError):
    """Raised when stored evidence cannot be decrypted (wrong/missing key)."""


@lru_cache(maxsize=8)
def _fernet(master_key: str) -> Fernet:
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO)
    derived = kdf.derive(master_key.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_evidence(raw: bytes, master_key: str | None) -> tuple[str, bool]:
    """Return ``(stored_text, encrypted)`` for raw evidence bytes.

    With a master key the bytes are encrypted losslessly and returned as an ASCII
    Fernet token. Without one, the previous plaintext behavior is preserved
    (UTF-8 with replacement), and ``encrypted`` is ``False``.
    """
    if master_key:
        return _fernet(master_key).encrypt(raw).decode("ascii"), True
    return raw.decode("utf-8", errors="replace"), False


def decrypt_evidence(stored: str, encrypted: bool, master_key: str | None) -> bytes:
    """Recover evidence bytes from their stored form.

    Plaintext artifacts are returned as UTF-8 bytes. Encrypted artifacts require
    the same master key that produced them; a missing or wrong key raises
    :class:`EvidenceDecryptionError`.
    """
    if not encrypted:
        return stored.encode("utf-8")
    if not master_key:
        raise EvidenceDecryptionError(
            "artifact is encrypted but no master key is configured (set VULNA_MASTER_KEY)"
        )
    try:
        return _fernet(master_key).decrypt(stored.encode("ascii"))
    except InvalidToken as exc:
        raise EvidenceDecryptionError(
            "could not decrypt artifact: the master key does not match the one used to store it"
        ) from exc
