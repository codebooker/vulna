"""Purpose-separated encryption for reusable application secrets."""

from __future__ import annotations

import base64
from enum import StrEnum

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecretPurpose(StrEnum):
    TOTP_SEED = "totp_seed"


_CONTEXT = {
    SecretPurpose.TOTP_SEED: b"vulna-totp-seed-encryption-v1",
}


class SecretDecryptionError(ValueError):
    """Raised when purpose-bound ciphertext cannot be authenticated."""


def _fernet(master_secret: str, purpose: SecretPurpose) -> Fernet:
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_CONTEXT[purpose],
    ).derive(master_secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(master_secret: str, purpose: SecretPurpose, plaintext: str) -> str:
    return _fernet(master_secret, purpose).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(master_secret: str, purpose: SecretPurpose, ciphertext: str) -> str:
    try:
        return _fernet(master_secret, purpose).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise SecretDecryptionError("Secret ciphertext is invalid for this purpose") from exc
