"""Ed25519 signing for job envelopes and local policy documents.

The orchestrator signs the canonical JSON form of a payload; the probe verifies
it independently with the orchestrator's public key. Canonicalization is
deliberately simple and language-agnostic so the Go probe can reproduce the
exact bytes:

* keys sorted (recursively),
* compact separators (``,`` and ``:``), no insignificant whitespace,
* UTF-8, non-ASCII left as UTF-8 (not ``\\uXXXX``),
* no trailing newline,
* numbers restricted to integers/strings in signed payloads (no floats).

The ``signature`` field is never part of the signed bytes; it is added to the
document after signing and removed before verifying.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_FIELD = "signature"


class SigningError(RuntimeError):
    """Raised when signing key material cannot be loaded."""


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Return the canonical byte form of ``payload`` used for signing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def document_hash(payload: dict[str, Any]) -> str:
    """Return the SHA-256 hex of a payload's canonical bytes (excludes signature)."""
    return hashlib.sha256(canonical_bytes(_without_signature(payload))).hexdigest()


def _without_signature(document: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != SIGNATURE_FIELD}


class Ed25519Signer:
    """Signs and verifies canonical payloads with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public = private_key.public_key()

    # -- construction ---------------------------------------------------------

    @classmethod
    def load_or_create(cls, key_path: Path, pub_path: Path) -> Ed25519Signer:
        if key_path.exists():
            return cls.load(key_path)
        return cls.create_and_save(key_path, pub_path)

    @classmethod
    def load(cls, key_path: Path) -> Ed25519Signer:
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except (ValueError, OSError) as exc:
            raise SigningError(f"Could not load signing key: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningError("Signing key is not an Ed25519 private key")
        return cls(key)

    @classmethod
    def create_and_save(cls, key_path: Path, pub_path: Path) -> Ed25519Signer:
        key = Ed25519PrivateKey.generate()
        signer = cls(key)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.write_bytes(
            signer._public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        pub_path.chmod(0o644)
        return signer

    # -- operations -----------------------------------------------------------

    @property
    def public_key_raw_b64(self) -> str:
        """The raw 32-byte Ed25519 public key, base64-encoded (for the probe)."""
        raw = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def sign_payload(self, payload: dict[str, Any]) -> str:
        """Return the base64 Ed25519 signature over ``payload``'s canonical bytes."""
        return base64.b64encode(self._private.sign(canonical_bytes(payload))).decode("ascii")

    def sign_document(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return ``payload`` plus a ``signature`` field over its canonical bytes."""
        signature = self.sign_payload(_without_signature(payload))
        return {**payload, SIGNATURE_FIELD: signature}

    def verify_document(self, document: dict[str, Any]) -> bool:
        """Verify a document that carries its own ``signature`` field."""
        signature = document.get(SIGNATURE_FIELD)
        if not isinstance(signature, str):
            return False
        message = canonical_bytes(_without_signature(document))
        try:
            self._public.verify(base64.b64decode(signature), message)
        except Exception:
            return False
        return True


def public_key_from_raw_b64(raw_b64: str) -> Ed25519PublicKey:
    """Build a public key from its base64 raw 32-byte form (test helper)."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw_b64))


_signer: Ed25519Signer | None = None


def get_signer(key_path: Path | None = None, pub_path: Path | None = None) -> Ed25519Signer:
    """Return the process-wide signer, loading/creating it from settings paths."""
    global _signer
    if _signer is None:
        from app.core.config import get_settings

        settings = get_settings()
        _signer = Ed25519Signer.load_or_create(
            key_path or Path(settings.job_signing_key_path),
            pub_path or Path(settings.job_signing_pubkey_path),
        )
    return _signer


def reset_signer_cache() -> None:
    """Reset the cached signer (used by tests that point at a fresh key dir)."""
    global _signer
    _signer = None
