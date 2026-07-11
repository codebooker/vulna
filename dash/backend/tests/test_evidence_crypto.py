"""Evidence at-rest encryption tests."""

from __future__ import annotations

import pytest
from app.services.evidence_crypto import (
    EvidenceDecryptionError,
    decrypt_evidence,
    encrypt_evidence,
)

RAW = b"<nmaprun><host><address addr='10.0.0.5'/></host></nmaprun>\x00\xff binary"


def test_plaintext_when_no_master_key() -> None:
    stored, encrypted = encrypt_evidence(RAW, None)
    assert encrypted is False
    # Plaintext path is the legacy behavior (UTF-8 with replacement).
    assert decrypt_evidence(stored, False, None) == stored.encode("utf-8")


def test_encrypts_and_round_trips_losslessly() -> None:
    stored, encrypted = encrypt_evidence(RAW, "a-strong-master-key")
    assert encrypted is True
    # Ciphertext must not contain the plaintext markers.
    assert "nmaprun" not in stored
    assert "10.0.0.5" not in stored
    # Correct key recovers the exact bytes (including the binary tail).
    assert decrypt_evidence(stored, True, "a-strong-master-key") == RAW


def test_wrong_key_is_rejected() -> None:
    stored, _ = encrypt_evidence(RAW, "key-one")
    with pytest.raises(EvidenceDecryptionError):
        decrypt_evidence(stored, True, "key-two")


def test_missing_key_on_encrypted_is_rejected() -> None:
    stored, _ = encrypt_evidence(RAW, "key-one")
    with pytest.raises(EvidenceDecryptionError):
        decrypt_evidence(stored, True, None)
