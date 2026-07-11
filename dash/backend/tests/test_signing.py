"""Unit tests for Ed25519 signing and canonical serialization."""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

import base64
from pathlib import Path

from app.services.signing import (
    Ed25519Signer,
    canonical_bytes,
    document_hash,
    public_key_from_raw_b64,
)


def test_canonical_bytes_sorted_and_compact() -> None:
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_bytes_no_html_escaping() -> None:
    # Unlike Go's default encoder, we must not escape <, >, & — the probe relies
    # on this to reproduce identical bytes.
    assert canonical_bytes({"x": "a<b>&c"}) == b'{"x":"a<b>&c"}'


def test_canonical_bytes_nested_sorted() -> None:
    payload = {"z": 1, "a": {"d": 4, "c": 3}, "m": [3, 2, 1]}
    assert canonical_bytes(payload) == b'{"a":{"c":3,"d":4},"m":[3,2,1],"z":1}'


def test_sign_and_verify_round_trip(tmp_path: Path) -> None:
    signer = Ed25519Signer.create_and_save(tmp_path / "k", tmp_path / "k.pub")
    doc = signer.sign_document({"policy_version": 3, "approved_cidrs": ["10.0.0.0/24"]})
    assert "signature" in doc
    assert signer.verify_document(doc) is True


def test_tampering_breaks_verification(tmp_path: Path) -> None:
    signer = Ed25519Signer.create_and_save(tmp_path / "k", tmp_path / "k.pub")
    doc = signer.sign_document({"approved_cidrs": ["10.0.0.0/24"]})
    doc["approved_cidrs"] = ["0.0.0.0/0"]  # tamper after signing
    assert signer.verify_document(doc) is False


def test_public_key_raw_is_32_bytes(tmp_path: Path) -> None:
    signer = Ed25519Signer.create_and_save(tmp_path / "k", tmp_path / "k.pub")
    raw = base64.b64decode(signer.public_key_raw_b64)
    assert len(raw) == 32
    # The exported raw key round-trips to a usable public key.
    public_key_from_raw_b64(signer.public_key_raw_b64)


def test_document_hash_excludes_signature(tmp_path: Path) -> None:
    signer = Ed25519Signer.create_and_save(tmp_path / "k", tmp_path / "k.pub")
    payload = {"a": 1, "b": 2}
    doc = signer.sign_document(payload)
    assert document_hash(payload) == document_hash(doc)


def test_load_persists_key(tmp_path: Path) -> None:
    key_path = tmp_path / "k"
    s1 = Ed25519Signer.create_and_save(key_path, tmp_path / "k.pub")
    s2 = Ed25519Signer.load(key_path)
    assert s1.public_key_raw_b64 == s2.public_key_raw_b64
    assert (key_path.stat().st_mode & 0o777) == 0o600
