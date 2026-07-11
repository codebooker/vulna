"""Unit tests for signed offline intelligence/update bundles (Phase 27)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.services.offline_bundle import (
    ALLOWED_KINDS,
    BundleError,
    inspect,
    plan_import,
)
from app.services.signing import Ed25519Signer, public_key_from_raw_b64


def _signer(tmp_path: Path) -> Ed25519Signer:
    return Ed25519Signer.create_and_save(tmp_path / "rel", tmp_path / "rel.pub")


def _manifest(created: datetime | None = None, **over: object) -> dict[str, object]:
    m: dict[str, object] = {
        "kind": "intel",
        "created_at": (created or datetime.now(UTC)).isoformat(),
        "feed_age_days": 3,
        "content_versions": {"nvd": "2026-07-01", "kev": "2026-07-05"},
        "items": [{"cve": "CVE-2026-1"}, {"cve": "CVE-2026-2"}],
    }
    m.update(over)
    return m


def test_inspect_reports_metadata_and_valid_signature(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    pub = public_key_from_raw_b64(signer.public_key_raw_b64)
    doc = signer.sign_document(_manifest())
    info = inspect(doc, pub)
    assert info.kind == "intel"
    assert info.feed_age_days == 3
    assert info.content_versions["nvd"] == "2026-07-01"
    assert info.item_count == 2
    assert info.signature_valid is True
    assert info.stale is False


def test_disallowed_kind_rejected(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    pub = public_key_from_raw_b64(signer.public_key_raw_b64)
    doc = signer.sign_document(_manifest(kind="plugin"))
    with pytest.raises(BundleError):
        inspect(doc, pub)
    # The allowlist is data-only.
    assert "plugin" not in ALLOWED_KINDS
    assert "binary" not in ALLOWED_KINDS


def test_import_fails_closed_on_bad_signature(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    pub = public_key_from_raw_b64(signer.public_key_raw_b64)
    doc = signer.sign_document(_manifest())
    doc["items"] = [{"cve": "TAMPERED"}]  # mutate after signing
    result = plan_import(doc, pub)
    assert result.usable is False
    assert result.blockers
    assert result.info.signature_valid is False


def test_unsigned_bundle_not_usable(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    pub = public_key_from_raw_b64(signer.public_key_raw_b64)
    result = plan_import(_manifest(), pub)  # never signed
    assert result.usable is False


def test_stale_bundle_usable_with_warning(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    pub = public_key_from_raw_b64(signer.public_key_raw_b64)
    old = datetime.now(UTC) - timedelta(days=200)
    doc = signer.sign_document(_manifest(created=old))
    result = plan_import(doc, pub)
    assert result.info.stale is True
    assert result.usable is True  # signed and valid, just old
    assert result.warnings


def test_wrong_key_is_not_valid(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    other = Ed25519Signer.create_and_save(tmp_path / "other", tmp_path / "other.pub")
    other_pub = public_key_from_raw_b64(other.public_key_raw_b64)
    doc = signer.sign_document(_manifest())
    assert plan_import(doc, other_pub).usable is False
