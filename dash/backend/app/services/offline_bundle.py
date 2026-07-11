"""Signed offline intelligence and update bundles (Phase 27).

Air-gapped and low-bandwidth sites cannot always reach NVD/KEV/EPSS or the release
server. An **offline bundle** lets an operator carry that data in on a USB stick or
over a slow link and import it through the CLI or UI.

A bundle is a signed manifest (the same Ed25519 canonical-document scheme used for
jobs and policy) describing **data only**: intelligence snapshots, feed exports,
Nuclei template sets, or an update manifest. It is deliberately **not** a plugin or
executable side-loading mechanism — the content-kind allowlist below contains no
executable kind, and import copies verified data, never runs code.

This module is pure and unit-testable: verification, inspection, and import
planning take bytes/dicts and the orchestrator's public key. It never touches the
network or the database (the API layer persists an audit record for history).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.services.signing import SIGNATURE_FIELD, canonical_bytes

# Data-only content kinds. There is intentionally no "plugin"/"binary"/"script"
# kind: an offline bundle can never introduce executable code.
ALLOWED_KINDS: tuple[str, ...] = ("intel", "feeds", "templates", "update")

# A bundle older than this is treated as stale on import (still inspectable).
MAX_BUNDLE_AGE_DAYS = 120


class BundleError(ValueError):
    """Raised when a bundle manifest is malformed, unsigned, or disallowed."""


@dataclass
class BundleInfo:
    """Non-sensitive metadata surfaced before any import decision."""

    kind: str
    created_at: str
    feed_age_days: int | None
    content_versions: dict[str, str]
    item_count: int
    stale: bool
    signature_valid: bool


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise BundleError(msg)


def verify_signature(manifest: dict[str, Any], pubkey: Ed25519PublicKey) -> bool:
    """Return True iff the manifest carries a valid Ed25519 signature.

    Verification is independent of trust in the bundle's own claims: the signature
    covers the canonical bytes of everything except the ``signature`` field.
    """
    signature = manifest.get(SIGNATURE_FIELD)
    if not isinstance(signature, str):
        return False
    import base64

    body = {k: v for k, v in manifest.items() if k != SIGNATURE_FIELD}
    try:
        pubkey.verify(base64.b64decode(signature), canonical_bytes(body))
    except Exception:
        return False
    return True


def inspect(
    manifest: dict[str, Any],
    pubkey: Ed25519PublicKey,
    *,
    now: datetime | None = None,
) -> BundleInfo:
    """Validate the manifest shape and return its metadata without importing.

    Raises :class:`BundleError` for a malformed manifest or a disallowed kind.
    The returned :class:`BundleInfo` reports whether the signature is valid and
    whether the bundle is stale, so the operator can decide before importing.
    """
    now = now or datetime.now(UTC)

    kind = manifest.get("kind")
    _require(isinstance(kind, str), "Bundle is missing a 'kind'.")
    _require(
        kind in ALLOWED_KINDS,
        f"Bundle kind '{kind}' is not importable. Offline bundles carry data only "
        f"(one of {list(ALLOWED_KINDS)}), never executables or plugins.",
    )

    created_raw = manifest.get("created_at")
    _require(isinstance(created_raw, str), "Bundle is missing 'created_at'.")
    try:
        created = datetime.fromisoformat(str(created_raw))
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
    except ValueError as exc:
        raise BundleError("Bundle 'created_at' is not a valid timestamp.") from exc

    versions = manifest.get("content_versions", {})
    _require(
        isinstance(versions, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in versions.items()),
        "Bundle 'content_versions' must be a string map.",
    )

    items = manifest.get("items", [])
    _require(isinstance(items, list), "Bundle 'items' must be a list.")

    feed_age = manifest.get("feed_age_days")
    _require(
        feed_age is None or (isinstance(feed_age, int) and not isinstance(feed_age, bool)),
        "Bundle 'feed_age_days' must be an integer when present.",
    )

    age_days = (now - created).days
    stale = age_days > MAX_BUNDLE_AGE_DAYS

    return BundleInfo(
        kind=str(kind),
        created_at=created.isoformat(),
        feed_age_days=feed_age,
        content_versions={str(k): str(v) for k, v in versions.items()},
        item_count=len(items),
        stale=stale,
        signature_valid=verify_signature(manifest, pubkey),
    )


@dataclass
class ImportPlan:
    """The outcome of validating a bundle for import. ``usable`` gates the import."""

    info: BundleInfo
    usable: bool
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def plan_import(
    manifest: dict[str, Any],
    pubkey: Ed25519PublicKey,
    *,
    now: datetime | None = None,
) -> ImportPlan:
    """Decide whether a bundle may be imported. Fails closed on a bad signature.

    An unsigned or tampered bundle is never usable. A stale but validly signed
    bundle is usable with a warning, so an air-gapped site can still import the
    best data it has.
    """
    info = inspect(manifest, pubkey, now=now)
    blockers: list[str] = []
    warnings: list[str] = []

    if not info.signature_valid:
        blockers.append(
            "Signature is invalid or missing. Only bundles signed by this "
            "deployment's release key can be imported."
        )
    if info.stale:
        warnings.append(
            f"Bundle was created more than {MAX_BUNDLE_AGE_DAYS} days ago; its "
            "intelligence may be out of date."
        )

    return ImportPlan(
        info=info,
        usable=not blockers,
        blockers=blockers,
        warnings=warnings,
    )


def import_record(info: BundleInfo, *, now: datetime | None = None) -> dict[str, Any]:
    """Build the history entry persisted (as an audit event) after a successful import."""
    now = now or datetime.now(UTC)
    return {
        "kind": info.kind,
        "created_at": info.created_at,
        "feed_age_days": info.feed_age_days,
        "content_versions": info.content_versions,
        "item_count": info.item_count,
        "imported_at": now.isoformat(),
    }
