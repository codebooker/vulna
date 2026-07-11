"""Unit tests for derived probe connectivity (online/offline)."""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

from datetime import UTC, datetime, timedelta

from app.models.enums import ProbeStatus
from app.models.probe import Probe
from app.schemas.probe import is_probe_online


def _probe(last_seen: datetime | None) -> Probe:
    return Probe(
        organization_id=None,
        site_id=None,
        name="p",
        status=ProbeStatus.ENROLLED,
        certificate_fingerprint="f",
        last_seen_at=last_seen,
    )


def test_never_seen_is_offline() -> None:
    assert is_probe_online(_probe(None), offline_after_seconds=180) is False


def test_recent_heartbeat_is_online() -> None:
    recent = datetime.now(UTC) - timedelta(seconds=10)
    assert is_probe_online(_probe(recent), offline_after_seconds=180) is True


def test_stale_heartbeat_is_offline() -> None:
    stale = datetime.now(UTC) - timedelta(seconds=600)
    assert is_probe_online(_probe(stale), offline_after_seconds=180) is False


def test_naive_last_seen_is_treated_as_utc() -> None:
    recent_naive = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=5)
    assert is_probe_online(_probe(recent_naive), offline_after_seconds=180) is True
