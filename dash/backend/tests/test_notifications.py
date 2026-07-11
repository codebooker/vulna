"""Unit tests for the notification core (Phase 29)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from app.services.notifications import (
    EMERGENCY_EVENTS,
    EventType,
    NotificationError,
    NotificationEvent,
    Policy,
    QuietHours,
    decrypt_secret,
    dedup_key,
    digest_due,
    encrypt_secret,
    should_delay,
    validate_destination,
    verify_webhook,
    webhook_payload,
)

EVT = NotificationEvent(
    type=EventType.SCAN_FAILED,
    title="Scan failed",
    summary="A scan on site-a failed",
    severity="high",
    site_id="s1",
    object_type="job",
    object_id="j1",
    data={"error_code": "timeout"},
)


def test_webhook_payload_is_signed_and_verifiable() -> None:
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    body, headers = webhook_payload(EVT, signing_key="k", delivery_id="d1", now=now)
    assert headers["X-Vulna-Event"] == "scan_failed"
    ts = int(headers["X-Vulna-Timestamp"])
    sig = headers["X-Vulna-Signature"].split("v1=")[1]
    assert verify_webhook("k", timestamp=ts, body=body, signature_hex=sig, now=now)
    # Wrong key fails.
    assert not verify_webhook("other", timestamp=ts, body=body, signature_hex=sig, now=now)


def test_webhook_replay_outside_window_rejected() -> None:
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    body, headers = webhook_payload(EVT, signing_key="k", delivery_id="d1", now=now)
    ts = int(headers["X-Vulna-Timestamp"])
    sig = headers["X-Vulna-Signature"].split("v1=")[1]
    later = now + timedelta(hours=1)
    assert not verify_webhook("k", timestamp=ts, body=body, signature_hex=sig, now=later)


def test_payload_carries_only_selected_fields() -> None:
    body, _ = webhook_payload(EVT, signing_key="k", delivery_id="d1", base_url="https://vulna.example")
    doc = json.loads(body)
    assert set(doc) == {
        "version", "id", "type", "occurred_at", "severity", "title", "summary",
        "site_id", "object", "deep_link", "data",
    }
    assert doc["deep_link"] == "https://vulna.example/jobs/j1"
    # No evidence/credential/raw-output keys leak in.
    flat = body.decode().lower()
    for banned in ("password", "evidence", "raw_output", "secret", "credential"):
        assert banned not in flat


def test_dedup_key_stable_and_distinct() -> None:
    other = NotificationEvent(type=EventType.SCAN_FAILED, title="Scan failed", summary="x",
                              object_type="job", object_id="j2")
    assert dedup_key(EVT) == dedup_key(EVT)
    assert dedup_key(EVT) != dedup_key(other)


# --- SSRF validation -------------------------------------------------------- #


def test_https_required() -> None:
    with pytest.raises(NotificationError):
        validate_destination("http://example.com/hook")


def test_public_https_allowed() -> None:
    validate_destination("https://8.8.8.8/hook")  # public literal IP, no raise


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/hook",
    "https://169.254.169.254/latest/meta-data",  # cloud metadata
    "https://[::1]/hook",
])
def test_loopback_and_metadata_blocked(url: str) -> None:
    with pytest.raises(NotificationError):
        validate_destination(url)


def test_private_blocked_by_default_but_opt_in_allows() -> None:
    with pytest.raises(NotificationError):
        validate_destination("https://10.0.0.5/hook")
    validate_destination("https://10.0.0.5/hook", allow_private=True)  # opt-in, no raise


def test_metadata_blocked_even_with_allow_private() -> None:
    with pytest.raises(NotificationError):
        validate_destination("https://169.254.169.254/hook", allow_private=True)


# --- policies / quiet hours ------------------------------------------------- #


def test_immediate_always_due() -> None:
    assert digest_due(Policy.IMMEDIATE, datetime.now(UTC), None)


def test_hourly_digest_respects_interval() -> None:
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    assert not digest_due(Policy.HOURLY, now, now - timedelta(minutes=30))
    assert digest_due(Policy.HOURLY, now, now - timedelta(hours=2))
    assert digest_due(Policy.HOURLY, now, None)


def test_quiet_hours_delay_non_emergency_only() -> None:
    quiet = QuietHours(start_hour=22, end_hour=7)  # wraps midnight
    assert quiet.contains(2) and not quiet.contains(12)
    # Non-emergency during quiet hours is delayed.
    assert should_delay(EventType.SCAN_COMPLETED, 2, quiet) is True
    # Emergency is not delayed.
    assert EventType.KEV_MATCH in EMERGENCY_EVENTS
    assert should_delay(EventType.KEV_MATCH, 2, quiet) is False
    # Outside quiet hours nothing is delayed.
    assert should_delay(EventType.SCAN_COMPLETED, 12, quiet) is False


# --- credential encryption -------------------------------------------------- #


def test_encrypt_roundtrip_and_opacity() -> None:
    token = encrypt_secret("deployment-secret", "smtp-password")
    assert token != "smtp-password"
    assert decrypt_secret("deployment-secret", token) == "smtp-password"


def test_decrypt_with_wrong_key_fails_closed() -> None:
    token = encrypt_secret("secret-a", "hunter2")
    with pytest.raises(NotificationError):
        decrypt_secret("secret-b", token)
