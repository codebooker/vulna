"""Notification core: events, signed webhook payloads, destination validation,
delivery policies, quiet hours, and credential encryption (Phase 29).

Outbound-only and self-hoster-friendly. Everything here is pure and
unit-testable: building a signed payload, validating a destination against SSRF,
deciding whether a digest is due, and encrypting a credential all take plain
inputs and return plain outputs. No network and no database.

Two safety rules run through the whole module:

* **Selected fields only.** A notification never carries raw evidence, scanner
  output, credentials, or report files — only a small, explicit set of scalar
  fields plus a deep link back into Vulna.
* **No SSRF.** A webhook destination must be an ``https`` URL that does not
  resolve to a loopback, link-local, cloud-metadata, or (by default) private
  address, so a webhook cannot be turned into a request forgery primitive.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
from base64 import urlsafe_b64encode
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken

PAYLOAD_VERSION = "1"
# Reject a webhook whose signature timestamp is older/newer than this (replay window).
REPLAY_TOLERANCE_SECONDS = 300


class NotificationError(ValueError):
    """Raised for an invalid destination, policy, or payload."""


# --------------------------------------------------------------------------- #
# Event catalogue (small-operator focused)
# --------------------------------------------------------------------------- #


class EventType(StrEnum):
    SCOUT_OFFLINE = "scout_offline"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    NEW_PRIORITY_FINDING = "new_priority_finding"
    KEV_MATCH = "kev_match"
    VERIFICATION_SUCCEEDED = "verification_succeeded"
    VERIFICATION_FAILED = "verification_failed"
    BACKUP_STALE = "backup_stale"
    FEED_STALE = "feed_stale"
    CERT_EXPIRING = "cert_expiring"
    STORAGE_PRESSURE = "storage_pressure"
    UPDATE_AVAILABLE = "update_available"


# Events treated as emergencies: they may be delivered even during quiet hours.
EMERGENCY_EVENTS = frozenset(
    {EventType.KEV_MATCH, EventType.STORAGE_PRESSURE, EventType.SCOUT_OFFLINE}
)

EVENT_CATALOG: dict[str, str] = {
    EventType.SCOUT_OFFLINE: "A Scout stopped checking in",
    EventType.SCAN_COMPLETED: "A scan finished",
    EventType.SCAN_FAILED: "A scan failed",
    EventType.NEW_PRIORITY_FINDING: "A new critical or high finding",
    EventType.KEV_MATCH: "A known-exploited (KEV) CVE now matches an asset",
    EventType.VERIFICATION_SUCCEEDED: "A remediation was verified fixed",
    EventType.VERIFICATION_FAILED: "A remediation did not verify",
    EventType.BACKUP_STALE: "No recent verified backup",
    EventType.FEED_STALE: "Intelligence feeds are stale",
    EventType.CERT_EXPIRING: "A certificate is expiring",
    EventType.STORAGE_PRESSURE: "Storage is under pressure",
    EventType.UPDATE_AVAILABLE: "An update is available",
}


@dataclass
class NotificationEvent:
    """A notifiable event. Only the fields here are ever sent — no evidence,
    credentials, scanner output, or report files."""

    type: str
    title: str
    summary: str
    severity: str = "info"
    site_id: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    data: dict[str, str | int | bool] = field(default_factory=dict)

    def deep_link(self, base_url: str) -> str | None:
        """A link back into Vulna for this object. Never contains a secret."""
        if not base_url or not self.object_type or not self.object_id:
            return None
        return f"{base_url.rstrip('/')}/{self.object_type}s/{self.object_id}"


def dedup_key(event: NotificationEvent) -> str:
    """A stable key grouping identical repeated events (for dedup / digests)."""
    basis = "|".join(
        [event.type, event.object_type or "", event.object_id or "", event.title]
    )
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# Signed webhook payloads (versioned, replay-resistant, selected fields)
# --------------------------------------------------------------------------- #


def webhook_payload(
    event: NotificationEvent,
    *,
    signing_key: str,
    delivery_id: str,
    base_url: str = "",
    now: datetime | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Build the signed webhook body and headers.

    The body is a versioned JSON document of selected fields only. The signature
    is ``HMAC-SHA256(signing_key, "<timestamp>.<body>")`` — binding the timestamp
    into the signed material makes replay detectable at the receiver.
    """
    now = now or datetime.now(UTC)
    ts = int(now.timestamp())
    document = {
        "version": PAYLOAD_VERSION,
        "id": delivery_id,
        "type": event.type,
        "occurred_at": now.isoformat(),
        "severity": event.severity,
        "title": event.title,
        "summary": event.summary,
        "site_id": event.site_id,
        "object": {"type": event.object_type, "id": event.object_id},
        "deep_link": event.deep_link(base_url),
        "data": event.data,
    }
    body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    signature = _sign(signing_key, ts, body)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Vulna-Webhook/1",
        "X-Vulna-Event": event.type,
        "X-Vulna-Delivery": delivery_id,
        "X-Vulna-Timestamp": str(ts),
        "X-Vulna-Signature": f"t={ts},v1={signature}",
    }
    return body, headers


def _sign(signing_key: str, ts: int, body: bytes) -> str:
    mac = hmac.new(signing_key.encode(), f"{ts}.".encode() + body, hashlib.sha256)
    return mac.hexdigest()


def verify_webhook(
    signing_key: str,
    *,
    timestamp: int,
    body: bytes,
    signature_hex: str,
    now: datetime | None = None,
    tolerance: int = REPLAY_TOLERANCE_SECONDS,
) -> bool:
    """Verify a received webhook (used by receivers and by tests).

    Returns False on a bad signature or a timestamp outside the replay window.
    """
    now = now or datetime.now(UTC)
    if abs(int(now.timestamp()) - timestamp) > tolerance:
        return False
    expected = _sign(signing_key, timestamp, body)
    return hmac.compare_digest(expected, signature_hex)


# --------------------------------------------------------------------------- #
# Destination validation (SSRF protection)
# --------------------------------------------------------------------------- #


def validate_destination(url: str, *, allow_private: bool = False) -> None:
    """Validate a webhook destination, raising :class:`NotificationError` if the
    URL could be used for request forgery.

    Requires ``https``. Resolves the host and rejects loopback, link-local,
    cloud-metadata, multicast, unspecified, and reserved addresses. Private
    (RFC1918/ULA) addresses are rejected unless ``allow_private`` is set, which an
    operator opts into for a trusted service on their own LAN.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise NotificationError("Webhook URL must use https.")
    host = parts.hostname
    if not host:
        raise NotificationError("Webhook URL has no host.")

    for addr in _resolve(host):
        ip = ipaddress.ip_address(addr)
        # Always blocked, even with allow_private: these are never a valid webhook
        # target and include the cloud metadata service.
        if (
            ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved
        ):
            raise NotificationError(
                f"Webhook host resolves to a blocked address ({addr}); "
                "loopback, link-local, and metadata addresses are not allowed."
            )
        if ip.is_private and not allow_private:
            raise NotificationError(
                f"Webhook host resolves to a private address ({addr}). Enable "
                "'allow private destination' only for a trusted service on your own network."
            )


def _resolve(host: str) -> list[str]:
    """Resolve a host to its IP strings. A literal IP resolves to itself."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise NotificationError(f"Could not resolve webhook host '{host}'.") from exc
    return sorted({str(info[4][0]) for info in infos})


# --------------------------------------------------------------------------- #
# Delivery policies, quiet hours, dedup grouping
# --------------------------------------------------------------------------- #


class Policy(StrEnum):
    IMMEDIATE = "immediate"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


_DIGEST_INTERVAL = {
    Policy.HOURLY: timedelta(hours=1),
    Policy.DAILY: timedelta(days=1),
    Policy.WEEKLY: timedelta(weeks=1),
}


def digest_due(policy: str, now: datetime, last_sent: datetime | None) -> bool:
    """Whether a digest for ``policy`` should be sent now."""
    if policy == Policy.IMMEDIATE:
        return True
    interval = _DIGEST_INTERVAL.get(Policy(policy))
    if interval is None:
        return True
    if last_sent is None:
        return True
    return (now - last_sent) >= interval


@dataclass(frozen=True)
class QuietHours:
    """Local quiet-hours window [start_hour, end_hour). Wraps past midnight."""

    start_hour: int
    end_hour: int

    def contains(self, hour: int) -> bool:
        if self.start_hour == self.end_hour:
            return False
        if self.start_hour < self.end_hour:
            return self.start_hour <= hour < self.end_hour
        return hour >= self.start_hour or hour < self.end_hour  # wraps midnight


def should_delay(event_type: str, local_hour: int, quiet: QuietHours | None) -> bool:
    """During quiet hours, delay (never discard) non-emergency notifications."""
    if quiet is None or not quiet.contains(local_hour):
        return False
    return event_type not in EMERGENCY_EVENTS


# --------------------------------------------------------------------------- #
# Email body (plain text, selected fields only)
# --------------------------------------------------------------------------- #


def email_body(events: list[NotificationEvent], *, base_url: str = "") -> str:
    """Plain-text email body for one or more events. No evidence or secrets."""
    lines: list[str] = []
    for e in events:
        lines.append(f"[{e.severity.upper()}] {e.title}")
        if e.summary:
            lines.append(f"  {e.summary}")
        link = e.deep_link(base_url)
        if link:
            lines.append(f"  {link}")
        lines.append("")
    lines.append("You are receiving this because a Vulna notification channel is subscribed.")
    return "\n".join(lines)


def event_as_dict(event: NotificationEvent) -> dict[str, object]:
    return asdict(event)


# --------------------------------------------------------------------------- #
# Credential encryption at rest
# --------------------------------------------------------------------------- #


def _fernet(secret_key: str) -> Fernet:
    # Derive a stable 32-byte Fernet key from the deployment secret.
    digest = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(urlsafe_b64encode(digest))


def encrypt_secret(secret_key: str, plaintext: str) -> str:
    """Encrypt a credential for storage. Never store or return the plaintext."""
    return _fernet(secret_key).encrypt(plaintext.encode()).decode()


def decrypt_secret(secret_key: str, token: str) -> str:
    """Decrypt a stored credential (only at send time)."""
    try:
        return _fernet(secret_key).decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise NotificationError("Stored credential could not be decrypted.") from exc
