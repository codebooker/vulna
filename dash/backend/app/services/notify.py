"""Notification channel management and delivery (Phase 29).

`emit_event` only *persists* pending deliveries — it never sends inline and is
wrapped by callers in a guard — so a notification problem can never block scan
completion or finding persistence. `dispatch_pending` does the sending later,
grouping by policy, honoring quiet hours, and recording history and retry state.

The actual transport is a :class:`Sender` (webhook via HTTPS, email via SMTP).
Tests inject a fake sender; validation, dedup, quiet hours, and history are all
exercised without touching the network.
"""

from __future__ import annotations

import smtplib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.notification import (
    CHANNEL_EMAIL,
    CHANNEL_WEBHOOK,
    DELIVERY_DELAYED,
    DELIVERY_FAILED,
    DELIVERY_PENDING,
    DELIVERY_SENT,
    NotificationChannel,
    NotificationDelivery,
)
from app.services import notifications as core

CHANNEL_TYPES = {CHANNEL_EMAIL, CHANNEL_WEBHOOK}
_MAX_ATTEMPTS = 5


class ChannelError(ValueError):
    """Raised for an invalid channel configuration."""


# --------------------------------------------------------------------------- #
# Channel configuration
# --------------------------------------------------------------------------- #


def _validate_config(channel_type: str, config: dict[str, Any]) -> None:
    if channel_type == CHANNEL_WEBHOOK:
        url = config.get("url")
        if not isinstance(url, str) or not url:
            raise ChannelError("A webhook channel needs a 'url'.")
        core.validate_destination(url, allow_private=bool(config.get("allow_private")))
    elif channel_type == CHANNEL_EMAIL:
        for key in ("host", "from_addr", "to_addrs"):
            if not config.get(key):
                raise ChannelError(f"An email channel needs '{key}'.")
        if not isinstance(config.get("to_addrs"), list):
            raise ChannelError("'to_addrs' must be a list of addresses.")
    else:
        raise ChannelError(f"channel_type must be one of {sorted(CHANNEL_TYPES)}.")


def _validate_events(events: list[str]) -> list[str]:
    valid = {e.value for e in core.EventType}
    bad = [e for e in events if e not in valid]
    if bad:
        raise ChannelError(f"Unknown event types: {bad}")
    return events


def build_channel(
    settings: Settings,
    org_id: uuid.UUID,
    user_id: uuid.UUID | None,
    *,
    name: str,
    channel_type: str,
    config: dict[str, Any],
    secret: str | None,
    events: list[str],
    policy: str,
    quiet_start_hour: int | None,
    quiet_end_hour: int | None,
) -> NotificationChannel:
    if channel_type not in CHANNEL_TYPES:
        raise ChannelError(f"channel_type must be one of {sorted(CHANNEL_TYPES)}.")
    _validate_config(channel_type, config)
    _validate_events(events)
    if policy not in {p.value for p in core.Policy}:
        raise ChannelError(f"Unknown policy '{policy}'.")

    enc = core.encrypt_secret(settings.require_secret_key(), secret) if secret else None
    return NotificationChannel(
        organization_id=org_id,
        name=name,
        channel_type=channel_type,
        config_json=config,
        encrypted_secret=enc,
        events_json=events,
        policy=policy,
        quiet_start_hour=quiet_start_hour,
        quiet_end_hour=quiet_end_hour,
        enabled=True,
        created_by=user_id,
    )


def rotate_secret(settings: Settings, channel: NotificationChannel, new_secret: str) -> None:
    """Replace the stored credential. The plaintext is never persisted or returned."""
    channel.encrypted_secret = core.encrypt_secret(settings.require_secret_key(), new_secret)


def redact_channel(channel: NotificationChannel) -> dict[str, Any]:
    """Serialize a channel WITHOUT its secret (the API never returns credentials)."""
    return {
        "id": str(channel.id),
        "name": channel.name,
        "channel_type": channel.channel_type,
        "config": channel.config_json,
        "has_secret": channel.encrypted_secret is not None,
        "events": channel.events_json,
        "policy": channel.policy,
        "quiet_start_hour": channel.quiet_start_hour,
        "quiet_end_hour": channel.quiet_end_hour,
        "enabled": channel.enabled,
        "last_digest_at": channel.last_digest_at.isoformat() if channel.last_digest_at else None,
    }


# --------------------------------------------------------------------------- #
# Emit (persist only — never blocks the caller)
# --------------------------------------------------------------------------- #


async def emit_event(
    session: AsyncSession,
    org_id: uuid.UUID,
    event: core.NotificationEvent,
    now: datetime | None = None,
) -> int:
    """Persist a pending delivery per subscribed channel. Never sends inline.

    Deduplicates against an existing unsent delivery for the same channel, and
    marks a delivery ``delayed`` (not discarded) when a quiet-hours window applies
    to a non-emergency event. Returns the number of deliveries created.
    """
    now = now or datetime.now(UTC)
    key = core.dedup_key(event)
    channels = (
        await session.execute(
            select(NotificationChannel).where(
                NotificationChannel.organization_id == org_id,
                NotificationChannel.enabled.is_(True),
            )
        )
    ).scalars().all()

    created = 0
    for ch in channels:
        if event.type not in ch.events_json:
            continue
        # Dedup: skip if an unsent delivery for this channel+event already exists.
        existing = await session.scalar(
            select(NotificationDelivery.id).where(
                NotificationDelivery.channel_id == ch.id,
                NotificationDelivery.dedup_key == key,
                NotificationDelivery.status.in_([DELIVERY_PENDING, DELIVERY_DELAYED]),
            )
        )
        if existing is not None:
            continue
        quiet = _quiet(ch)
        status = (
            DELIVERY_DELAYED
            if core.should_delay(event.type, now.hour, quiet)
            else DELIVERY_PENDING
        )
        session.add(
            NotificationDelivery(
                organization_id=org_id,
                channel_id=ch.id,
                event_type=event.type,
                dedup_key=key,
                status=status,
                title=event.title[:512],
                site_id=uuid.UUID(event.site_id) if event.site_id else None,
                payload_json=core.event_as_dict(event),
            )
        )
        # Flush so a repeated emit within the same transaction sees this delivery
        # and deduplicates against it.
        await session.flush()
        created += 1
    return created


def _quiet(ch: NotificationChannel) -> core.QuietHours | None:
    if ch.quiet_start_hour is None or ch.quiet_end_hour is None:
        return None
    return core.QuietHours(ch.quiet_start_hour, ch.quiet_end_hour)


# --------------------------------------------------------------------------- #
# Dispatch (send due deliveries)
# --------------------------------------------------------------------------- #


class Sender(Protocol):
    def send(
        self, channel: NotificationChannel, secret: str | None,
        events: list[core.NotificationEvent], base_url: str,
    ) -> None: ...


@dataclass
class _Ready:
    delivery: NotificationDelivery
    event: core.NotificationEvent


async def dispatch_pending(
    session: AsyncSession,
    org_id: uuid.UUID,
    sender: Sender,
    settings: Settings,
    now: datetime | None = None,
) -> dict[str, int]:
    """Send deliveries that are due, grouped by channel policy. Records status,
    attempts, and errors. Failures are isolated per channel."""
    now = now or datetime.now(UTC)
    result = {"sent": 0, "failed": 0, "held": 0}
    base_url = settings.public_base_url or ""

    channels = (
        await session.execute(
            select(NotificationChannel).where(
                NotificationChannel.organization_id == org_id,
                NotificationChannel.enabled.is_(True),
            )
        )
    ).scalars().all()

    for ch in channels:
        deliveries = (
            await session.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.channel_id == ch.id,
                    NotificationDelivery.status.in_([DELIVERY_PENDING, DELIVERY_DELAYED]),
                )
            )
        ).scalars().all()

        ready: list[_Ready] = []
        for d in deliveries:
            # A delayed delivery is held until it leaves the quiet-hours window.
            if d.status == DELIVERY_DELAYED and core.should_delay(
                d.event_type, now.hour, _quiet(ch)
            ):
                result["held"] += 1
                continue
            ready.append(_Ready(d, _event_from_payload(d.payload_json)))

        if not ready:
            continue
        if ch.policy != core.Policy.IMMEDIATE and not core.digest_due(
            ch.policy, now, ch.last_digest_at
        ):
            result["held"] += len(ready)
            continue

        secret = (
            core.decrypt_secret(settings.require_secret_key(), ch.encrypted_secret)
            if ch.encrypted_secret
            else None
        )
        batches = [ready] if ch.policy != core.Policy.IMMEDIATE else [[r] for r in ready]
        for batch in batches:
            try:
                sender.send(ch, secret, [r.event for r in batch], base_url)
            except Exception as exc:  # noqa: BLE001 - record and continue
                for r in batch:
                    r.delivery.attempts += 1
                    r.delivery.last_error = str(exc)[:1024]
                    if r.delivery.attempts >= _MAX_ATTEMPTS:
                        r.delivery.status = DELIVERY_FAILED
                    result["failed"] += 1
                continue
            for r in batch:
                r.delivery.status = DELIVERY_SENT
                r.delivery.attempts += 1
                r.delivery.sent_at = now
                result["sent"] += 1
        if ch.policy != core.Policy.IMMEDIATE:
            ch.last_digest_at = now
    return result


def _event_from_payload(payload: dict[str, Any]) -> core.NotificationEvent:
    return core.NotificationEvent(
        type=payload.get("type", "scan_completed"),
        title=payload.get("title", ""),
        summary=payload.get("summary", ""),
        severity=payload.get("severity", "info"),
        site_id=payload.get("site_id"),
        object_type=payload.get("object_type"),
        object_id=payload.get("object_id"),
        data=payload.get("data", {}) or {},
    )


# --------------------------------------------------------------------------- #
# Real transport
# --------------------------------------------------------------------------- #


class RealSender:
    """The production sender: HTTPS webhooks and SMTP email."""

    def send(
        self, channel: NotificationChannel, secret: str | None,
        events: list[core.NotificationEvent], base_url: str,
    ) -> None:
        if channel.channel_type == CHANNEL_WEBHOOK:
            self._send_webhook(channel, secret, events, base_url)
        elif channel.channel_type == CHANNEL_EMAIL:
            self._send_email(channel, secret, events, base_url)

    def _send_webhook(
        self, channel: NotificationChannel, secret: str | None,
        events: list[core.NotificationEvent], base_url: str,
    ) -> None:
        url = channel.config_json["url"]
        # Revalidate at send time with the same rules as configuration/test.
        core.validate_destination(url, allow_private=bool(channel.config_json.get("allow_private")))
        for event in events:
            body, headers = core.webhook_payload(
                event, signing_key=secret or "", delivery_id=str(uuid.uuid4()), base_url=base_url
            )
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, content=body, headers=headers)
                resp.raise_for_status()

    def _send_email(
        self, channel: NotificationChannel, secret: str | None,
        events: list[core.NotificationEvent], base_url: str,
    ) -> None:
        cfg = channel.config_json
        msg = EmailMessage()
        msg["From"] = cfg["from_addr"]
        msg["To"] = ", ".join(cfg["to_addrs"])
        subject = events[0].title if len(events) == 1 else f"Vulna: {len(events)} notifications"
        msg["Subject"] = f"[Vulna] {subject}"
        msg.set_content(core.email_body(events, base_url=base_url))

        host, port = cfg["host"], int(cfg.get("port", 587))
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if cfg.get("use_tls", True):
                smtp.starttls()
            if cfg.get("username") and secret:
                smtp.login(cfg["username"], secret)
            smtp.send_message(msg)
