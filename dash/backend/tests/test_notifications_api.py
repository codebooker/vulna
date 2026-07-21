"""API + service tests for notifications (Phase 29)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.core.config import get_settings
from app.models.notification import (
    DELIVERY_DELAYED,
    DELIVERY_SENT,
    NotificationChannel,
)
from app.services import notifications as core
from app.services import notify
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers
from tests.test_assets import _create_job
from tests.test_jobs import _ready_probe

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]

WEBHOOK = {
    "name": "ops",
    "channel_type": "webhook",
    "config": {"url": "https://8.8.8.8/vulna"},
    "secret": "signing-key",
    "events": ["scan_failed", "scan_completed"],
    "policy": "immediate",
}


async def test_create_channel_hides_secret_and_ssrf_blocks(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    created = await client.post(
        "/api/v1/notifications/channels", json=WEBHOOK, headers=admin_headers
    )
    assert created.status_code == 201
    body = created.json()
    assert body["has_secret"] is True
    assert "secret" not in body and "encrypted_secret" not in body

    listed = await client.get("/api/v1/notifications/channels", headers=admin_headers)
    assert all("secret" not in c or c.get("secret") is None for c in listed.json()["channels"])

    # SSRF: a private / metadata destination is rejected.
    bad = await client.post(
        "/api/v1/notifications/channels",
        json={**WEBHOOK, "config": {"url": "https://169.254.169.254/hook"}},
        headers=admin_headers,
    )
    assert bad.status_code == 422


async def test_channel_config_requires_admin(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.post("/api/v1/notifications/channels", json=WEBHOOK, headers=viewer_headers)
    assert r.status_code == 403


async def test_scan_failure_queues_notification(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    await client.post("/api/v1/notifications/channels", json=WEBHOOK, headers=admin_headers)
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    job_id, attempt_headers = await _create_job(client, admin_headers, probe)

    # The probe reports the job failed -> a pending delivery is queued (non-blocking).
    status_resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={"status": "failed", "error_code": "timeout"},
        headers={**probe_cert_headers(probe["fingerprint"]), **attempt_headers},
    )
    assert status_resp.status_code == 204

    deliveries = await client.get("/api/v1/notifications/deliveries", headers=admin_headers)
    rows = deliveries.json()["deliveries"]
    assert any(d["event_type"] == "scan_failed" and d["status"] == "pending" for d in rows)


class _FakeSender:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.fail = False

    def send(self, channel, secret, events, base_url):  # noqa: ANN001
        if self.fail:
            raise RuntimeError("destination unreachable")
        self.sent.extend(e.type for e in events)


async def _make_channel(session: AsyncSession, org_id, **over) -> NotificationChannel:
    ch = notify.build_channel(
        get_settings(),
        org_id,
        None,
        name="c",
        channel_type="webhook",
        config={"url": "https://8.8.8.8/h"},
        secret="k",
        events=["scan_failed"],
        policy="immediate",
        quiet_start_hour=over.get("quiet_start"),
        quiet_end_hour=over.get("quiet_end"),
    )
    session.add(ch)
    await session.commit()
    return ch


def _event() -> core.NotificationEvent:
    return core.NotificationEvent(
        type=core.EventType.SCAN_FAILED,
        title="Scan failed",
        summary="x",
        severity="high",
        object_type="job",
        object_id="j1",
    )


async def test_emit_dedup_and_dispatch_sends(db_session: AsyncSession, organization) -> None:
    ch = await _make_channel(db_session, organization.id)
    # Emit the same event twice -> deduplicated to one pending delivery.
    await notify.emit_event(db_session, organization.id, _event())
    await notify.emit_event(db_session, organization.id, _event())
    await db_session.commit()
    pending = (
        (
            await db_session.execute(
                select(notify.NotificationDelivery).where(
                    notify.NotificationDelivery.channel_id == ch.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(pending) == 1

    sender = _FakeSender()
    result = await notify.dispatch_pending(
        db_session, organization.id, sender, get_settings(), datetime.now(UTC)
    )
    await db_session.commit()
    assert result["sent"] == 1
    assert sender.sent == ["scan_failed"]
    assert pending[0].status == DELIVERY_SENT


async def test_dispatch_failure_records_error(db_session: AsyncSession, organization) -> None:
    await _make_channel(db_session, organization.id)
    await notify.emit_event(db_session, organization.id, _event())
    await db_session.commit()

    sender = _FakeSender()
    sender.fail = True
    result = await notify.dispatch_pending(
        db_session, organization.id, sender, get_settings(), datetime.now(UTC)
    )
    await db_session.commit()
    assert result["failed"] == 1
    row = (await db_session.execute(select(notify.NotificationDelivery))).scalars().first()
    assert row is not None
    assert row.attempts == 1 and row.last_error and row.status != DELIVERY_SENT


async def test_quiet_hours_delays_then_sends(db_session: AsyncSession, organization) -> None:
    # Quiet all day so the event is delayed on emit.
    await _make_channel(db_session, organization.id, quiet_start=0, quiet_end=23)
    at_2am = datetime(2026, 7, 11, 2, 0, tzinfo=UTC)
    await notify.emit_event(db_session, organization.id, _event(), now=at_2am)
    await db_session.commit()
    row = (await db_session.execute(select(notify.NotificationDelivery))).scalars().first()
    assert row is not None and row.status == DELIVERY_DELAYED

    # During quiet hours dispatch holds it (does not discard).
    sender = _FakeSender()
    held = await notify.dispatch_pending(
        db_session, organization.id, sender, get_settings(), at_2am
    )
    assert held["sent"] == 0 and held["held"] == 1

    # Outside quiet hours (23:00) it sends.
    at_11pm = datetime(2026, 7, 11, 23, 30, tzinfo=UTC)
    sent = await notify.dispatch_pending(
        db_session, organization.id, sender, get_settings(), at_11pm
    )
    await db_session.commit()
    assert sent["sent"] == 1
