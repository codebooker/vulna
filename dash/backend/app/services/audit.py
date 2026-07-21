"""Audit logging service.

A thin helper that appends an :class:`AuditEvent` to the current session. Audit
events are written within the same transaction as the action they describe, so
a change and its audit record commit together (or not at all).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any

from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.authorization import ServiceAccount
from app.models.enums import ActorType
from app.models.user import User

AuditPrincipal = User | ServiceAccount
_GENESIS_HASH = "0" * 64


def _signing_key() -> bytes:
    settings = get_settings()
    secret = settings.audit_integrity_key or settings.master_key or settings.secret_key
    # Production configuration already requires strong master/session keys. This
    # development-only fallback keeps local bootstrap usable while clearly
    # identifying records that were not signed by a deployment secret.
    return (secret or "vulna-development-audit-integrity-key").encode("utf-8")


def _key_id(key: bytes) -> str:
    return hashlib.sha256(b"vulna-audit-key-id-v1\0" + key).hexdigest()[:16]


def _canonical_event(event: AuditEvent) -> bytes:
    actor_type = getattr(event.actor_type, "value", event.actor_type)
    value = {
        "action": event.action,
        "actor_id": str(event.actor_id) if event.actor_id is not None else None,
        "actor_type": str(actor_type),
        "id": str(event.id),
        "metadata": event.metadata_json,
        "organization_id": (
            str(event.organization_id) if event.organization_id is not None else None
        ),
        "request_id": event.request_id,
        "source_ip": event.source_ip,
        "target_id": event.target_id,
        "target_type": event.target_type,
        "user_agent": event.user_agent,
        "version": event.integrity_version,
    }
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def _signature(event: AuditEvent, key: bytes) -> str:
    return hmac.new(
        key,
        b"vulna-audit-event-v1\0" + _canonical_event(event),
        hashlib.sha256,
    ).hexdigest()


def _chain_hash(previous_hash: str, event_signature: str) -> str:
    return hashlib.sha256(bytes.fromhex(previous_hash) + bytes.fromhex(event_signature)).hexdigest()


@event.listens_for(Session, "before_flush")
def _seal_pending_events(session: Session, _flush_context: object, _instances: object) -> None:
    """Seal new audit rows for portable databases.

    PostgreSQL repeats the chain-position calculation in a serialized trigger so
    concurrent transactions cannot fork a chain. This hook makes SQLite/dev and
    unit tests use the same wire representation.
    """
    pending = [row for row in session.new if isinstance(row, AuditEvent)]
    if not pending:
        return
    latest_by_scope: dict[str, tuple[int, str]] = {}
    for row in pending:
        scope = row.chain_scope
        latest = latest_by_scope.get(scope)
        if latest is None:
            prior = session.execute(
                select(AuditEvent.chain_sequence, AuditEvent.chain_hash)
                .where(AuditEvent.chain_scope == scope)
                .order_by(AuditEvent.chain_sequence.desc())
                .limit(1)
            ).first()
            latest = (int(prior[0]), str(prior[1])) if prior is not None else (0, _GENESIS_HASH)
        sequence, previous = latest
        row.chain_sequence = sequence + 1
        row.previous_hash = previous
        row.chain_hash = _chain_hash(previous, row.event_signature)
        latest_by_scope[scope] = (row.chain_sequence, row.chain_hash)


def _verification_keys() -> dict[str, bytes]:
    settings = get_settings()
    raw = [
        settings.audit_integrity_key
        or settings.master_key
        or settings.secret_key
        or "vulna-development-audit-integrity-key",
        *(part.strip() for part in settings.audit_integrity_previous_keys.split(",")),
    ]
    keys = [value.encode() for value in raw if value]
    return {_key_id(key): key for key in keys}


def verify_event_signature(event: AuditEvent) -> bool:
    """Verify one event against the current or retained audit signing keys."""
    if event.integrity_algorithm == "legacy-sha256-v1":
        expected = hashlib.sha256(f"legacy-audit-event-v1\0{event.id}".encode()).hexdigest()
        return hmac.compare_digest(event.event_signature, expected)
    key = _verification_keys().get(event.integrity_key_id)
    return key is not None and hmac.compare_digest(event.event_signature, _signature(event, key))


async def verify_audit_chain(
    session: AsyncSession, organization_id: uuid.UUID
) -> dict[str, int | bool | str | None]:
    """Verify every event signature and link for one organization."""
    scope = str(organization_id)
    rows = list(
        (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.chain_scope == scope)
                .order_by(AuditEvent.chain_sequence.asc())
            )
        ).scalars()
    )
    previous = _GENESIS_HASH
    expected_sequence = 1
    legacy_events = 0
    for row in rows:
        if row.chain_sequence != expected_sequence:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "failure": f"sequence gap at {expected_sequence}",
                "last_hash": previous,
            }
        if row.previous_hash != previous:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "failure": f"previous hash mismatch at {expected_sequence}",
                "last_hash": previous,
            }
        if row.chain_hash != _chain_hash(previous, row.event_signature):
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "failure": f"chain hash mismatch at {expected_sequence}",
                "last_hash": previous,
            }
        if not verify_event_signature(row):
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "failure": f"event signature mismatch at {expected_sequence}",
                "last_hash": previous,
                "legacy_events": legacy_events,
            }
        if row.integrity_algorithm == "legacy-sha256-v1":
            legacy_events += 1
        previous = row.chain_hash
        expected_sequence += 1
    return {
        "valid": True,
        "events_checked": len(rows),
        "failure": None,
        "last_hash": previous if rows else None,
        "legacy_events": legacy_events,
    }


def record_audit(
    session: AsyncSession,
    *,
    action: str,
    actor: AuditPrincipal | None = None,
    actor_type: ActorType = ActorType.USER,
    actor_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an audit event to ``session`` and return it (not yet committed).

    Pass ``actor`` for a user action; for system or probe actions pass
    ``actor_type`` (and optionally ``actor_id``) instead.
    """
    event_id = uuid.uuid4()
    resolved_organization = organization_id or (actor.organization_id if actor else None)
    key = _signing_key()
    event = AuditEvent(
        id=event_id,
        organization_id=resolved_organization,
        actor_type=(
            ActorType.SERVICE_ACCOUNT
            if isinstance(actor, ServiceAccount)
            else (ActorType.USER if actor is not None else actor_type)
        ),
        actor_id=actor.id if actor is not None else actor_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        source_ip=source_ip,
        user_agent=user_agent,
        request_id=request_id,
        metadata_json=metadata or {},
        integrity_version=1,
        integrity_algorithm="hmac-sha256-v1",
        integrity_key_id=_key_id(key),
        event_signature="0" * 64,
        chain_scope=str(resolved_organization) if resolved_organization is not None else "global",
        chain_sequence=0,
        previous_hash=_GENESIS_HASH,
        chain_hash=_GENESIS_HASH,
    )
    event.event_signature = _signature(event, key)
    session.add(event)
    return event
