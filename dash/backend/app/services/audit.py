"""Audit logging service.

A thin helper that appends an :class:`AuditEvent` to the current session. Audit
events are written within the same transaction as the action they describe, so
a change and its audit record commit together (or not at all).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent
from app.models.enums import ActorType
from app.models.user import User


def record_audit(
    session: AsyncSession,
    *,
    action: str,
    actor: User | None = None,
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
    event = AuditEvent(
        organization_id=organization_id or (actor.organization_id if actor else None),
        actor_type=ActorType.USER if actor is not None else actor_type,
        actor_id=actor.id if actor is not None else actor_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        source_ip=source_ip,
        user_agent=user_agent,
        request_id=request_id,
        metadata_json=metadata or {},
    )
    session.add(event)
    return event
