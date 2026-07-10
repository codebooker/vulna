"""Audit event model (build plan Section 9.20).

Application-level audit logs must be append-only: this model exposes only an
immutable ``created_at`` and is never updated or deleted through the API.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ActorType


class AuditEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An append-only record of a security-relevant action."""

    __tablename__ = "audit_events"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_type: Mapped[ActorType] = mapped_column(
        String(16),
        nullable=False,
        default=ActorType.USER,
    )
    # Nullable so failed logins (no known user) and system actions can be logged.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
