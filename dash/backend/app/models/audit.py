"""Audit event model (build plan Section 9.20).

Application-level audit logs must be append-only: this model exposes only an
immutable ``created_at`` and is never updated or deleted through the API.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, BigInteger, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ActorType


class AuditEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An append-only record of a security-relevant action."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("chain_scope", "chain_sequence", name="uq_audit_chain_sequence"),
    )

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
    # New events are authenticated with a deployment-held HMAC key and linked in
    # an organization-local SHA-256 chain. PostgreSQL assigns the final chain
    # position in a serialized trigger; the ORM hook provides identical behavior
    # for SQLite development/tests. Keeping the signature key outside PostgreSQL
    # means a database-only compromise cannot silently rewrite history.
    integrity_version: Mapped[int] = mapped_column(nullable=False, default=1)
    integrity_algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default="hmac-sha256-v1"
    )
    integrity_key_id: Mapped[str] = mapped_column(String(16), nullable=False)
    event_signature: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_scope: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    chain_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
