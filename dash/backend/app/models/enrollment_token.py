"""One-time probe enrollment token (build plan Section 10).

The secret token value is never stored — only its SHA-256 hash — so a database
read cannot recover a usable token. Tokens are single-use and expire after a
short TTL (default 15 minutes).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class EnrollmentToken(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A single-use, expiring token that authorizes one probe enrollment."""

    __tablename__ = "enrollment_tokens"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 hex of the token secret; the secret itself is shown once and never stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Short human-readable code for out-of-band verification / display.
    short_code: Mapped[str] = mapped_column(String(16), nullable=False)
    # Suggested probe identity, applied when the token is consumed.
    probe_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_probe_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
