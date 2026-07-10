"""Rules of Engagement model (build plan Section 9.6).

The authorization envelope for controlled testing at an organization: what is
allowed and prohibited, the permitted hours, contacts, evidence/retention and
session policy, and whether cleanup is required. Controlled-pentest sessions
reference a versioned, approved Rules-of-Engagement record.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class RulesOfEngagement(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named, versioned rules-of-engagement record."""

    __tablename__ = "rules_of_engagement"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_actions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    prohibited_actions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_hours_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    emergency_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_policy_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    data_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    session_policy_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    cleanup_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
