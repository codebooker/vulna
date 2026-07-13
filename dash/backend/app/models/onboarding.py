"""Guided first-run (onboarding) state (Phase 19).

A single resumable record per organization tracks progress through the first-run
wizard so a refreshed or reopened browser never loses its place and never creates
duplicate work. Nothing here authorizes a scan or a scope on its own — approvals
still go through the ordinary, audited scope and job paths.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin

# Ordered wizard steps. Stored as plain strings so adding steps later needs no
# migration.
ONBOARDING_STEPS: tuple[str, ...] = (
    "admin",
    "profile_plan",
    "recovery_codes",
    "health",
    "site",
    "scout",
    "network",
    "scope",
    "preset",
    "launch",
    "results",
)


class OnboardingState(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Resumable first-run wizard state for one organization."""

    __tablename__ = "onboarding_states"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    current_step: Mapped[str] = mapped_column(String(32), nullable=False, default="admin")
    completed_steps_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Soft references to the objects the wizard created (never a scope approval).
    site_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    first_job_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    demo_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    extra_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
