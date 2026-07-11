"""Full-spectrum workflow run (build plan Section 13.3).

A run is a multi-stage assessment state machine: precheck → discovery →
assessment → (conditional web/TLS) → candidate validation → approval pause →
validation → evidence → cleanup → verification → reporting. Conditional stages
are skipped when they do not apply, an intrusive stage may be denied at the
approval gate (the workflow then continues safely), and cleanup/verification/
reporting always run when applicable. ``stages_json`` is the per-stage audit
trail.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, Boolean, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import JobMode, WorkflowRunStatus


class WorkflowRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A multi-stage assessment run and its stage trail."""

    __tablename__ = "workflow_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Optional target network: when set, scanning stages run on a scout bound to
    # this network over the network's ranges. When null, the run falls back to the
    # site's first enrolled probe and its whole approved scope.
    network_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("networks.id", ondelete="SET NULL"), nullable=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    mode: Mapped[JobMode] = mapped_column(
        Enum(JobMode, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=JobMode.FULL_SPECTRUM,
    )
    status: Mapped[WorkflowRunStatus] = mapped_column(
        Enum(WorkflowRunStatus, native_enum=False, length=24, validate_strings=True),
        nullable=False,
        default=WorkflowRunStatus.PENDING,
        index=True,
    )
    include_web: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    include_intrusive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    intrusive_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stages_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
