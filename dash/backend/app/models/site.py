"""Site model (build plan Section 9.2).

A site is a physical or logical location owned by an organization. Probes,
network scopes, assets, and findings are scoped to a site.
"""

from __future__ import annotations

import uuid

from sqlalchemy import JSON, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Site(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A location that probes assess and against which findings are recorded."""

    __tablename__ = "sites"
    __table_args__ = (
        # A site code is unique within its organization.
        UniqueConstraint("organization_id", "code", name="uq_sites_organization_id_code"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    address: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    business_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    technical_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
