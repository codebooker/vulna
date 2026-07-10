"""Organization model (build plan Section 9.1).

The MVP may expose only one organization, but organization ownership is carried
throughout the schema so tenant boundaries can be enforced and tested from the
start.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A tenant that owns sites, probes, assets, and findings."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    default_timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    retention_policy_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
