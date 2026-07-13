"""Asset and asset-identifier models (build plan Sections 9.10–9.11).

An asset is a device or system discovered at a site. Assets are identified by
weighted identifiers (IP, MAC, hostname, …) rather than by IP alone, so repeated
scans update an existing asset rather than creating duplicates.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
    DataClassification,
    IdentifierType,
)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A discovered device or system."""

    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=AssetType.UNKNOWN,
    )
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=AssetStatus.ACTIVE,
    )
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    identity_confidence: Mapped[int] = mapped_column(nullable=False, default=50)

    # Structured operator context. Neutral defaults preserve the meaning of
    # existing inventory until an administrator classifies it.
    department: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    business_function: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(
            AssetEnvironment,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetEnvironment.UNKNOWN,
        index=True,
    )
    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(
            AssetCriticality,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetCriticality.UNKNOWN,
        index=True,
    )
    data_classification: Mapped[DataClassification] = mapped_column(
        Enum(
            DataClassification,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=DataClassification.UNKNOWN,
        index=True,
    )
    internet_exposed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    context_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_assessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    identifiers: Mapped[list[AssetIdentifier]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )


class AssetIdentifier(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A stable identifier that ties observations to an asset."""

    __tablename__ = "asset_identifiers"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "identifier_type",
            "identifier_value",
            name="uq_asset_identifiers_asset_type_value",
        ),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identifier_type: Mapped[IdentifierType] = mapped_column(
        Enum(IdentifierType, native_enum=False, length=32, validate_strings=True), nullable=False
    )
    identifier_value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(nullable=False, default=50)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="identifiers")
