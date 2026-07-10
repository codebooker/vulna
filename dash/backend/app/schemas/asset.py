"""Asset and service read schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import (
    AssetStatus,
    AssetType,
    IdentifierType,
    ServiceState,
    ServiceTransport,
)


class AssetIdentifierRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    identifier_type: IdentifierType
    identifier_value: str
    confidence: int
    last_seen_at: datetime | None


class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    transport: ServiceTransport
    port: int
    state: ServiceState
    service_name: str | None
    product: str | None
    version: str | None
    cpe: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    canonical_name: str
    asset_type: AssetType
    status: AssetStatus
    operating_system: str | None
    manufacturer: str | None
    identity_confidence: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    last_assessed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    """An asset with its identifiers and services."""

    identifiers: list[AssetIdentifierRead]
    services: list[ServiceRead]
