"""Network-scope schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NetworkScopeRead(BaseModel):
    """Network scope as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    network_id: uuid.UUID
    probe_id: uuid.UUID | None
    name: str
    cidr: str
    enabled: bool
    allow_public_addresses: bool
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    expires_at: datetime | None
    maximum_hosts: int | None
    maximum_packets_per_second: int | None
    maximum_concurrency: int | None
    notes: str | None
    policy_version: int
    created_at: datetime
    updated_at: datetime


class NetworkScopeCreate(BaseModel):
    """Payload to create a network scope (administrator only).

    The ``cidr`` is normalized and validated server-side; public ranges require
    ``allow_public_addresses`` to be true.
    """

    site_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    cidr: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    allow_public_addresses: bool = False
    expires_at: datetime | None = None
    maximum_hosts: int | None = Field(default=None, ge=1)
    maximum_packets_per_second: int | None = Field(default=None, ge=1)
    maximum_concurrency: int | None = Field(default=None, ge=1)
    notes: str | None = Field(default=None, max_length=2048)


class NetworkScopeUpdate(BaseModel):
    """Partial update for a network scope (administrator only)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    cidr: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    allow_public_addresses: bool | None = None
    expires_at: datetime | None = None
    maximum_hosts: int | None = Field(default=None, ge=1)
    maximum_packets_per_second: int | None = Field(default=None, ge=1)
    maximum_concurrency: int | None = Field(default=None, ge=1)
    notes: str | None = Field(default=None, max_length=2048)
