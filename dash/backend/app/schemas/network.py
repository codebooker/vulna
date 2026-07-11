"""Schemas for networks: named range groups under a site, bound to scouts."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NetworkRangeCreate(BaseModel):
    """A single address range to add to a network."""

    cidr: str = Field(min_length=1, max_length=64)
    allow_public_addresses: bool = False
    maximum_hosts: int | None = Field(default=None, ge=1)
    maximum_packets_per_second: int | None = Field(default=None, ge=1)
    maximum_concurrency: int | None = Field(default=None, ge=1)


class NetworkRangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cidr: str
    enabled: bool
    allow_public_addresses: bool
    maximum_hosts: int | None
    maximum_packets_per_second: int | None
    maximum_concurrency: int | None


class NetworkScoutBind(BaseModel):
    """Bind a scout (probe) to a network."""

    probe_id: uuid.UUID
    is_primary: bool = False


class NetworkScoutRead(BaseModel):
    probe_id: uuid.UUID
    probe_name: str
    is_primary: bool


class NetworkCreate(BaseModel):
    site_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    ranges: list[NetworkRangeCreate] = Field(default_factory=list)
    scouts: list[NetworkScoutBind] = Field(default_factory=list)


class NetworkUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None


class NetworkRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    name: str
    description: str | None
    enabled: bool
    policy_version: int
    ranges: list[NetworkRangeRead] = Field(default_factory=list)
    scouts: list[NetworkScoutRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
