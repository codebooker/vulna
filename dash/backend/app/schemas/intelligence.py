"""Schemas for VulnaWatch intelligence: feed health, CVE records, sync results."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import FeedSource, FeedStatus


class FeedHealthRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: FeedSource
    status: FeedStatus
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    records_processed: int
    records_changed: int
    attempts: int
    error: str | None
    last_source_timestamp: str | None
    updated_at: datetime


class EnrichmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    is_kev: bool
    kev_date_added: date | None
    kev_due_date: date | None
    kev_required_action: str | None
    known_ransomware_use: bool
    epss_score: float | None
    epss_percentile: float | None
    epss_date: date | None
    public_exploit_available: bool
    last_enriched_at: datetime | None


class CveRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    published_at: datetime | None
    modified_at: datetime | None
    description: str | None
    cvss_v2_json: dict[str, Any] | None
    cvss_v3_json: dict[str, Any] | None
    cvss_v4_json: dict[str, Any] | None
    cwe_ids_json: list[str]
    cpe_matches_json: list[dict[str, Any]]
    references_json: list[str]
    source: str
    rejected: bool
    last_synced_at: datetime | None


class CveDetail(BaseModel):
    """A CVE record joined with its threat-intel enrichment."""

    cve: CveRecordRead
    enrichment: EnrichmentRead | None


class SyncResultRead(BaseModel):
    source: FeedSource
    status: FeedStatus
    attempts: int
    records_processed: int
    records_changed: int
    change_events: int
    error: str | None
