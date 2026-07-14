"""CVE intelligence models (build plan Sections 9.13 and 9.14).

``CveRecord`` mirrors an upstream CVE (NVD), and ``ThreatIntelEnrichment`` holds
the volatile threat signals layered on top of it (CISA KEV membership, EPSS
scoring, exploit availability). They are keyed by ``cve_id`` rather than a
surrogate UUID because the CVE identifier is the natural, stable key and is how
findings reference them. Enrichment is a separate table because it changes on a
different cadence than the CVE record and can exist before the CVE itself has
been synced from NVD (e.g. a CVE that appears in KEV first).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin


class CveRecord(TimestampMixin, Base):
    """A locally cached CVE record synced from NVD (build plan Section 9.13)."""

    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_v2_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    cvss_v3_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    cvss_v4_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    cwe_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cpe_matches_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="nvd")
    rejected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CveProductIndex(Base):
    """Maps a CPE product name to each CVE whose CPE matches reference it.

    Correlation needs "which CVEs mention product X"; ``cve_records`` only stores
    the CPE matches as JSON, so answering that without this table means scanning
    every row. Maintained alongside ``CveRecord`` on NVD sync. The composite
    primary key ``(product, cve_id)`` also serves the product-prefix lookup, so
    no extra index is required.
    """

    __tablename__ = "cve_product_index"

    product: Mapped[str] = mapped_column(String(255), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)


class ThreatIntelEnrichment(TimestampMixin, Base):
    """KEV/EPSS/exploit signals for a CVE (build plan Section 9.14)."""

    __tablename__ = "threat_intel_enrichments"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    previous_epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    public_exploit_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploit_reference_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    last_enriched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
