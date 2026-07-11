"""Privacy, data-ownership, and outbound transparency (Phase 31).

Vulna is self-hosted so the operator keeps control of their data. This module
makes that concrete and inspectable:

* **Outbound transparency** — enumerate every place data can leave the deployment
  (intelligence feeds, configured SMTP and webhooks) and what does *not* leave
  (the app never contacts a release server; there is no telemetry endpoint).
* **Secret inventory** — list configured secrets and whether they are set, without
  ever revealing a value.
* **Telemetry** — off by default; opt-in only, with a field-level preview of the
  strictly anonymous, aggregate payload. Disabling telemetry or update checks
  never affects scanning, reporting, remediation, or local intelligence import.
* **Local analytics** — the same aggregate usage counts, computed locally and
  never transmitted.

Toggles live in the organization's ``settings_json`` (no schema change).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import Settings
from app.models.asset import Asset
from app.models.enums import Severity, UserRole
from app.models.finding import Finding
from app.models.notification import CHANNEL_EMAIL, CHANNEL_WEBHOOK, NotificationChannel
from app.models.organization import Organization
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.models.user import User

# Privacy toggles and their privacy-preserving defaults. Telemetry is OFF; nothing
# is opted in by default.
PRIVACY_DEFAULTS: dict[str, bool] = {
    "telemetry_enabled": False,
    "update_check_enabled": True,
    "intelligence_feeds_enabled": True,
    "local_analytics_enabled": True,
}

TELEMETRY_SCHEMA_VERSION = "1"


def get_privacy_settings(org: Organization) -> dict[str, bool]:
    stored = org.settings_json or {}
    return {key: bool(stored.get(key, default)) for key, default in PRIVACY_DEFAULTS.items()}


def set_privacy_settings(org: Organization, updates: dict[str, bool]) -> dict[str, bool]:
    """Apply explicit toggle changes. Only known keys are honored; an opt-in is
    never inferred — the caller must set the value explicitly."""
    settings = dict(org.settings_json or {})
    for key, value in updates.items():
        if key in PRIVACY_DEFAULTS:
            settings[key] = bool(value)
    org.settings_json = settings
    flag_modified(org, "settings_json")
    return get_privacy_settings(org)


# --------------------------------------------------------------------------- #
# Outbound transparency
# --------------------------------------------------------------------------- #


async def outbound_connections(
    session: AsyncSession, settings: Settings, org: Organization
) -> list[dict[str, Any]]:
    """Every destination the deployment may contact, and whether it is enabled."""
    toggles = get_privacy_settings(org)
    feeds_on = toggles["intelligence_feeds_enabled"]

    out: list[dict[str, Any]] = [
        {
            "name": "NVD (CVE data)", "category": "intelligence",
            "destination": _host(settings.nvd_api_url), "enabled": feeds_on,
            "purpose": "Download CVE records to enrich findings.",
        },
        {
            "name": "CISA KEV", "category": "intelligence",
            "destination": _host(settings.kev_feed_url), "enabled": feeds_on,
            "purpose": "Download the known-exploited-vulnerabilities catalog.",
        },
        {
            "name": "EPSS", "category": "intelligence",
            "destination": _host(settings.epss_feed_url), "enabled": feeds_on,
            "purpose": "Download exploitation-probability scores.",
        },
        {
            "name": "Update checks", "category": "updates",
            "destination": None, "enabled": False,
            "purpose": (
                "The application never contacts a release server. Updates are run by "
                "the operator with the signed `vulna` CLI."
            ),
        },
    ]

    channels = (
        await session.execute(
            select(NotificationChannel).where(
                NotificationChannel.organization_id == org.id,
                NotificationChannel.enabled.is_(True),
            )
        )
    ).scalars().all()
    for ch in channels:
        if ch.channel_type == CHANNEL_EMAIL:
            out.append({
                "name": f"SMTP: {ch.name}", "category": "notifications",
                "destination": ch.config_json.get("host"), "enabled": True,
                "purpose": "Send email notifications you configured.",
            })
        elif ch.channel_type == CHANNEL_WEBHOOK:
            out.append({
                "name": f"Webhook: {ch.name}", "category": "notifications",
                "destination": _host(str(ch.config_json.get("url", ""))), "enabled": True,
                "purpose": "Send webhook notifications you configured.",
            })

    if toggles["telemetry_enabled"]:
        out.append({
            "name": "Anonymous telemetry", "category": "telemetry",
            "destination": (org.settings_json or {}).get("telemetry_endpoint"),
            "enabled": True,
            "purpose": "Send strictly anonymous, aggregate usage counts (opt-in).",
        })
    return out


def _host(url: str) -> str | None:
    from urllib.parse import urlsplit

    if not url:
        return None
    return urlsplit(url).hostname or url


# --------------------------------------------------------------------------- #
# Secret inventory (never values)
# --------------------------------------------------------------------------- #


async def secret_inventory(
    session: AsyncSession, settings: Settings, org: Organization
) -> list[dict[str, Any]]:
    """List configured secrets and whether they are set. Never returns a value."""
    admin_count = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.organization_id == org.id, User.role == UserRole.ADMINISTRATOR)
    )
    channel_secrets = await session.scalar(
        select(func.count())
        .select_from(NotificationChannel)
        .where(
            NotificationChannel.organization_id == org.id,
            NotificationChannel.encrypted_secret.is_not(None),
        )
    )
    return [
        {"name": "Application secret key", "present": settings.secret_key is not None,
         "category": "core", "rotatable": True},
        {"name": "Administrator account", "present": bool(admin_count),
         "category": "core", "rotatable": True},
        {"name": "Internal CA private key", "present": Path(settings.ca_key_path).exists(),
         "category": "pki", "rotatable": True},
        {"name": "Job/policy signing key", "present": Path(settings.job_signing_key_path).exists(),
         "category": "pki", "rotatable": True},
        {"name": "NVD API key", "present": settings.nvd_api_key is not None,
         "category": "intelligence", "rotatable": True},
        {"name": "Notification channel secrets", "present": bool(channel_secrets),
         "category": "notifications", "rotatable": True,
         "count": int(channel_secrets or 0)},
    ]


# --------------------------------------------------------------------------- #
# Telemetry preview + local analytics (aggregate, no PII)
# --------------------------------------------------------------------------- #


async def _aggregate_counts(session: AsyncSession, org_id: uuid.UUID) -> dict[str, int]:
    sites = await session.scalar(
        select(func.count()).select_from(Site).where(Site.organization_id == org_id)
    )
    assets = await session.scalar(
        select(func.count()).select_from(Asset).where(Asset.organization_id == org_id)
    )
    scans = await session.scalar(
        select(func.count()).select_from(ScanJob).where(ScanJob.organization_id == org_id)
    )
    findings = await session.scalar(
        select(func.count()).select_from(Finding).where(Finding.organization_id == org_id)
    )
    criticals = await session.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.organization_id == org_id, Finding.severity == Severity.CRITICAL
        )
    )
    return {
        "sites": int(sites or 0),
        "assets": int(assets or 0),
        "scans": int(scans or 0),
        "findings": int(findings or 0),
        "critical_findings": int(criticals or 0),
    }


async def telemetry_preview(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID
) -> dict[str, Any]:
    """The exact anonymous payload telemetry *would* send, for a field-level review.

    By construction it contains only aggregate counts and the product version. It
    never contains IP addresses, hostnames, usernames, findings, CVEs tied to
    assets, evidence, credentials, report contents, or a stable cross-installation
    identifier.
    """
    counts = await _aggregate_counts(session, org_id)
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "vulna_version": settings.version,
        "counts": counts,
        "excluded": [
            "ip_addresses", "hostnames", "usernames", "findings", "cves",
            "evidence", "credentials", "report_contents", "install_identifier",
        ],
    }


async def local_analytics(session: AsyncSession, org_id: uuid.UUID) -> dict[str, Any]:
    """Aggregate usage counts computed locally and never transmitted."""
    return {"transmitted": False, "counts": await _aggregate_counts(session, org_id)}
