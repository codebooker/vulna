"""Redacted support bundle and local event timeline (Phase 26).

The support bundle is built from an **allowlist**: only explicitly listed,
non-sensitive fields are copied from each source. It never includes passwords,
tokens, private keys, authorization headers, raw credentials, unrestricted
evidence, or full scanner output. A pattern-based secret scanner runs afterward as
a second line of defense (not the primary control), and the bundle is returned as
a *preview* for the operator to review before exporting.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.audit import AuditEvent
from app.models.enums import JobStatus
from app.models.feed_health import FeedHealth
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.services.diagnostics import as_dicts, run_diagnostics, summarize

# The manifest documents exactly which sections and fields are included so a
# reviewer knows what is being shared.
BUNDLE_MANIFEST: list[dict[str, Any]] = [
    {"section": "system", "fields": ["service", "version", "environment", "generated_at"]},
    {
        "section": "diagnostics",
        "fields": ["summary", "checks(component,status,impact,data_safety,next_step)"],
    },
    {"section": "feeds", "fields": ["source", "status", "last_success_at", "last_attempt_at"]},
    {
        "section": "probes",
        "fields": [
            "name", "status", "last_seen_at", "certificate_expires_at",
            "operating_system", "architecture", "agent_version",
        ],
    },
    {
        "section": "recent_events",
        "fields": ["action", "actor_type", "target_type", "created_at"],
    },
]


async def build_support_bundle(
    session: AsyncSession, settings: Settings, org_id: uuid.UUID, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)

    diagnostics = await run_diagnostics(session, settings, org_id, now)

    feeds = (await session.execute(select(FeedHealth))).scalars().all()
    probes = (
        await session.execute(select(Probe).where(Probe.organization_id == org_id))
    ).scalars().all()
    events = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.organization_id == org_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(50)
        )
    ).scalars().all()

    bundle: dict[str, Any] = {
        "system": {
            "service": settings.app_name,
            "version": settings.version,
            "environment": settings.env,
            "generated_at": now.isoformat(),
        },
        "diagnostics": {"summary": summarize(diagnostics), "checks": as_dicts(diagnostics)},
        # Allowlisted, non-sensitive fields only.
        "feeds": [
            {
                "source": f.source.value,
                "status": f.status.value,
                "last_success_at": _iso(f.last_success_at),
                "last_attempt_at": _iso(f.last_attempt_at),
            }
            for f in feeds
        ],
        "probes": [
            {
                "name": p.name,
                "status": p.status.value,
                "last_seen_at": _iso(p.last_seen_at),
                "certificate_expires_at": _iso(p.certificate_expires_at),
                "operating_system": p.operating_system,
                "architecture": p.architecture,
                "agent_version": p.agent_version,
            }
            for p in probes
        ],
        # Only action/type/timestamp — never the audit metadata (which can carry
        # IPs, short codes, or other detail).
        "recent_events": [
            {
                "action": e.action,
                "actor_type": e.actor_type,
                "target_type": e.target_type,
                "created_at": _iso(e.created_at),
            }
            for e in events
        ],
    }

    scan = scan_for_secrets(bundle)
    return {"manifest": BUNDLE_MANIFEST, "bundle": bundle, "secret_scan": scan}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


# Defense-in-depth patterns (the allowlist is the primary control).
_SECRET_PATTERNS = [
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("password_field", re.compile(r'"(password|passphrase|secret|token)"\s*:', re.IGNORECASE)),
    ("authorization_header", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{10,}")),
]


def scan_for_secrets(data: Any) -> dict[str, Any]:
    """Scan a serialized bundle for accidental secrets. Returns findings (empty when
    clean). This is a second line of defense on top of the allowlist build."""
    import json

    text = json.dumps(data)
    findings: list[str] = []
    for name, pat in _SECRET_PATTERNS:
        if pat.search(text):
            findings.append(name)
    return {"clean": len(findings) == 0, "findings": findings}


async def build_timeline(
    session: AsyncSession, org_id: uuid.UUID, limit: int = 40
) -> list[dict[str, Any]]:
    """Return a local event timeline: recent audited actions plus failed jobs,
    newest first. Contains no secrets (action/type/timestamp only)."""
    events = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.organization_id == org_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    timeline = [
        {
            "when": e.created_at.isoformat(),
            "kind": e.action,
            "summary": f"{e.actor_type} · {e.action}"
            + (f" · {e.target_type}" if e.target_type else ""),
        }
        for e in events
    ]

    failed = (
        await session.execute(
            select(ScanJob)
            .where(ScanJob.organization_id == org_id, ScanJob.status == JobStatus.FAILED)
            .order_by(ScanJob.created_at.desc())
            .limit(10)
        )
    ).scalars().all()
    for j in failed:
        timeline.append(
            {
                "when": (j.finished_at or j.created_at).isoformat(),
                "kind": "job_failed",
                "summary": f"scan job {j.mode.value} failed"
                + (f": {j.error_code}" if j.error_code else ""),
            }
        )

    timeline.sort(key=lambda t: t["when"], reverse=True)
    return timeline[:limit]
