"""Build the signed local policy delivered to a probe.

The local policy is the probe's independent source of truth for what it may
assess: approved CIDRs, allowed modes/plugins, and resource limits. The probe
verifies the Ed25519 signature and enforces the policy itself, so a compromised
orchestrator cannot direct a probe outside its approved scope.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.network_scope import NetworkScope
from app.models.probe import Probe

# Modes and plugins permitted in Phase 3. Vulnerability assessment with Nmap
# discovery is the baseline; more are unlocked in later phases.
_DEFAULT_ALLOWED_MODES = ["vulnerability_assessment"]
_DEFAULT_ALLOWED_PLUGINS = ["nmap"]

_DEFAULT_LIMITS = {
    "max_hosts": 256,
    "max_parallel_hosts": 8,
    "max_packets_per_second": 1000,
    "max_duration_seconds": 10800,
}


async def _probe_scopes(session: AsyncSession, probe: Probe) -> list[NetworkScope]:
    """Return the enabled scopes that apply to this probe (site-wide or assigned)."""
    result = await session.execute(
        select(NetworkScope)
        .where(
            NetworkScope.site_id == probe.site_id,
            NetworkScope.enabled.is_(True),
            or_(NetworkScope.probe_id.is_(None), NetworkScope.probe_id == probe.id),
        )
        .order_by(NetworkScope.cidr.asc())
    )
    return list(result.scalars().all())


def _int_or_default(values: list[int | None], default: int) -> int:
    """Return the smallest positive limit among values, or the default."""
    present = [v for v in values if isinstance(v, int) and v > 0]
    return min(present) if present else default


async def build_policy_document(
    session: AsyncSession, probe: Probe, settings: Settings
) -> dict[str, Any]:
    """Build the unsigned local-policy payload for a probe."""
    scopes = await _probe_scopes(session, probe)
    approved = [s.cidr for s in scopes]
    allow_public = any(s.allow_public_addresses for s in scopes)
    # The policy version tracks the latest scope change for the probe's site.
    policy_version = max((s.policy_version for s in scopes), default=0)

    limits = {
        "max_hosts": _int_or_default(
            [s.maximum_hosts for s in scopes], _DEFAULT_LIMITS["max_hosts"]
        ),
        "max_parallel_hosts": _int_or_default(
            [s.maximum_concurrency for s in scopes], _DEFAULT_LIMITS["max_parallel_hosts"]
        ),
        "max_packets_per_second": _int_or_default(
            [s.maximum_packets_per_second for s in scopes],
            _DEFAULT_LIMITS["max_packets_per_second"],
        ),
        "max_duration_seconds": _DEFAULT_LIMITS["max_duration_seconds"],
    }

    # The document is deterministic given the probe's scopes/limits so its hash
    # is stable across fetches; the probe uses that hash for change detection.
    return {
        "policy_version": policy_version,
        "probe_id": str(probe.id),
        "site_id": str(probe.site_id),
        "approved_cidrs": approved,
        "denied_cidrs": [],
        "allow_public_addresses": allow_public,
        "allowed_modes": list(_DEFAULT_ALLOWED_MODES),
        "allowed_plugins": list(_DEFAULT_ALLOWED_PLUGINS),
        "limits": limits,
    }
