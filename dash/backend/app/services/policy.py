"""Build the signed local policy delivered to a probe.

The local policy is the probe's independent source of truth for what it may
assess: approved CIDRs, allowed modes/plugins, and resource limits. The probe
verifies the Ed25519 signature and enforces the policy itself, so a compromised
orchestrator cannot direct a probe outside its approved scope.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.probe import Probe
from app.models.relay import Relay

# Modes and plugins permitted for non-intrusive assessment: Nmap discovery,
# Nuclei vulnerability checks, testssl.sh TLS analysis, and passive ZAP.
_DEFAULT_ALLOWED_MODES = ["vulnerability_assessment"]
_DEFAULT_ALLOWED_PLUGINS = ["nmap", "nuclei", "testssl", "zap"]

_DEFAULT_LIMITS = {
    "max_hosts": 256,
    "max_parallel_hosts": 8,
    "max_packets_per_second": 1000,
    "max_duration_seconds": 10800,
}

_DURATION_HOST_STEP = 256
_MAX_DURATION_SECONDS = 24 * 60 * 60


def duration_limit_for_hosts(hosts: int) -> int:
    """Scale the signed workflow budget with explicitly approved scope size.

    Three hours remains the conservative budget for up to one /24. Larger host
    limits get another three-hour block per 256 addresses, capped at 24 hours so
    an abandoned job never becomes open-ended.
    """
    steps = max(1, (max(1, hosts) + _DURATION_HOST_STEP - 1) // _DURATION_HOST_STEP)
    return min(_MAX_DURATION_SECONDS, _DEFAULT_LIMITS["max_duration_seconds"] * steps)


async def _probe_scopes(session: AsyncSession, probe: Probe) -> list[NetworkScope]:
    """Return the enabled ranges this probe may assess.

    Scope is sourced solely from networks the scout is bound to via
    :class:`NetworkScout` — the standalone/per-probe-pinned scope model is retired.
    A site's ranges reach its probes through the site's default network; a scout
    can also be bound to another site's network to scan it across an SD-WAN/VPN.
    """
    bound_networks = (
        select(NetworkScout.network_id)
        .join(Network, Network.id == NetworkScout.network_id)
        .where(NetworkScout.probe_id == probe.id, Network.enabled.is_(True))
    )
    result = await session.execute(
        select(NetworkScope)
        .where(
            NetworkScope.enabled.is_(True),
            NetworkScope.network_id.in_(bound_networks),
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
    managed_relay_ids: set[str] = set()
    ordinary_scopes: list[NetworkScope] = []
    for scope in scopes:
        prefix = "Managed by relay "
        if scope.notes and scope.notes.startswith(prefix):
            managed_relay_ids.add(scope.notes.removeprefix(prefix).strip())
            if probe.name != settings.relay_scanner_probe_name:
                continue
        ordinary_scopes.append(scope)
    scopes = ordinary_scopes
    approved = [s.cidr for s in scopes]
    denied: list[str] = []
    if managed_relay_ids and probe.name == settings.relay_scanner_probe_name:
        relay_ids = []
        for value in managed_relay_ids:
            try:
                relay_ids.append(uuid.UUID(value))
            except ValueError:
                continue
        if relay_ids:
            relays = (
                await session.execute(select(Relay).where(Relay.id.in_(relay_ids)))
            ).scalars()
            denied = sorted({cidr for relay in relays for cidr in relay.denied_cidrs_json})
    allow_public = any(s.allow_public_addresses for s in scopes)
    # The policy version tracks the latest scope change for the probe's site.
    policy_version = max((s.policy_version for s in scopes), default=0)

    max_hosts = _int_or_default(
        [s.maximum_hosts for s in scopes], _DEFAULT_LIMITS["max_hosts"]
    )
    limits = {
        "max_hosts": max_hosts,
        "max_parallel_hosts": _int_or_default(
            [s.maximum_concurrency for s in scopes], _DEFAULT_LIMITS["max_parallel_hosts"]
        ),
        "max_packets_per_second": _int_or_default(
            [s.maximum_packets_per_second for s in scopes],
            _DEFAULT_LIMITS["max_packets_per_second"],
        ),
        "max_duration_seconds": duration_limit_for_hosts(max_hosts),
    }

    # Controlled-pentest mode, Metasploit, and active ZAP are permitted only for a
    # scout an operator has explicitly enabled. Passive ZAP remains part of the
    # ordinary assessment policy; the Scout independently rejects a limited-active
    # ZAP profile unless this signed flag is true.
    allowed_modes = list(_DEFAULT_ALLOWED_MODES)
    allowed_plugins = list(_DEFAULT_ALLOWED_PLUGINS)
    if getattr(probe, "pentest_enabled", False):
        allowed_modes.append("controlled_pentest")
        allowed_plugins.append("metasploit")
    credentialed_scans_allowed = bool(
        getattr(probe, "credentialed_scans_enabled", False)
        and getattr(probe, "encryption_public_key_b64", None)
    )
    if credentialed_scans_allowed:
        allowed_plugins.extend(["ssh_inventory", "winrm_inventory"])

    # The document is deterministic given the probe's scopes/limits so its hash
    # is stable across fetches; the probe uses that hash for change detection.
    return {
        "policy_version": policy_version,
        "probe_id": str(probe.id),
        "site_id": str(probe.site_id),
        "approved_cidrs": approved,
        "denied_cidrs": denied,
        "allow_public_addresses": allow_public,
        "allowed_modes": allowed_modes,
        "allowed_plugins": allowed_plugins,
        "active_web_scans_allowed": bool(getattr(probe, "pentest_enabled", False)),
        "credentialed_scans_allowed": credentialed_scans_allowed,
        "limits": limits,
    }
