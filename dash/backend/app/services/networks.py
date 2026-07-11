"""Shared helpers for resolving a network's scout and ranges.

Both the full-spectrum workflow and the scan scheduler need "which enrolled scout
runs this network, and over which ranges". Keeping it here means one definition of
scout selection (primary preferred) and target derivation.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import JobStatus, ProbeStatus
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.probe import Probe
from app.models.scan_job import ScanJob

# Non-terminal job statuses: a network with one of these has a test in flight.
_ACTIVE_JOB = (JobStatus.QUEUED, JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING)


async def network_has_active_job(session: AsyncSession, network_id: uuid.UUID) -> bool:
    """True if the network already has a test in flight — used to guarantee at most
    one active test per network (no two scouts testing it at once)."""
    found = (
        await session.execute(
            select(ScanJob.id).where(
                ScanJob.network_id == network_id, ScanJob.status.in_(_ACTIVE_JOB)
            ).limit(1)
        )
    ).first()
    return found is not None


async def ensure_default_network(
    session: AsyncSession, organization_id: uuid.UUID, site_id: uuid.UUID
) -> Network:
    """Find (or create) a site's default network — the home for ranges created via
    the legacy /scopes convenience. Every site probe is bound to it, preserving
    the old site-wide scope semantics now that policy is network-sourced."""
    net = (
        await session.execute(
            select(Network).where(
                Network.site_id == site_id, Network.is_default.is_(True)
            )
        )
    ).scalar_one_or_none()
    if net is None:
        net = Network(
            organization_id=organization_id,
            site_id=site_id,
            name="Site network",
            description="Default network for this site's approved ranges.",
            enabled=True,
            is_default=True,
            policy_version=1,
        )
        session.add(net)
        await session.flush()
    return net


async def bind_all_site_probes(
    session: AsyncSession, network: Network, site_id: uuid.UUID
) -> None:
    """Bind every probe at the site to the network (idempotent). Used to keep a
    site's default network covering all its probes."""
    probes = (
        await session.execute(select(Probe.id).where(Probe.site_id == site_id))
    ).scalars().all()
    existing = set(
        (
            await session.execute(
                select(NetworkScout.probe_id).where(NetworkScout.network_id == network.id)
            )
        ).scalars().all()
    )
    first = not existing
    for probe_id in probes:
        if probe_id not in existing:
            session.add(
                NetworkScout(network_id=network.id, probe_id=probe_id, is_primary=first)
            )
            first = False


async def bind_probe_to_default_network(session: AsyncSession, probe: Probe) -> None:
    """Bind a probe to its site's default network if one exists (called on enroll),
    so ranges added to the site reach a later-enrolled probe."""
    net = (
        await session.execute(
            select(Network).where(
                Network.site_id == probe.site_id, Network.is_default.is_(True)
            )
        )
    ).scalar_one_or_none()
    if net is None:
        return
    already = (
        await session.execute(
            select(NetworkScout.id).where(
                NetworkScout.network_id == net.id, NetworkScout.probe_id == probe.id
            )
        )
    ).scalar_one_or_none()
    if already is None:
        session.add(NetworkScout(network_id=net.id, probe_id=probe.id, is_primary=False))


async def select_network_scout(session: AsyncSession, network_id: uuid.UUID) -> Probe | None:
    """Return an enrolled scout bound to the network — the primary if present,
    otherwise the earliest-bound — or ``None`` if none is available."""
    rows = (
        await session.execute(
            select(Probe, NetworkScout.is_primary)
            .join(NetworkScout, NetworkScout.probe_id == Probe.id)
            .where(
                NetworkScout.network_id == network_id,
                Probe.status == ProbeStatus.ENROLLED,
            )
            .order_by(NetworkScout.is_primary.desc(), Probe.created_at.asc())
        )
    ).all()
    return rows[0][0] if rows else None


async def network_cidrs(session: AsyncSession, network_id: uuid.UUID) -> list[str]:
    """Return the enabled range CIDRs of a network."""
    return list(
        (
            await session.execute(
                select(NetworkScope.cidr).where(
                    NetworkScope.network_id == network_id, NetworkScope.enabled.is_(True)
                )
            )
        ).scalars().all()
    )
