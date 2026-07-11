"""Networks: named groups of address ranges under a site, bound to Scouts.

A *network* is how an operator describes a place worth scanning — e.g. "Orlando
LAN" holding the 10.2.0.0/16 ranges — and which VulnaScout(s) reach it. Ranges
are ordinary :class:`~app.models.network_scope.NetworkScope` rows carrying a
``network_id``; the scout binding is the :class:`NetworkScout` association.

By default one scout serves one network, but the association is many-to-many so a
scout can be assigned additional networks — e.g. a Houston scout scanning a
Salisbury branch across an SD-WAN/VPN. Job dispatch targets a network and routes
to one of its bound, enrolled scouts.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Network(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named group of address ranges under a site."""

    __tablename__ = "networks"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # The per-site "default" network holds ranges created via the legacy /scopes
    # convenience and binds every probe at the site, preserving the old site-wide
    # scope behavior now that policy is sourced only from networks.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Bumped whenever the network's ranges or bindings change, so a bound scout's
    # local policy hash shifts and it re-syncs.
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class NetworkScout(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Association binding a Scout (probe) to a network it may scan.

    ``is_primary`` marks the scout that owns the network by default; additional
    (non-primary) bindings cover cross-site reachability (SD-WAN/VPN).
    """

    __tablename__ = "network_scouts"
    __table_args__ = (
        UniqueConstraint("network_id", "probe_id", name="uq_network_scouts_network_probe"),
    )

    network_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("probes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
