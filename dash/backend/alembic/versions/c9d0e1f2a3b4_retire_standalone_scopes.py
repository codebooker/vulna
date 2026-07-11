"""retire standalone scopes: unify onto per-site default networks

Adds Network.is_default and migrates any scope not yet in a network into its
site's default network, binding the site's probes so policy (now network-only)
keeps reaching them.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-07-11 10:30:00.000000
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9d0e1f2a3b4"
down_revision: str | None = "b8c9d0e1f2a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    bind = op.get_bind()
    # Sites that have orphan scopes (no network yet).
    sites = bind.execute(
        sa.text(
            "SELECT DISTINCT organization_id, site_id FROM network_scopes "
            "WHERE network_id IS NULL"
        )
    ).fetchall()
    for org_id, site_id in sites:
        net_id = uuid.uuid4()
        bind.execute(
            sa.text(
                "INSERT INTO networks "
                "(id, organization_id, site_id, name, description, enabled, is_default, "
                " policy_version, created_at, updated_at) "
                "VALUES (:id, :org, :site, 'Site network', "
                "'Default network for this site''s approved ranges.', :t, :t, 1, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"id": _uid(net_id), "org": org_id, "site": site_id, "t": True},
        )
        bind.execute(
            sa.text(
                "UPDATE network_scopes SET network_id = :net "
                "WHERE site_id = :site AND network_id IS NULL"
            ),
            {"net": _uid(net_id), "site": site_id},
        )
        probes = bind.execute(
            sa.text("SELECT id FROM probes WHERE site_id = :site"), {"site": site_id}
        ).fetchall()
        for i, (probe_id,) in enumerate(probes):
            bind.execute(
                sa.text(
                    "INSERT INTO network_scouts "
                    "(id, network_id, probe_id, is_primary, created_at, updated_at) "
                    "VALUES (:id, :net, :probe, :primary, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                ),
                {
                    "id": _uid(uuid.uuid4()),
                    "net": _uid(net_id),
                    "probe": probe_id,
                    "primary": i == 0,
                },
            )


def _uid(value: uuid.UUID) -> object:
    """Render a UUID the way the app's Uuid type stores it (hex on SQLite,
    canonical on PostgreSQL)."""
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        return str(value)
    return value.hex


def downgrade() -> None:
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.drop_column("is_default")
