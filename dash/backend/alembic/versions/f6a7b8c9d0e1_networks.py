"""networks: named range groups under a site, bound to scouts

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-07-11 09:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: str | None = "e5f6a7b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "networks",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"],
            name=op.f("fk_networks_organization_id_organizations"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name=op.f("fk_networks_site_id_sites"), ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_networks")),
    )
    with op.batch_alter_table("networks", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_networks_organization_id"), ["organization_id"])
        batch_op.create_index(batch_op.f("ix_networks_site_id"), ["site_id"])

    op.create_table(
        "network_scouts",
        sa.Column("network_id", sa.Uuid(), nullable=False),
        sa.Column("probe_id", sa.Uuid(), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"],
            name=op.f("fk_network_scouts_network_id_networks"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["probe_id"], ["probes.id"],
            name=op.f("fk_network_scouts_probe_id_probes"), ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_scouts")),
        sa.UniqueConstraint("network_id", "probe_id", name="uq_network_scouts_network_probe"),
    )
    with op.batch_alter_table("network_scouts", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_network_scouts_network_id"), ["network_id"])
        batch_op.create_index(batch_op.f("ix_network_scouts_probe_id"), ["probe_id"])

    with op.batch_alter_table("network_scopes", schema=None) as batch_op:
        batch_op.add_column(sa.Column("network_id", sa.Uuid(), nullable=True))
        batch_op.create_index(batch_op.f("ix_network_scopes_network_id"), ["network_id"])
        batch_op.create_foreign_key(
            op.f("fk_network_scopes_network_id_networks"), "networks",
            ["network_id"], ["id"], ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("network_scopes", schema=None) as batch_op:
        batch_op.drop_constraint(op.f("fk_network_scopes_network_id_networks"), type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_network_scopes_network_id"))
        batch_op.drop_column("network_id")

    op.drop_table("network_scouts")
    op.drop_table("networks")
