"""scan jobs: target network (per-network test lock)

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-07-11 11:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d0e1f2a3b4c5"
down_revision: str | None = "c9d0e1f2a3b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("network_id", sa.Uuid(), nullable=True))
        batch_op.create_index(batch_op.f("ix_scan_jobs_network_id"), ["network_id"])
        batch_op.create_foreign_key(
            op.f("fk_scan_jobs_network_id_networks"), "networks",
            ["network_id"], ["id"], ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.drop_constraint(op.f("fk_scan_jobs_network_id_networks"), type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_scan_jobs_network_id"))
        batch_op.drop_column("network_id")
