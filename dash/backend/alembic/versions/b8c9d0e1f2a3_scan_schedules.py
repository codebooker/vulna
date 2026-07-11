"""scheduled scans

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-07-11 10:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8c9d0e1f2a3"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MODE = sa.Enum(
    "VULNERABILITY_ASSESSMENT", "CONTROLLED_PENTEST", "FULL_SPECTRUM",
    name="jobmode", native_enum=False, length=32,
)


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("network_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("mode", _MODE, nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.Uuid(), nullable=True),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
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
            name=op.f("fk_scan_schedules_organization_id_organizations"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"],
            name=op.f("fk_scan_schedules_network_id_networks"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["last_job_id"], ["scan_jobs.id"],
            name=op.f("fk_scan_schedules_last_job_id_scan_jobs"), ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"],
            name=op.f("fk_scan_schedules_created_by_users"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_schedules")),
    )
    with op.batch_alter_table("scan_schedules", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_scan_schedules_organization_id"), ["organization_id"]
        )
        batch_op.create_index(batch_op.f("ix_scan_schedules_network_id"), ["network_id"])
        batch_op.create_index(batch_op.f("ix_scan_schedules_next_run_at"), ["next_run_at"])


def downgrade() -> None:
    op.drop_table("scan_schedules")
