"""phase 27: probe result upload idempotency

Revision ID: a1b2c3d4e5f6
Revises: 5fa1afe0d8e3
Create Date: 2026-07-11 03:20:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "5fa1afe0d8e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "probe_result_uploads",
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_probe_result_uploads_scan_job_id_scan_jobs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_probe_result_uploads")),
        sa.UniqueConstraint(
            "scan_job_id", "idempotency_key", name="uq_probe_result_uploads_job_key"
        ),
    )
    with op.batch_alter_table("probe_result_uploads", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_probe_result_uploads_scan_job_id"),
            ["scan_job_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("probe_result_uploads", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_probe_result_uploads_scan_job_id"))
    op.drop_table("probe_result_uploads")
