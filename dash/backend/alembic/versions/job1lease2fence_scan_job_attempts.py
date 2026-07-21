"""add leased and fenced scan-job attempts

Revision ID: job1lease2fence
Revises: sch1preset2pin
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "job1lease2fence"
down_revision: str | None = "sch1preset2pin"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "scan_job_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("probe_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("fencing_token", sa.Integer(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("offered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_renewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["probe_id"], ["probes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lease_id", name="uq_job_attempt_lease_id"),
        sa.UniqueConstraint("scan_job_id", "attempt_number", name="uq_job_attempt_number"),
        sa.UniqueConstraint("scan_job_id", "fencing_token", name="uq_job_attempt_fence"),
    )
    op.create_index(
        "ix_job_attempt_active_lease",
        "scan_job_attempts",
        ["scan_job_id", "lease_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scan_job_attempts_lease_expires_at"),
        "scan_job_attempts",
        ["lease_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scan_job_attempts_probe_id"), "scan_job_attempts", ["probe_id"], unique=False
    )
    op.create_index(
        op.f("ix_scan_job_attempts_scan_job_id"),
        "scan_job_attempts",
        ["scan_job_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scan_job_attempts_status"), "scan_job_attempts", ["status"], unique=False
    )
    with op.batch_alter_table("probe_result_uploads") as batch_op:
        batch_op.add_column(sa.Column("scan_job_attempt_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_probe_result_upload_attempt",
            "scan_job_attempts",
            ["scan_job_attempt_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_probe_result_uploads_scan_job_attempt_id",
            ["scan_job_attempt_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("probe_result_uploads") as batch_op:
        batch_op.drop_index("ix_probe_result_uploads_scan_job_attempt_id")
        batch_op.drop_constraint("fk_probe_result_upload_attempt", type_="foreignkey")
        batch_op.drop_column("scan_job_attempt_id")
    op.drop_index(op.f("ix_scan_job_attempts_status"), table_name="scan_job_attempts")
    op.drop_index(op.f("ix_scan_job_attempts_scan_job_id"), table_name="scan_job_attempts")
    op.drop_index(op.f("ix_scan_job_attempts_probe_id"), table_name="scan_job_attempts")
    op.drop_index(op.f("ix_scan_job_attempts_lease_expires_at"), table_name="scan_job_attempts")
    op.drop_index("ix_job_attempt_active_lease", table_name="scan_job_attempts")
    op.drop_table("scan_job_attempts")
