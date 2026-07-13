"""scan progress and sanitized failure observability

Revision ID: 0b1c2d3e4f5a
Revises: f0a1b2c3d4e5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0b1c2d3e4f5a"
down_revision: str | None = "f0a1b2c3d4e5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(
            sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("progress_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.add_column(sa.Column("estimated_completion_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("last_progress_at", sa.DateTime(timezone=True)))
        batch.add_column(
            sa.Column("failure_log_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'"))
        )
    op.execute("UPDATE scan_jobs SET progress_percent = 100 WHERE status = 'COMPLETED'")


def downgrade() -> None:
    # Detailed progress/failure history is irrecoverably removed. Export the
    # operator diagnostics you need and take a verified encrypted backup first.
    with op.batch_alter_table("scan_jobs") as batch:
        for column in (
            "failure_log_json",
            "last_progress_at",
            "estimated_completion_at",
            "progress_json",
            "progress_percent",
        ):
            batch.drop_column(column)
