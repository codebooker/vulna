"""enforce at most one active job per network (close the test-lock race)

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-07-11 13:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3b4c5d6e7f8"
down_revision: str | None = "f2a3b4c5d6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Stored enum NAMES are uppercase (native_enum=False stores JobStatus.name).
_WHERE = "network_id IS NOT NULL AND status IN ('QUEUED', 'OFFERED', 'ACCEPTED', 'RUNNING')"


def upgrade() -> None:
    op.create_index(
        "uq_scan_jobs_active_network",
        "scan_jobs",
        ["network_id"],
        unique=True,
        postgresql_where=sa.text(_WHERE),
        sqlite_where=sa.text(_WHERE),
    )


def downgrade() -> None:
    op.drop_index("uq_scan_jobs_active_network", table_name="scan_jobs")
