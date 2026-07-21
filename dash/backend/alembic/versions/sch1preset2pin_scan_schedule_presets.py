"""pin executable presets on recurring scan schedules

Revision ID: sch1preset2pin
Revises: rel1cert2life
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "sch1preset2pin"
down_revision: str | None = "rel1cert2life"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_schedules") as batch_op:
        batch_op.add_column(
            sa.Column(
                "preset_key", sa.String(length=128), server_default="standard", nullable=False
            )
        )
        batch_op.add_column(
            sa.Column("preset_version", sa.Integer(), server_default="2", nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_schedules") as batch_op:
        batch_op.drop_column("preset_version")
        batch_op.drop_column("preset_key")
