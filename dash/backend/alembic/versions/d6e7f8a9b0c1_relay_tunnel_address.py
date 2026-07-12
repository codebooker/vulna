"""relay: allocate a unique WireGuard tunnel address

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d6e7f8a9b0c1"
down_revision: str | None = "c5d6e7f8a9b0"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("relays", sa.Column("tunnel_address", sa.String(length=64), nullable=True))
    op.create_index("ix_relays_tunnel_address", "relays", ["tunnel_address"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_relays_tunnel_address", table_name="relays")
    op.drop_column("relays", "tunnel_address")
