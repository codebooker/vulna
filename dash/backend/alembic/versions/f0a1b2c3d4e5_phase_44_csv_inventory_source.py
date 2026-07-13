"""phase 44 encrypted CSV inventory source

Revision ID: f0a1b2c3d4e5
Revises: e9f0a1b2c3d4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f0a1b2c3d4e5"
down_revision: str | None = "e9f0a1b2c3d4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("inventory_connectors") as batch:
        batch.add_column(sa.Column("encrypted_source_data", sa.Text(), nullable=True))
        batch.add_column(sa.Column("source_filename", sa.String(255), nullable=True))
        batch.add_column(sa.Column("source_sha256", sa.String(64), nullable=True))
        batch.add_column(sa.Column("source_size_bytes", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("source_uploaded_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("source_uploaded_by_user_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_inventory_connectors_source_uploaded_by_user_id_users",
            "users",
            ["source_uploaded_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    # Encrypted CSV source content and its provenance metadata are irrecoverably
    # removed. Export metadata and take a verified encrypted backup first.
    with op.batch_alter_table("inventory_connectors") as batch:
        batch.drop_constraint(
            "fk_inventory_connectors_source_uploaded_by_user_id_users",
            type_="foreignkey",
        )
        for column in (
            "source_uploaded_by_user_id",
            "source_uploaded_at",
            "source_size_bytes",
            "source_sha256",
            "source_filename",
            "encrypted_source_data",
        ):
            batch.drop_column(column)
