"""relay enrollment and certificate lifecycle

Revision ID: rel1cert2life
Revises: cve1prod2idx3
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "rel1cert2life"
down_revision: str | None = "cve1prod2idx3"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("relays") as batch_op:
        batch_op.add_column(
            sa.Column("enrollment_token_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("certificate_serial", sa.String(length=128), nullable=True))
        batch_op.add_column(
            sa.Column("previous_certificate_fingerprint", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("previous_certificate_valid_until", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("certificate_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_index(
            "ix_relays_previous_certificate_fingerprint",
            ["previous_certificate_fingerprint"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("relays") as batch_op:
        batch_op.drop_index("ix_relays_previous_certificate_fingerprint")
        batch_op.drop_column("certificate_expires_at")
        batch_op.drop_column("previous_certificate_valid_until")
        batch_op.drop_column("previous_certificate_fingerprint")
        batch_op.drop_column("certificate_serial")
        batch_op.drop_column("enrollment_token_expires_at")
