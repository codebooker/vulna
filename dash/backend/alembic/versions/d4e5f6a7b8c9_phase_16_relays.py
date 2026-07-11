"""phase 16: vulnarelay (opt-in)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-11 06:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS = sa.Enum(
    "PENDING_ENROLLMENT", "ENROLLED", "KILLED", "REVOKED",
    name="relaystatus", native_enum=False, length=24,
)


def upgrade() -> None:
    op.create_table(
        "relays",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", _STATUS, nullable=False),
        sa.Column("enrollment_token_hash", sa.String(length=64), nullable=True),
        sa.Column("certificate_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("tunnel_public_key", sa.String(length=128), nullable=True),
        sa.Column("tunnel_up", sa.Boolean(), nullable=False),
        sa.Column("approved_cidrs_json", sa.JSON(), nullable=False),
        sa.Column("denied_cidrs_json", sa.JSON(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("killed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
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
            ["created_by"], ["users.id"],
            name=op.f("fk_relays_created_by_users"), ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"],
            name=op.f("fk_relays_organization_id_organizations"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"],
            name=op.f("fk_relays_site_id_sites"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_relays")),
    )
    with op.batch_alter_table("relays", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_relays_organization_id"), ["organization_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_relays_site_id"), ["site_id"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_relays_certificate_fingerprint"),
            ["certificate_fingerprint"], unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("relays", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_relays_certificate_fingerprint"))
        batch_op.drop_index(batch_op.f("ix_relays_site_id"))
        batch_op.drop_index(batch_op.f("ix_relays_organization_id"))
    op.drop_table("relays")
