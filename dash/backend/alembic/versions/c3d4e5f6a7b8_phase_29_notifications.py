"""phase 29: notification channels and deliveries

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-11 05:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b2c3d4e5f6a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("channel_type", sa.String(length=16), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("encrypted_secret", sa.String(length=2048), nullable=True),
        sa.Column("events_json", sa.JSON(), nullable=False),
        sa.Column("policy", sa.String(length=16), nullable=False),
        sa.Column("quiet_start_hour", sa.Integer(), nullable=True),
        sa.Column("quiet_end_hour", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_digest_at", sa.DateTime(timezone=True), nullable=True),
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
            ["created_by"], ["users.id"],
            name=op.f("fk_notification_channels_created_by_users"), ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"],
            name=op.f("fk_notification_channels_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_channels")),
    )
    with op.batch_alter_table("notification_channels", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_notification_channels_organization_id"),
            ["organization_id"], unique=False,
        )

    op.create_table(
        "notification_deliveries",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=True),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["channel_id"], ["notification_channels.id"],
            name=op.f("fk_notification_deliveries_channel_id_notification_channels"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"],
            name=op.f("fk_notification_deliveries_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_deliveries")),
    )
    with op.batch_alter_table("notification_deliveries", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_notification_deliveries_organization_id"),
            ["organization_id"], unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_notification_deliveries_channel_id"),
            ["channel_id"], unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_notification_deliveries_dedup_key"),
            ["dedup_key"], unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("notification_deliveries", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_notification_deliveries_dedup_key"))
        batch_op.drop_index(batch_op.f("ix_notification_deliveries_channel_id"))
        batch_op.drop_index(batch_op.f("ix_notification_deliveries_organization_id"))
    op.drop_table("notification_deliveries")
    with op.batch_alter_table("notification_channels", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_notification_channels_organization_id"))
    op.drop_table("notification_channels")
