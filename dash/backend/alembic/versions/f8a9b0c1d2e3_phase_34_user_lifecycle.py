"""phase 34: user administration and lifecycle

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f8a9b0c1d2e3"
down_revision: str | None = "e7f8a9b0c1d2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "hashed_password",
            existing_type=sa.String(length=255),
            nullable=True,
        )
        batch_op.add_column(
            sa.Column(
                "account_status",
                sa.String(length=32),
                nullable=False,
                server_default="active",
            )
        )
        batch_op.add_column(
            sa.Column(
                "authentication_source",
                sa.String(length=32),
                nullable=False,
                server_default="local",
            )
        )
        batch_op.add_column(
            sa.Column(
                "site_access_mode",
                sa.String(length=32),
                nullable=False,
                server_default="all",
            )
        )
        batch_op.add_column(
            sa.Column("auth_version", sa.Integer(), nullable=False, server_default="1")
        )
        batch_op.add_column(sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("created_by_user_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_users_created_by_user_id_users",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.execute(
        sa.text(
            "UPDATE users SET account_status = CASE WHEN is_active THEN 'active' "
            "ELSE 'deactivated' END"
        )
    )
    op.execute(
        sa.text(
            "UPDATE users SET activated_at = created_at "
            "WHERE account_status = 'active' AND activated_at IS NULL"
        )
    )
    op.execute(
        sa.text(
            "UPDATE users SET deactivated_at = updated_at "
            "WHERE account_status = 'deactivated' AND deactivated_at IS NULL"
        )
    )

    op.create_table(
        "user_invitations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_method", sa.String(length=32), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_invitations_organization_id", "user_invitations", ["organization_id"])
    op.create_index("ix_user_invitations_user_id", "user_invitations", ["user_id"])
    op.create_index("ix_user_invitations_token_hash", "user_invitations", ["token_hash"], unique=True)

    op.create_table(
        "password_reset_tokens",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_password_reset_tokens_organization_id",
        "password_reset_tokens",
        ["organization_id"],
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index(
        "ix_password_reset_tokens_token_hash",
        "password_reset_tokens",
        ["token_hash"],
        unique=True,
    )

    op.create_table(
        "user_site_assignments",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "site_id", name="uq_user_site_assignments_user_site"
        ),
    )
    op.create_index(
        "ix_user_site_assignments_organization_id",
        "user_site_assignments",
        ["organization_id"],
    )
    op.create_index("ix_user_site_assignments_user_id", "user_site_assignments", ["user_id"])
    op.create_index("ix_user_site_assignments_site_id", "user_site_assignments", ["site_id"])

    op.create_table(
        "user_lifecycle_events",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.String(length=1024), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_user_lifecycle_events_organization_id",
        "user_lifecycle_events",
        ["organization_id"],
    )
    op.create_index("ix_user_lifecycle_events_user_id", "user_lifecycle_events", ["user_id"])
    op.create_index(
        "ix_user_lifecycle_events_event_type", "user_lifecycle_events", ["event_type"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    passwordless = bind.execute(
        sa.text("SELECT COUNT(*) FROM users WHERE hashed_password IS NULL")
    ).scalar_one()
    if passwordless:
        raise RuntimeError(
            "Phase 34 downgrade refused: invited/passwordless users exist. "
            "Deactivate and remove those accounts from a disposable copy before downgrading."
        )

    op.drop_table("user_lifecycle_events")
    op.drop_table("user_site_assignments")
    op.drop_table("password_reset_tokens")
    op.drop_table("user_invitations")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("fk_users_created_by_user_id_users", type_="foreignkey")
        batch_op.drop_column("created_by_user_id")
        batch_op.drop_column("password_changed_at")
        batch_op.drop_column("deactivated_at")
        batch_op.drop_column("suspended_at")
        batch_op.drop_column("activated_at")
        batch_op.drop_column("invited_at")
        batch_op.drop_column("auth_version")
        batch_op.drop_column("site_access_mode")
        batch_op.drop_column("authentication_source")
        batch_op.drop_column("account_status")
        batch_op.alter_column(
            "hashed_password", existing_type=sa.String(length=255), nullable=False
        )
