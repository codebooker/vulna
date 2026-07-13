"""phase 38: SCIM tokens, users, groups, mappings, and provisioning logs

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "d2e3f4a5b6c7"
down_revision: str | None = "c1d2e3f4a5b6"
branch_labels: str | None = None
depends_on: str | None = None


def _created_at() -> sa.Column[Any]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _timestamps() -> list[sa.Column[Any]]:
    return [
        _created_at(),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("scim_external_id", sa.String(512), nullable=True))
        batch.create_unique_constraint(
            "uq_users_org_scim_external_id", ["organization_id", "scim_external_id"]
        )

    op.create_table(
        "scim_tokens",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_prefix", sa.String(24), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("rotated_from_id", sa.Uuid()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_ip", sa.String(64)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rotated_from_id"], ["scim_tokens.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scim_tokens_organization_id", "scim_tokens", ["organization_id"])
    op.create_index("ix_scim_tokens_token_hash", "scim_tokens", ["token_hash"], unique=True)
    op.create_index("ix_scim_tokens_expires_at", "scim_tokens", ["expires_at"])

    op.create_table(
        "scim_groups",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(512), nullable=False),
        sa.Column("external_id", sa.String(512)),
        sa.Column("mapped_role", sa.String(32)),
        sa.Column("grants_all_sites", sa.Boolean(), nullable=False),
        sa.Column("asset_group_targets_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "display_name", name="uq_scim_group_org_name"),
        sa.UniqueConstraint("organization_id", "external_id", name="uq_scim_group_org_external"),
    )
    op.create_index("ix_scim_groups_organization_id", "scim_groups", ["organization_id"])

    op.create_table(
        "scim_group_members",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["scim_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "user_id", name="uq_scim_group_member"),
    )
    for column in ("organization_id", "group_id", "user_id"):
        op.create_index(f"ix_scim_group_members_{column}", "scim_group_members", [column])

    op.create_table(
        "scim_group_site_mappings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["scim_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "site_id", name="uq_scim_group_site_mapping"),
    )
    for column in ("organization_id", "group_id", "site_id"):
        op.create_index(
            f"ix_scim_group_site_mappings_{column}", "scim_group_site_mappings", [column]
        )

    op.create_table(
        "scim_provisioning_logs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("token_id", sa.Uuid()),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("resource_type", sa.String(32)),
        sa.Column("resource_id", sa.String(64)),
        sa.Column("external_id", sa.String(512)),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.String(1024)),
        sa.Column("request_id", sa.String(64)),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("changes_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["token_id"], ["scim_tokens.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("organization_id", "token_id", "operation"):
        op.create_index(f"ix_scim_provisioning_logs_{column}", "scim_provisioning_logs", [column])

    op.create_table(
        "scim_rate_limit_windows",
        sa.Column("token_id", sa.Uuid(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["token_id"], ["scim_tokens.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_id", "window_started_at", name="uq_scim_rate_window"),
    )
    op.create_index("ix_scim_rate_limit_windows_token_id", "scim_rate_limit_windows", ["token_id"])
    op.create_index(
        "ix_scim_rate_limit_windows_window_started_at",
        "scim_rate_limit_windows",
        ["window_started_at"],
    )


def downgrade() -> None:
    # Provisioning tokens, mappings, and logs cannot be represented by Phase 37.
    # User rows and lifecycle history remain; only SCIM external ids are dropped.
    op.drop_table("scim_rate_limit_windows")
    op.drop_table("scim_provisioning_logs")
    op.drop_table("scim_group_site_mappings")
    op.drop_table("scim_group_members")
    op.drop_table("scim_groups")
    op.drop_table("scim_tokens")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_users_org_scim_external_id", type_="unique")
        batch.drop_column("scim_external_id")
