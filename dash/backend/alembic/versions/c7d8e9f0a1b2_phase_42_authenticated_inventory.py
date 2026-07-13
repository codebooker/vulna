"""phase 42 authenticated scanning, credential vault, and software inventory

Revision ID: c7d8e9f0a1b2
Revises: b6c7d8e9f0a1
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "c7d8e9f0a1b2"
down_revision: str | None = "b6c7d8e9f0a1"
branch_labels: str | None = None
depends_on: str | None = None


def _timestamps() -> list[sa.Column[Any]]:
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def _created_at() -> sa.Column[Any]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    with op.batch_alter_table("probes") as batch:
        batch.add_column(
            sa.Column(
                "credentialed_scans_enabled",
                sa.Boolean(),
                server_default=sa.false(),
                nullable=False,
            )
        )
        batch.add_column(sa.Column("encryption_public_key_b64", sa.String(64)))

    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("asset_id", sa.Uuid()))
        batch.add_column(
            sa.Column("credential_protocols_json", sa.JSON(), server_default="[]", nullable=False)
        )
        batch.create_foreign_key(
            "fk_scan_jobs_asset_id", "assets", ["asset_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_scan_jobs_asset_id", ["asset_id"])

    op.create_table(
        "credential_records",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("auth_type", sa.String(32), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_credential_record_org_name"),
    )
    _indexes("credential_records", ("organization_id", "protocol", "is_active"))

    op.create_table(
        "credential_secret_versions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id", "version", name="uq_credential_secret_version"),
    )
    _indexes("credential_secret_versions", ("organization_id", "credential_id"))

    op.create_table(
        "credential_assignments",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("assigned_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "credential_id",
            "target_type",
            "target_id",
            name="uq_credential_assignment_target",
        ),
    )
    _indexes(
        "credential_assignments",
        ("organization_id", "credential_id", "target_type", "target_id", "site_id"),
    )

    op.create_table(
        "credential_tests",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("secret_version_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("message", sa.String(1024)),
        sa.Column("tested_by_user_id", sa.Uuid()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["secret_version_id"], ["credential_secret_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("credential_tests", ("organization_id", "credential_id", "asset_id", "scan_job_id"))

    op.create_table(
        "credential_usage_audit",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("secret_version_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("probe_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("detail", sa.String(1024)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["secret_version_id"], ["credential_secret_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["probe_id"], ["probes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "credential_usage_audit",
        ("organization_id", "credential_id", "asset_id", "probe_id", "scan_job_id"),
    )

    op.create_table(
        "software_inventory_items",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("package_key", sa.String(512), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("architecture", sa.String(64), server_default="unknown", nullable=False),
        sa.Column("publisher", sa.String(255)),
        sa.Column("product_key", sa.String(255)),
        sa.Column("install_date", sa.Date()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True)),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id", "source", "package_key", "architecture", name="uq_software_asset_package"
        ),
    )
    _indexes(
        "software_inventory_items",
        ("organization_id", "site_id", "asset_id", "source", "package_key", "product_key"),
    )

    op.create_table(
        "software_inventory_history",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("software_item_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid()),
        sa.Column("change_type", sa.String(24), nullable=False),
        sa.Column("previous_version", sa.String(255)),
        sa.Column("observed_version", sa.String(255)),
        sa.Column("observation_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["software_item_id"], ["software_inventory_items.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "software_inventory_history",
        ("organization_id", "site_id", "asset_id", "software_item_id", "scan_job_id"),
    )

    op.create_table(
        "eol_intelligence_records",
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product_key", sa.String(255), nullable=False),
        sa.Column("version_prefix", sa.String(128), server_default="", nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("release_date", sa.Date()),
        sa.Column("eol_date", sa.Date()),
        sa.Column("source_url", sa.String(2048)),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider", "product_key", "version_prefix", name="uq_eol_provider_product_version"
        ),
    )
    _indexes("eol_intelligence_records", ("provider", "product_key"))

    op.create_table(
        "eol_overrides",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("software_item_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("eol_date", sa.Date()),
        sa.Column("reason", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["software_item_id"], ["software_inventory_items.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("eol_overrides", ("organization_id", "software_item_id", "active"))


def downgrade() -> None:
    for table in (
        "eol_overrides",
        "eol_intelligence_records",
        "software_inventory_history",
        "software_inventory_items",
        "credential_usage_audit",
        "credential_tests",
        "credential_assignments",
        "credential_secret_versions",
        "credential_records",
    ):
        op.drop_table(table)

    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_index("ix_scan_jobs_asset_id")
        batch.drop_constraint("fk_scan_jobs_asset_id", type_="foreignkey")
        batch.drop_column("credential_protocols_json")
        batch.drop_column("asset_id")
    with op.batch_alter_table("probes") as batch:
        batch.drop_column("encryption_public_key_b64")
        batch.drop_column("credentialed_scans_enabled")
