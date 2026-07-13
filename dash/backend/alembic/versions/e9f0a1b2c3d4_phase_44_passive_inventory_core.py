"""phase 44 passive inventory, reconciliation, analytics, and report builder

Revision ID: e9f0a1b2c3d4
Revises: d8e9f0a1b2c3
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "e9f0a1b2c3d4"
down_revision: str | None = "d8e9f0a1b2c3"
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


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    op.create_table(
        "inventory_connectors",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("connector_type", sa.String(32), nullable=False),
        sa.Column("base_url", sa.String(2048)),
        sa.Column("config_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("encrypted_secret", sa.Text()),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("interval_minutes", sa.Integer()),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("successful_test_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_error", sa.String(1024)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_inventory_connector_org_name"),
    )
    _indexes("inventory_connectors", ("organization_id", "site_id", "connector_type", "enabled"))

    op.create_table(
        "connector_runs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("background_task_id", sa.Uuid()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("records_read", sa.Integer(), server_default="0", nullable=False),
        sa.Column("observations_created", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.String(2048)),
        sa.Column("cursor_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["inventory_connectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["background_task_id"], ["background_tasks.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "connector_runs",
        ("organization_id", "site_id", "connector_id", "background_task_id", "status"),
    )

    op.create_table(
        "asset_observations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("source_record_id", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("identifiers_json", sa.JSON(), nullable=False),
        sa.Column("attributes_json", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("matched_asset_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["inventory_connectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["connector_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["matched_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id", "source_record_id", name="uq_asset_observation_run_source_record"
        ),
    )
    _indexes(
        "asset_observations",
        (
            "organization_id",
            "site_id",
            "connector_id",
            "run_id",
            "observed_at",
            "payload_hash",
            "matched_asset_id",
        ),
    )

    op.create_table(
        "asset_source_links",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("source_record_id", sa.String(512), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("identifiers_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["inventory_connectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connector_id", "source_record_id", name="uq_asset_source_link_connector_record"
        ),
    )
    _indexes("asset_source_links", ("organization_id", "site_id", "connector_id", "asset_id"))

    op.create_table(
        "asset_inventory_states",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("expected", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True)),
        sa.Column("assessed_at", sa.DateTime(timezone=True)),
        sa.Column("last_observed_at", sa.DateTime(timezone=True)),
        sa.Column("missing_since", sa.DateTime(timezone=True)),
        sa.Column("stale_after_days", sa.Integer(), server_default="30", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", name="uq_asset_inventory_state_asset"),
    )
    _indexes("asset_inventory_states", ("organization_id", "site_id", "asset_id", "state"))

    op.create_table(
        "inventory_lifecycle_events",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("previous_state", sa.String(16)),
        sa.Column("new_state", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("source_observation_id", sa.Uuid()),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_observation_id"], ["asset_observations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("inventory_lifecycle_events", ("organization_id", "site_id", "asset_id", "new_state"))

    op.create_table(
        "reconciliation_candidates",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("observation_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_asset_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("reasons_json", sa.JSON(), nullable=False),
        sa.Column("conflicts_json", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("merge_snapshot_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("decided_by_user_id", sa.Uuid()),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("split_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["asset_observations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["candidate_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["decided_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "observation_id", "candidate_asset_id", name="uq_reconciliation_observation_asset"
        ),
    )
    _indexes(
        "reconciliation_candidates",
        ("organization_id", "site_id", "observation_id", "candidate_asset_id", "score", "status"),
    )

    op.create_table(
        "daily_finding_aggregates",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("scope_key", sa.String(36), nullable=False),
        sa.Column("aggregate_date", sa.Date(), nullable=False),
        sa.Column("finding_total", sa.Integer(), server_default="0", nullable=False),
        sa.Column("finding_open", sa.Integer(), server_default="0", nullable=False),
        sa.Column("finding_resolved", sa.Integer(), server_default="0", nullable=False),
        sa.Column("finding_breached", sa.Integer(), server_default="0", nullable=False),
        sa.Column("severity_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("inventory_state_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "scope_key",
            "aggregate_date",
            name="uq_daily_aggregate_org_scope_date",
        ),
    )
    _indexes("daily_finding_aggregates", ("organization_id", "site_id", "aggregate_date"))

    op.create_table(
        "analytics_cache_entries",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("cache_key", sa.String(255), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "cache_key", name="uq_analytics_cache_scope_key"),
    )
    _indexes("analytics_cache_entries", ("organization_id", "site_id", "expires_at"))

    op.create_table(
        "report_templates",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("report_types_json", sa.JSON(), nullable=False),
        sa.Column("sections_json", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("filters_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("redaction_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("branding_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("encrypted_export_password", sa.Text()),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_report_template_org_name"),
    )
    _indexes("report_templates", ("organization_id", "site_id", "enabled"))

    op.create_table(
        "report_template_schedules",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("template_id", sa.Uuid(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivery_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["template_id"], ["report_templates.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "report_template_schedules",
        ("organization_id", "site_id", "template_id", "next_run_at", "enabled"),
    )

    op.create_table(
        "report_template_runs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid()),
        sa.Column("template_id", sa.Uuid(), nullable=False),
        sa.Column("schedule_id", sa.Uuid()),
        sa.Column("background_task_id", sa.Uuid()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("parameters_json", sa.JSON(), nullable=False),
        sa.Column("report_ids_json", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("comparison_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("encrypted_export_password", sa.Text()),
        sa.Column("error", sa.String(2048)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["template_id"], ["report_templates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["schedule_id"], ["report_template_schedules.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["background_task_id"], ["background_tasks.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "report_template_runs",
        ("organization_id", "site_id", "template_id", "status"),
    )

    connection = op.get_bind()
    assets = sa.table(
        "assets",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("first_seen_at", sa.DateTime(timezone=True)),
        sa.column("last_seen_at", sa.DateTime(timezone=True)),
        sa.column("last_assessed_at", sa.DateTime(timezone=True)),
    )
    states = sa.table(
        "asset_inventory_states",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("state", sa.String()),
        sa.column("expected", sa.Boolean()),
        sa.column("discovered_at", sa.DateTime(timezone=True)),
        sa.column("assessed_at", sa.DateTime(timezone=True)),
        sa.column("last_observed_at", sa.DateTime(timezone=True)),
        sa.column("stale_after_days", sa.Integer()),
    )
    for row in connection.execute(sa.select(assets)).mappings():
        connection.execute(
            states.insert().values(
                id=uuid.uuid4(),
                organization_id=row["organization_id"],
                site_id=row["site_id"],
                asset_id=row["id"],
                state="assessed" if row["last_assessed_at"] else "discovered",
                expected=False,
                discovered_at=row["first_seen_at"],
                assessed_at=row["last_assessed_at"],
                last_observed_at=row["last_seen_at"],
                stale_after_days=30,
            )
        )


def downgrade() -> None:
    # Downgrade drops Phase 44 operational history and cannot reconstruct split
    # source records. Take a verified backup before downgrading.
    for table in (
        "report_template_runs",
        "report_template_schedules",
        "report_templates",
        "analytics_cache_entries",
        "daily_finding_aggregates",
        "reconciliation_candidates",
        "inventory_lifecycle_events",
        "asset_inventory_states",
        "asset_source_links",
        "asset_observations",
        "connector_runs",
        "inventory_connectors",
    ):
        op.drop_table(table)
