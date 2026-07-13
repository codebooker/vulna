"""phase 43 SLA, structured guidance, and ticket synchronization core

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "d8e9f0a1b2c3"
down_revision: str | None = "c7d8e9f0a1b2"
branch_labels: str | None = None
depends_on: str | None = None

_DUE_DAYS = {"critical": 7, "high": 30, "medium": 60, "low": 90, "info": 180}


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


def _backfill_deadlines() -> None:
    connection = op.get_bind()
    findings = sa.table(
        "findings",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("severity", sa.String()),
        sa.column("first_seen_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("due_at", sa.DateTime(timezone=True)),
        sa.column("current_sla_calculation_id", sa.Uuid()),
        sa.column("sla_started_at", sa.DateTime(timezone=True)),
    )
    calculations = sa.table(
        "finding_sla_calculations",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("site_id", sa.Uuid()),
        sa.column("finding_id", sa.Uuid()),
        sa.column("policy_id", sa.Uuid()),
        sa.column("previous_calculation_id", sa.Uuid()),
        sa.column("source", sa.String()),
        sa.column("started_at", sa.DateTime(timezone=True)),
        sa.column("due_at", sa.DateTime(timezone=True)),
        sa.column("calculation_json", sa.JSON()),
        sa.column("created_by_user_id", sa.Uuid()),
    )
    rows = connection.execute(
        sa.select(
            findings.c.id,
            findings.c.organization_id,
            findings.c.site_id,
            findings.c.severity,
            findings.c.first_seen_at,
            findings.c.created_at,
            findings.c.due_at,
        )
    ).mappings()
    for row in rows:
        started_at = row["first_seen_at"] or row["created_at"] or datetime.now(UTC)
        severity = str(row["severity"] or "info").lower()
        days = _DUE_DAYS.get(severity, _DUE_DAYS["info"])
        due_at = row["due_at"] or started_at + timedelta(days=days)
        calculation_id = uuid.uuid4()
        connection.execute(
            calculations.insert().values(
                id=calculation_id,
                organization_id=row["organization_id"],
                site_id=row["site_id"],
                finding_id=row["id"],
                policy_id=None,
                previous_calculation_id=None,
                source="severity_fallback",
                started_at=started_at,
                due_at=due_at,
                calculation_json={
                    "severity": severity,
                    "days": days,
                    "migration_backfill": True,
                    "preserved_existing_due_at": row["due_at"] is not None,
                    "pause_on_risk_acceptance": False,
                },
                created_by_user_id=None,
            )
        )
        connection.execute(
            findings.update()
            .where(findings.c.id == row["id"])
            .values(
                current_sla_calculation_id=calculation_id,
                sla_started_at=started_at,
                due_at=due_at,
            )
        )


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("current_sla_calculation_id", sa.Uuid()))
        batch.add_column(sa.Column("sla_started_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("sla_paused_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("sla_completed_at", sa.DateTime(timezone=True)))

    op.create_table(
        "sla_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("match_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("due_days_json", sa.JSON(), nullable=False),
        sa.Column("pause_on_risk_acceptance", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_sla_policy_org_name"),
        sa.UniqueConstraint("organization_id", "priority", name="uq_sla_policy_org_priority"),
    )
    _indexes("sla_policies", ("organization_id", "enabled"))

    op.create_table(
        "finding_sla_calculations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid()),
        sa.Column("previous_calculation_id", sa.Uuid()),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("calculation_json", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["sla_policies.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["previous_calculation_id"], ["finding_sla_calculations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "finding_sla_calculations",
        ("organization_id", "site_id", "finding_id", "policy_id", "source", "due_at"),
    )

    op.create_table(
        "sla_exceptions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("requested_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid()),
        sa.Column("reviewed_by_user_id", sa.Uuid()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("review_notes", sa.Text()),
        sa.Column("resulting_calculation_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["resulting_calculation_id"], ["finding_sla_calculations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("sla_exceptions", ("organization_id", "site_id", "finding_id", "status"))

    op.create_table(
        "sla_history",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.Uuid()),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("sla_history", ("organization_id", "site_id", "finding_id", "event"))

    op.create_table(
        "remediation_guidance",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("summary", sa.String(1024), nullable=False),
        sa.Column("steps_json", sa.JSON(), nullable=False),
        sa.Column("validation_steps_json", sa.JSON(), nullable=False),
        sa.Column("references_json", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "remediation_guidance", ("organization_id", "site_id", "finding_id", "classification")
    )

    op.create_table(
        "ticket_connectors",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("connector_type", sa.String(16), nullable=False),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("project_key", sa.String(512), nullable=False),
        sa.Column("config_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("close_after_verification", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), server_default="15", nullable=False),
        sa.Column("successful_test_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_error", sa.String(1024)),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_ticket_connector_org_name"),
    )
    _indexes("ticket_connectors", ("organization_id", "connector_type", "enabled"))

    op.create_table(
        "ticket_syncs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_action", sa.String(16), nullable=False),
        sa.Column("external_ticket_id", sa.String(512)),
        sa.Column("external_ticket_url", sa.String(2048)),
        sa.Column("last_payload_hash", sa.String(64)),
        sa.Column("last_error", sa.String(2048)),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["ticket_connectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector_id", "finding_id", name="uq_ticket_sync_connector_finding"),
    )
    _indexes("ticket_syncs", ("organization_id", "site_id", "connector_id", "finding_id", "status"))

    op.create_table(
        "ticket_sync_events",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("sync_id", sa.Uuid(), nullable=False),
        sa.Column("background_task_id", sa.Uuid()),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("response_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("error", sa.String(2048)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["sync_id"], ["ticket_syncs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["background_task_id"], ["background_tasks.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_ticket_sync_event_idempotency"),
    )
    _indexes(
        "ticket_sync_events", ("organization_id", "site_id", "sync_id", "background_task_id")
    )

    _backfill_deadlines()


def downgrade() -> None:
    # Downgrade intentionally drops Phase 43 policy/synchronization history and
    # keeps only the compatibility ``findings.due_at`` value.
    for table in (
        "ticket_sync_events",
        "ticket_syncs",
        "ticket_connectors",
        "remediation_guidance",
        "sla_history",
        "sla_exceptions",
        "finding_sla_calculations",
        "sla_policies",
    ):
        op.drop_table(table)
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("sla_completed_at")
        batch.drop_column("sla_paused_at")
        batch.drop_column("sla_started_at")
        batch.drop_column("current_sla_calculation_id")
