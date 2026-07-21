"""Add PostgreSQL tenant row-level security.

Revision ID: sec1tenant2rls
Revises: gov1audit2roe
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "sec1tenant2rls"
down_revision: str | None = "gov1audit2roe"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DIRECT_TENANT_TABLES = (
    "analytics_cache_entries",
    "asset_groups",
    "asset_inventory_states",
    "asset_observations",
    "asset_ownership_history",
    "asset_source_links",
    "asset_tags",
    "assets",
    "credential_assignments",
    "credential_records",
    "credential_secret_versions",
    "credential_tests",
    "credential_usage_audit",
    "finding_decisions",
    "finding_score_snapshots",
    "finding_sla_calculations",
    "findings",
    "inventory_connectors",
    "network_scopes",
    "networks",
    "pentest_sessions",
    "remediation_guidance",
    "remediation_suggestions",
    "remediation_unit_findings",
    "remediation_units",
    "report_template_runs",
    "report_template_schedules",
    "report_templates",
    "reports",
    "risk_acceptances",
    "rules_of_engagement",
    "scan_jobs",
    "scan_schedules",
    "sites",
    "software_inventory_history",
    "software_inventory_items",
    "ticket_connectors",
    "ticket_sync_events",
    "ticket_syncs",
    "workflow_runs",
)

_CHILD_TENANT_TABLES = {
    "probe_result_uploads": (
        "scan_jobs",
        "scan_job_id",
    ),
    "scan_artifacts": (
        "scan_jobs",
        "scan_job_id",
    ),
    "scan_job_attempts": (
        "scan_jobs",
        "scan_job_id",
    ),
    "services": (
        "assets",
        "asset_id",
    ),
}

_TENANT_SETTING = "NULLIF(current_setting('vulna.organization_id', true), '')::uuid"


def _create_roles() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulna_runtime') THEN
                CREATE ROLE vulna_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulna_maintenance') THEN
                CREATE ROLE vulna_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT BYPASSRLS;
            END IF;
            ALTER ROLE vulna_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOINHERIT NOBYPASSRLS;
            ALTER ROLE vulna_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOINHERIT BYPASSRLS;
            EXECUTE format('GRANT vulna_runtime TO %I', current_user);
            EXECUTE format('GRANT vulna_maintenance TO %I', current_user);
        END
        $$
        """
    )
    for role in ("vulna_runtime", "vulna_maintenance"):
        op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}")
        op.execute(f"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {role}")
        op.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            f"GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {role}"
        )


def _enable_direct_policy(table: str) -> None:
    predicate = f"organization_id = {_TENANT_SETTING}"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY vulna_tenant_isolation ON "{table}" '
        f"FOR ALL TO vulna_runtime USING ({predicate}) WITH CHECK ({predicate})"
    )


def _enable_child_policy(table: str, parent: str, foreign_key: str) -> None:
    predicate = (
        f'EXISTS (SELECT 1 FROM "{parent}" tenant_parent '  # noqa: S608
        f'WHERE tenant_parent.id = "{table}"."{foreign_key}" '
        f"AND tenant_parent.organization_id = {_TENANT_SETTING})"
    )
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY vulna_tenant_isolation ON "{table}" '
        f"FOR ALL TO vulna_runtime USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    _create_roles()
    for table in _DIRECT_TENANT_TABLES:
        _enable_direct_policy(table)
    for table, (parent, foreign_key) in _CHILD_TENANT_TABLES.items():
        _enable_child_policy(table, parent, foreign_key)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in (*_DIRECT_TENANT_TABLES, *_CHILD_TENANT_TABLES):
        op.execute(f'DROP POLICY IF EXISTS vulna_tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
