"""phase 39: granular authorization, service accounts, and API tokens

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "e3f4a5b6c7d8"
down_revision: str | None = "d2e3f4a5b6c7"
branch_labels: str | None = None
depends_on: str | None = None

_ROLE_ORDER = (
    "administrator",
    "security_operator",
    "pentest_approver",
    "remediation_owner",
    "auditor",
    "viewer",
)

# Frozen Phase 39 catalogue. Later migrations may add keys without changing the
# deterministic result of upgrading through this revision.
_PERMISSIONS = (
    "system.admin",
    "system.read",
    "organization.manage",
    "users.read",
    "users.manage",
    "roles.read",
    "roles.manage",
    "tokens.self",
    "service_accounts.manage",
    "sessions.self",
    "sessions.manage",
    "identity.self",
    "identity.manage",
    "scim.manage",
    "sites.read",
    "sites.manage",
    "scopes.read",
    "scopes.manage",
    "networks.read",
    "networks.manage",
    "scouts.read",
    "scouts.manage",
    "relays.read",
    "relays.manage",
    "schedules.read",
    "schedules.manage",
    "jobs.read",
    "jobs.create",
    "jobs.manage",
    "assets.read",
    "assets.manage",
    "findings.read",
    "findings.manage",
    "remediation.read",
    "remediation.manage",
    "pentest.read",
    "pentest.request",
    "pentest.approve",
    "workflows.read",
    "workflows.run",
    "workflows.approve",
    "risk_acceptance.read",
    "risk_acceptance.approve",
    "risk_acceptance.manage",
    "reports.read",
    "reports.create",
    "audit.read",
    "feeds.read",
    "feeds.manage",
    "notifications.read",
    "notifications.manage",
    "privacy.read",
    "privacy.manage",
    "maintenance.read",
    "maintenance.manage",
    "portability.read",
    "portability.manage",
    "diagnostics.read",
    "diagnostics.manage",
    "presets.read",
    "presets.manage",
    "resources.read",
    "resources.manage",
    "onboarding.read",
    "onboarding.manage",
    "demo.read",
    "demo.manage",
    "tasks.read",
    "tasks.manage",
)
_READ = frozenset(key for key in _PERMISSIONS if key.endswith(".read"))
_PRIVILEGED_READ = frozenset({"audit.read", "roles.read", "tasks.read", "users.read"})
_GENERAL_READ = _READ - _PRIVILEGED_READ
_SELF = frozenset({"tokens.self", "sessions.self", "identity.self"})
_ROLE_PERMISSIONS = {
    "administrator": frozenset(_PERMISSIONS),
    "security_operator": _GENERAL_READ
    | _SELF
    | frozenset(
        {
            "networks.manage",
            "schedules.manage",
            "jobs.create",
            "jobs.manage",
            "assets.manage",
            "findings.manage",
            "remediation.manage",
            "pentest.request",
            "workflows.run",
            "reports.create",
            "presets.manage",
        }
    ),
    "pentest_approver": _GENERAL_READ
    | _SELF
    | frozenset(
        {
            "jobs.create",
            "pentest.request",
            "pentest.approve",
            "workflows.approve",
            "risk_acceptance.approve",
            "reports.create",
        }
    ),
    "remediation_owner": _GENERAL_READ
    | _SELF
    | frozenset({"remediation.manage", "reports.create"}),
    "auditor": _GENERAL_READ | _SELF | frozenset({"audit.read"}),
    "viewer": _GENERAL_READ | _SELF,
}


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


def _role_id(organization_id: object, role: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"vulna:phase39:{organization_id}:{role}").hex


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("authorization_migrated_at", sa.DateTime(timezone=True)))

    op.create_table(
        "authorization_roles",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("compatibility_role", sa.String(32)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key", name="uq_authorization_role_org_key"),
        sa.UniqueConstraint("organization_id", "name", name="uq_authorization_role_org_name"),
    )
    op.create_index(
        "ix_authorization_roles_organization_id", "authorization_roles", ["organization_id"]
    )

    op.create_table(
        "role_permissions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_key", sa.String(128), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["authorization_roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("role_id", "permission_key", name="uq_role_permission"),
    )
    for column in ("organization_id", "role_id", "permission_key"):
        op.create_index(f"ix_role_permissions_{column}", "role_permissions", [column])

    op.create_table(
        "service_accounts",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("primary_role", sa.String(32), nullable=False),
        sa.Column("auth_version", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_service_account_org_name"),
    )
    op.create_index("ix_service_accounts_organization_id", "service_accounts", ["organization_id"])

    op.create_table(
        "scoped_grants",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("user_id", sa.Uuid()),
        sa.Column("service_account_id", sa.Uuid()),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("scope_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.CheckConstraint(
            "(principal_type = 'user' AND user_id IS NOT NULL AND service_account_id IS NULL) "
            "OR (principal_type = 'service_account' AND user_id IS NULL "
            "AND service_account_id IS NOT NULL)",
            name="ck_scoped_grant_principal",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["service_account_id"], ["service_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["role_id"], ["authorization_roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id", name="uq_user_role_scope_grant"
        ),
        sa.UniqueConstraint(
            "service_account_id",
            "role_id",
            "scope_type",
            "scope_id",
            name="uq_service_role_scope_grant",
        ),
    )
    for column in (
        "organization_id",
        "principal_type",
        "user_id",
        "service_account_id",
        "role_id",
        "scope_type",
        "scope_id",
    ):
        op.create_index(f"ix_scoped_grants_{column}", "scoped_grants", [column])

    op.create_table(
        "api_tokens",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("user_id", sa.Uuid()),
        sa.Column("service_account_id", sa.Uuid()),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_prefix", sa.String(24), nullable=False),
        sa.Column("issued_auth_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("rotated_from_id", sa.Uuid()),
        sa.Column("ip_restrictions_json", sa.JSON(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_ip", sa.String(64)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.CheckConstraint(
            "(principal_type = 'user' AND user_id IS NOT NULL AND service_account_id IS NULL) "
            "OR (principal_type = 'service_account' AND user_id IS NULL "
            "AND service_account_id IS NOT NULL)",
            name="ck_api_token_principal",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["service_account_id"], ["service_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["rotated_from_id"], ["api_tokens.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "organization_id",
        "principal_type",
        "user_id",
        "service_account_id",
        "expires_at",
    ):
        op.create_index(f"ix_api_tokens_{column}", "api_tokens", [column])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"], unique=True)

    _backfill()


def _backfill() -> None:
    bind = op.get_bind()
    metadata = sa.MetaData()
    organizations = sa.Table("organizations", metadata, autoload_with=bind)
    users = sa.Table("users", metadata, autoload_with=bind)
    assignments = sa.Table("user_site_assignments", metadata, autoload_with=bind)
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    role_permissions = sa.Table("role_permissions", metadata, autoload_with=bind)
    grants = sa.Table("scoped_grants", metadata, autoload_with=bind)
    now = datetime.now(UTC)

    organization_ids = [row.id for row in bind.execute(sa.select(organizations.c.id))]
    role_rows: list[dict[str, Any]] = []
    permission_rows: list[dict[str, Any]] = []
    for organization_id in organization_ids:
        for role in _ROLE_ORDER:
            role_id = _role_id(organization_id, role)
            role_rows.append(
                {
                    "id": role_id,
                    "organization_id": organization_id,
                    "key": role,
                    "name": role.replace("_", " ").title(),
                    "description": f"Built-in compatibility role: {role}",
                    "is_system": True,
                    "compatibility_role": role,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            permission_rows.extend(
                {
                    "id": uuid.uuid4().hex,
                    "organization_id": organization_id,
                    "role_id": role_id,
                    "permission_key": permission,
                    "created_at": now,
                }
                for permission in sorted(_ROLE_PERMISSIONS[role])
            )
    if role_rows:
        bind.execute(roles.insert(), role_rows)
        bind.execute(role_permissions.insert(), permission_rows)

    assignment_rows: dict[uuid.UUID, list[uuid.UUID]] = {}
    for row in bind.execute(sa.select(assignments.c.user_id, assignments.c.site_id)):
        assignment_rows.setdefault(row.user_id, []).append(row.site_id)
    grant_rows: list[dict[str, Any]] = []
    user_rows = bind.execute(
        sa.select(
            users.c.id,
            users.c.organization_id,
            users.c.role,
            users.c.site_access_mode,
        )
    )
    for user in user_rows:
        role_value = str(user.role).lower()
        scope_ids = (
            [user.organization_id]
            if role_value == "administrator" or user.site_access_mode == "all"
            else assignment_rows.get(user.id, [])
        )
        scope_type = (
            "organization"
            if role_value == "administrator" or user.site_access_mode == "all"
            else "site"
        )
        for scope_id in scope_ids:
            grant_rows.append(
                {
                    "id": uuid.uuid4().hex,
                    "organization_id": user.organization_id,
                    "principal_type": "user",
                    "user_id": user.id,
                    "service_account_id": None,
                    "role_id": _role_id(user.organization_id, role_value),
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "created_by_user_id": None,
                    "created_at": now,
                }
            )
    if grant_rows:
        bind.execute(grants.insert(), grant_rows)
    bind.execute(users.update().values(authorization_migrated_at=now))


def downgrade() -> None:
    # Custom roles, grants, service accounts, and token metadata have no Phase 38
    # representation and are removed. Derived User.role/site fields remain.
    op.drop_table("api_tokens")
    op.drop_table("scoped_grants")
    op.drop_table("service_accounts")
    op.drop_table("role_permissions")
    op.drop_table("authorization_roles")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("authorization_migrated_at")
