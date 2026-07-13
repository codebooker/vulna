"""phase 37: OIDC/SAML SSO, identity links, and break-glass policy

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "c1d2e3f4a5b6"
down_revision: str | None = "b0c1d2e3f4a5"
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
    op.add_column(
        "users",
        sa.Column("is_break_glass", sa.Boolean(), server_default=sa.false(), nullable=False),
    )

    op.create_table(
        "identity_providers",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False),
        sa.Column("default_role", sa.String(32), nullable=False),
        sa.Column("preset", sa.String(32), nullable=False),
        sa.Column("allow_private_network", sa.Boolean(), nullable=False),
        sa.Column("issuer", sa.String(2048)),
        sa.Column("discovery_url", sa.String(2048)),
        sa.Column("client_id", sa.String(512)),
        sa.Column("encrypted_client_secret", sa.String(4096)),
        sa.Column("scopes_json", sa.JSON(), nullable=False),
        sa.Column("oidc_metadata_json", sa.JSON(), nullable=False),
        sa.Column("idp_entity_id", sa.String(2048)),
        sa.Column("idp_sso_url", sa.String(2048)),
        sa.Column("idp_slo_url", sa.String(2048)),
        sa.Column("encrypted_idp_certificate", sa.String(16384)),
        sa.Column("encrypted_next_idp_certificate", sa.String(16384)),
        sa.Column("encrypted_sp_certificate", sa.String(16384)),
        sa.Column("encrypted_sp_private_key", sa.String(16384)),
        sa.Column("want_assertions_encrypted", sa.Boolean(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_succeeded_at", sa.DateTime(timezone=True)),
        sa.Column("last_tested_by_user_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_tested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_identity_provider_org_slug"),
    )
    op.create_index(
        "ix_identity_providers_organization_id", "identity_providers", ["organization_id"]
    )

    op.create_table(
        "sso_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid()),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sso_policies_organization_id",
        "sso_policies",
        ["organization_id"],
        unique=True,
    )

    op.create_table(
        "external_identity_links",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(1024), nullable=False),
        sa.Column("email_at_link", sa.String(320)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "identity_provider_id", "subject", name="uq_external_identity_subject"
        ),
        sa.UniqueConstraint("identity_provider_id", "user_id", name="uq_external_identity_user"),
    )
    for column in ("organization_id", "identity_provider_id", "user_id"):
        op.create_index(f"ix_external_identity_links_{column}", "external_identity_links", [column])

    op.create_table(
        "identity_group_mappings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("external_group", sa.String(512), nullable=False),
        sa.Column("role", sa.String(32)),
        sa.Column("site_ids_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "identity_provider_id", "external_group", name="uq_identity_group_mapping"
        ),
    )
    op.create_index(
        "ix_identity_group_mappings_organization_id",
        "identity_group_mappings",
        ["organization_id"],
    )
    op.create_index(
        "ix_identity_group_mappings_identity_provider_id",
        "identity_group_mappings",
        ["identity_provider_id"],
    )

    op.create_table(
        "identity_provider_tests",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("tested_by_user_id", sa.Uuid()),
        sa.Column("test_type", sa.String(32), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.String(1024)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["tested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_identity_provider_tests_organization_id",
        "identity_provider_tests",
        ["organization_id"],
    )
    op.create_index(
        "ix_identity_provider_tests_identity_provider_id",
        "identity_provider_tests",
        ["identity_provider_id"],
    )

    op.create_table(
        "sso_protocol_states",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("encrypted_nonce", sa.String(4096)),
        sa.Column("encrypted_pkce_verifier", sa.String(4096)),
        sa.Column("request_id", sa.String(512)),
        sa.Column("return_path", sa.String(1024), nullable=False),
        sa.Column("initiated_by_user_id", sa.Uuid()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["initiated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sso_protocol_states_organization_id", "sso_protocol_states", ["organization_id"]
    )
    op.create_index(
        "ix_sso_protocol_states_identity_provider_id",
        "sso_protocol_states",
        ["identity_provider_id"],
    )
    op.create_index(
        "ix_sso_protocol_states_state_hash",
        "sso_protocol_states",
        ["state_hash"],
        unique=True,
    )
    op.create_index(
        "ix_sso_protocol_states_expires_at", "sso_protocol_states", ["expires_at"]
    )

    op.create_table(
        "saml_replay_records",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("identity_provider_id", sa.Uuid(), nullable=False),
        sa.Column("identifier_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["identity_provider_id"], ["identity_providers.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identifier_hash"),
    )
    op.create_index(
        "ix_saml_replay_records_organization_id", "saml_replay_records", ["organization_id"]
    )
    op.create_index(
        "ix_saml_replay_records_identity_provider_id",
        "saml_replay_records",
        ["identity_provider_id"],
    )
    op.create_index(
        "ix_saml_replay_records_expires_at", "saml_replay_records", ["expires_at"]
    )

    organizations = sa.table("organizations", sa.column("id", sa.Uuid()))
    policies = sa.table(
        "sso_policies",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("mode", sa.String()),
    )
    for organization_id in op.get_bind().execute(sa.select(organizations.c.id)).scalars():
        op.get_bind().execute(
            policies.insert().values(
                id=uuid.uuid4(), organization_id=organization_id, mode="disabled"
            )
        )


def downgrade() -> None:
    # Downgrade removes SSO configuration and external links. It cannot preserve
    # those features in the Phase 36 schema; local users/history remain intact.
    op.drop_table("saml_replay_records")
    op.drop_table("sso_protocol_states")
    op.drop_table("identity_provider_tests")
    op.drop_table("identity_group_mappings")
    op.drop_table("external_identity_links")
    op.drop_table("sso_policies")
    op.drop_table("identity_providers")
    op.drop_column("users", "is_break_glass")
