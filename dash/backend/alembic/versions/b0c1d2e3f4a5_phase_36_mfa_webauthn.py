"""phase 36: MFA, WebAuthn, step-up, and durable throttling

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "b0c1d2e3f4a5"
down_revision: str | None = "a9b0c1d2e3f4"
branch_labels: str | None = None
depends_on: str | None = None


def _timestamps() -> list[sa.Column[Any]]:
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        )
    ]


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_grace_expires_at", sa.DateTime(timezone=True)))
    op.add_column(
        "user_sessions",
        sa.Column("mfa_pending", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "user_sessions", sa.Column("mfa_authenticated_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "user_sessions",
        sa.Column("authentication_methods_json", sa.JSON(), server_default="[]", nullable=False),
    )

    op.create_table(
        "totp_factors",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("encrypted_secret", sa.String(2048), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_timecode", sa.Integer()),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_totp_factors_organization_id", "totp_factors", ["organization_id"])
    op.create_index("ix_totp_factors_user_id", "totp_factors", ["user_id"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mfa_recovery_codes_organization_id", "mfa_recovery_codes", ["organization_id"]
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])

    op.create_table(
        "webauthn_credentials",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.String(1024), nullable=False),
        sa.Column("credential_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("transports_json", sa.JSON(), nullable=False),
        sa.Column("device_type", sa.String(32), nullable=False),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_webauthn_credentials_organization_id", "webauthn_credentials", ["organization_id"]
    )
    op.create_index("ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"])
    op.create_index(
        "ix_webauthn_credentials_credential_id",
        "webauthn_credentials",
        ["credential_id"],
        unique=True,
    )

    op.create_table(
        "webauthn_challenges",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid()),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["user_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_webauthn_challenges_organization_id", "webauthn_challenges", ["organization_id"]
    )
    op.create_index("ix_webauthn_challenges_user_id", "webauthn_challenges", ["user_id"])
    op.create_index("ix_webauthn_challenges_session_id", "webauthn_challenges", ["session_id"])
    op.create_index("ix_webauthn_challenges_expires_at", "webauthn_challenges", ["expires_at"])

    op.create_table(
        "mfa_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("required_roles_json", sa.JSON(), nullable=False),
        sa.Column("grace_period_days", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mfa_policies_organization_id", "mfa_policies", ["organization_id"], unique=True
    )

    op.create_table(
        "authentication_throttles",
        sa.Column("key_type", sa.String(16), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failure_at", sa.DateTime(timezone=True)),
        sa.Column("blocked_until", sa.DateTime(timezone=True)),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_type", "key_hash", name="uq_auth_throttle_key"),
    )

    _migrate_recovery_codes()


def _migrate_recovery_codes() -> None:
    connection = op.get_bind()
    users = sa.table(
        "users",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("recovery_codes_json", sa.JSON()),
        sa.column("recovery_codes_generated_at", sa.DateTime(timezone=True)),
    )
    recovery = sa.table(
        "mfa_recovery_codes",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("user_id", sa.Uuid()),
        sa.column("code_hash", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    for row in connection.execute(sa.select(users)).mappings():
        raw = row["recovery_codes_json"] or []
        codes = json.loads(raw) if isinstance(raw, str) else list(raw)
        generated_at = row["recovery_codes_generated_at"] or datetime.now(UTC)
        if codes:
            connection.execute(
                recovery.insert(),
                [
                    {
                        "id": uuid.uuid4(),
                        "organization_id": row["organization_id"],
                        "user_id": row["id"],
                        "code_hash": code_hash,
                        "created_at": generated_at,
                    }
                    for code_hash in codes
                ],
            )
            connection.execute(
                users.update().where(users.c.id == row["id"]).values(recovery_codes_json=[])
            )

    organizations = sa.table("organizations", sa.column("id", sa.Uuid()))
    policies = sa.table(
        "mfa_policies",
        sa.column("id", sa.Uuid()),
        sa.column("organization_id", sa.Uuid()),
        sa.column("mode", sa.String()),
        sa.column("required_roles_json", sa.JSON()),
        sa.column("grace_period_days", sa.Integer()),
    )
    for org_id in connection.execute(sa.select(organizations.c.id)).scalars():
        connection.execute(
            policies.insert().values(
                id=uuid.uuid4(),
                organization_id=org_id,
                mode="optional",
                required_roles_json=[],
                grace_period_days=7,
            )
        )


def downgrade() -> None:
    op.drop_table("authentication_throttles")
    op.drop_table("mfa_policies")
    op.drop_table("webauthn_challenges")
    op.drop_table("webauthn_credentials")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("totp_factors")
    op.drop_column("user_sessions", "authentication_methods_json")
    op.drop_column("user_sessions", "mfa_authenticated_at")
    op.drop_column("user_sessions", "mfa_pending")
    op.drop_column("users", "mfa_grace_expires_at")
