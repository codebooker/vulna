"""Phase 38 prior-head, fresh-install, and downgrade migration coverage."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _alembic(database: Path, *args: str) -> None:
    env = {**os.environ, "VULNA_DATABASE_URL": f"sqlite+aiosqlite:///{database}"}
    subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def test_phase38_upgrade_preserves_users_and_adds_scim_storage(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "c1d2e3f4a5b6")
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations (
                id, name, slug, default_timezone, settings_json,
                retention_policy_json, experience_profile, feature_overrides_json,
                created_at, updated_at
            ) VALUES (
                '11111111111111111111111111111111', 'Existing', 'existing', 'UTC',
                '{}', '{}', 'small_business', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO users (
                id, organization_id, email, hashed_password, role, is_active,
                account_status, authentication_source, site_access_mode, auth_version,
                recovery_codes_json, is_break_glass, created_at, updated_at
            ) VALUES (
                '22222222222222222222222222222222',
                '11111111111111111111111111111111', 'existing@example.com',
                '$argon2id$existing-hash', 'ADMINISTRATOR', 1, 'active', 'local',
                'all', 2, '[]', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """
        )

    _alembic(database, "upgrade", "d2e3f4a5b6c7")
    with sqlite3.connect(database) as connection:
        user = connection.execute(
            "SELECT email, authentication_source, scim_external_id FROM users"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert user == ("existing@example.com", "local", None)
    assert {
        "scim_tokens",
        "scim_groups",
        "scim_group_members",
        "scim_group_site_mappings",
        "scim_provisioning_logs",
        "scim_rate_limit_windows",
    }.issubset(tables)

    _alembic(database, "downgrade", "c1d2e3f4a5b6")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info('users')")}
        user = connection.execute(
            "SELECT email, authentication_source, is_break_glass FROM users"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert "scim_external_id" not in columns
    assert "scim_tokens" not in tables
    assert user == ("existing@example.com", "local", 1)


def test_phase38_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
