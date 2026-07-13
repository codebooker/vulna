"""Phase 39 authorization backfill, fresh-install, and downgrade coverage."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _alembic(database: Path, *args: str) -> None:
    env = {**os.environ, "VULNA_DATABASE_URL": f"sqlite+aiosqlite:///{database}"}
    result = subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_phase39_upgrade_backfills_roles_and_scoped_grants(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "d2e3f4a5b6c7")
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
            INSERT INTO sites (
                id, organization_id, name, code, timezone, tags, created_at, updated_at
            ) VALUES (
                '33333333333333333333333333333333',
                '11111111111111111111111111111111', 'North', 'N', 'UTC', '[]',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """
        )
        for user_id, email, role, site_mode in (
            ("22222222222222222222222222222222", "admin@example.com", "ADMINISTRATOR", "all"),
            ("44444444444444444444444444444444", "viewer@example.com", "VIEWER", "assigned"),
        ):
            connection.execute(
                """
                INSERT INTO users (
                    id, organization_id, email, hashed_password, role, is_active,
                    account_status, authentication_source, site_access_mode, auth_version,
                    recovery_codes_json, is_break_glass, created_at, updated_at
                ) VALUES (?, '11111111111111111111111111111111', ?, '$argon2id$hash', ?, 1,
                          'active', 'local', ?, 1, '[]', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (user_id, email, role, site_mode),
            )
        connection.execute(
            """
            INSERT INTO user_site_assignments (
                id, organization_id, user_id, site_id, assigned_by_user_id, created_at
            ) VALUES (
                '55555555555555555555555555555555',
                '11111111111111111111111111111111',
                '44444444444444444444444444444444',
                '33333333333333333333333333333333', NULL, CURRENT_TIMESTAMP
            )
            """
        )

    _alembic(database, "upgrade", "e3f4a5b6c7d8")
    with sqlite3.connect(database) as connection:
        role_count = connection.execute(
            "SELECT COUNT(*) FROM authorization_roles WHERE is_system = 1"
        ).fetchone()[0]
        admin_grant = connection.execute(
            """
            SELECT g.scope_type, g.scope_id, r.compatibility_role
            FROM scoped_grants g JOIN authorization_roles r ON r.id = g.role_id
            WHERE g.user_id = '22222222222222222222222222222222'
            """
        ).fetchone()
        viewer_grant = connection.execute(
            """
            SELECT g.scope_type, g.scope_id, r.compatibility_role
            FROM scoped_grants g JOIN authorization_roles r ON r.id = g.role_id
            WHERE g.user_id = '44444444444444444444444444444444'
            """
        ).fetchone()
        permission_count = connection.execute("SELECT COUNT(*) FROM role_permissions").fetchone()[0]
        migrated = connection.execute(
            "SELECT COUNT(*) FROM users WHERE authorization_migrated_at IS NOT NULL"
        ).fetchone()[0]
    assert role_count == 6
    assert admin_grant == (
        "organization",
        "11111111111111111111111111111111",
        "administrator",
    )
    assert viewer_grant == (
        "site",
        "33333333333333333333333333333333",
        "viewer",
    )
    assert permission_count > 100
    assert migrated == 2

    _alembic(database, "downgrade", "d2e3f4a5b6c7")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info('users')")}
        users = connection.execute(
            "SELECT email, role, site_access_mode FROM users ORDER BY email"
        ).fetchall()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert "authorization_migrated_at" not in columns
    assert "authorization_roles" not in tables
    assert users == [
        ("admin@example.com", "ADMINISTRATOR", "all"),
        ("viewer@example.com", "VIEWER", "assigned"),
    ]


def test_phase39_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
