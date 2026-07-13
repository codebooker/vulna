"""Phase 34 prior-head, fresh-install, downgrade, and backfill coverage."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _alembic(database: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "VULNA_DATABASE_URL": f"sqlite+aiosqlite:///{database}",
    }
    return subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=check,
        capture_output=True,
        text=True,
    )


def _insert_organization(connection: sqlite3.Connection, *, suffix: str = "") -> str:
    org_id = f"1234567812345678123456781234{suffix or '5678'}"
    connection.execute(
        """
        INSERT INTO organizations (
            id, name, slug, default_timezone, settings_json,
            retention_policy_json, experience_profile, feature_overrides_json,
            created_at, updated_at
        ) VALUES (?, ?, ?, 'UTC', '{}', '{}', 'small_business', '{}',
                  CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (org_id, f"Existing {suffix}", f"existing-{suffix or 'org'}"),
    )
    return org_id


def test_phase34_upgrades_prior_head_backfills_and_downgrades(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "e7f8a9b0c1d2")
    with sqlite3.connect(database) as connection:
        org_id = _insert_organization(connection)
        for index, active in enumerate((1, 0), start=1):
            connection.execute(
                """
                INSERT INTO users (
                    id, organization_id, email, hashed_password, full_name, role,
                    is_active, recovery_codes_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'ADMINISTRATOR', ?, '[]',
                          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    f"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{index}",
                    org_id,
                    f"user{index}@example.com",
                    "$argon2id$existing-hash",
                    f"User {index}",
                    active,
                ),
            )
    # Pin the Phase 34 assertion to its own revision. Later migrations may
    # intentionally transform these fields (Phase 35 increments auth_version).
    _alembic(database, "upgrade", "f8a9b0c1d2e3")
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT account_status, authentication_source, site_access_mode,
                   auth_version, activated_at IS NOT NULL, deactivated_at IS NOT NULL
            FROM users ORDER BY email
            """
        ).fetchall()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert rows == [
        ("active", "local", "all", 1, 1, 0),
        ("deactivated", "local", "all", 1, 0, 1),
    ]
    assert {
        "user_invitations",
        "password_reset_tokens",
        "user_site_assignments",
        "user_lifecycle_events",
    }.issubset(tables)

    _alembic(database, "downgrade", "e7f8a9b0c1d2")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        password_column = next(
            row
            for row in connection.execute("PRAGMA table_info(users)")
            if row[1] == "hashed_password"
        )
    assert "account_status" not in columns
    assert password_column[3] == 1  # restored NOT NULL


def test_phase34_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")


def test_phase34_downgrade_refuses_passwordless_invited_accounts(tmp_path: Path) -> None:
    database = tmp_path / "refuse.db"
    _alembic(database, "upgrade", "head")
    with sqlite3.connect(database) as connection:
        org_id = _insert_organization(connection, suffix="9999")
        connection.execute(
            """
            INSERT INTO users (
                id, organization_id, email, hashed_password, role, is_active,
                account_status, authentication_source, site_access_mode, auth_version,
                recovery_codes_json, created_at, updated_at
            ) VALUES (
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', ?, 'invited@example.com', NULL,
                'VIEWER', 0, 'invited', 'local', 'assigned', 1, '[]',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """,
            (org_id,),
        )
    result = _alembic(database, "downgrade", "e7f8a9b0c1d2", check=False)
    assert result.returncode != 0
    assert "downgrade refused" in (result.stdout + result.stderr).lower()
