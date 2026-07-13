"""Phase 37 prior-head, fresh-install, policy seed, and downgrade coverage."""

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


def test_phase37_upgrade_seeds_disabled_policy_and_preserves_local_login(
    tmp_path: Path,
) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "b0c1d2e3f4a5")
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
                recovery_codes_json,
                created_at, updated_at
            ) VALUES (
                '22222222222222222222222222222222',
                '11111111111111111111111111111111', 'existing@example.com',
                '$argon2id$existing-hash', 'ADMINISTRATOR', 1, 'active', 'local',
                'all', 2, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """
        )

    _alembic(database, "upgrade", "c1d2e3f4a5b6")
    with sqlite3.connect(database) as connection:
        policy = connection.execute("SELECT mode FROM sso_policies").fetchone()[0]
        break_glass = connection.execute(
            "SELECT is_break_glass FROM users WHERE email = 'existing@example.com'"
        ).fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert policy == "disabled"
    assert break_glass == 0
    assert {
        "identity_providers",
        "external_identity_links",
        "identity_group_mappings",
        "identity_provider_tests",
        "sso_protocol_states",
        "saml_replay_records",
    }.issubset(tables)

    _alembic(database, "downgrade", "b0c1d2e3f4a5")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        user = connection.execute(
            "SELECT email, is_active FROM users WHERE email = 'existing@example.com'"
        ).fetchone()
    assert "identity_providers" not in tables
    assert user == ("existing@example.com", 1)


def test_phase37_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
