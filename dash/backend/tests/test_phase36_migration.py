"""Phase 36 prior-head, fresh-install, backfill, and downgrade coverage."""

from __future__ import annotations

import json
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


def test_phase36_upgrade_migrates_only_recovery_hashes_and_downgrades(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "a9b0c1d2e3f4")
    old_hashes = ["$argon2id$legacy-one", "$argon2id$legacy-two"]
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
                recovery_codes_json, recovery_codes_generated_at, created_at, updated_at
            ) VALUES (
                '22222222222222222222222222222222',
                '11111111111111111111111111111111', 'existing@example.com',
                '$argon2id$existing-hash', 'ADMINISTRATOR', 1, 'active', 'local',
                'all', 2, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """,
            (json.dumps(old_hashes),),
        )

    _alembic(database, "upgrade", "b0c1d2e3f4a5")
    with sqlite3.connect(database) as connection:
        migrated = [
            row[0]
            for row in connection.execute(
                "SELECT code_hash FROM mfa_recovery_codes ORDER BY code_hash"
            )
        ]
        legacy = connection.execute(
            "SELECT recovery_codes_json FROM users WHERE email = 'existing@example.com'"
        ).fetchone()[0]
        policy = connection.execute(
            "SELECT mode, grace_period_days FROM mfa_policies"
        ).fetchone()
        session_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(user_sessions)")
        }
    assert migrated == sorted(old_hashes)
    assert json.loads(legacy) == []
    assert policy == ("optional", 7)
    assert {"mfa_pending", "mfa_authenticated_at", "authentication_methods_json"}.issubset(
        session_columns
    )

    _alembic(database, "downgrade", "a9b0c1d2e3f4")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        # Downgrade cannot safely recreate consumed/rotated recovery-code state.
        legacy = connection.execute(
            "SELECT recovery_codes_json FROM users WHERE email = 'existing@example.com'"
        ).fetchone()[0]
    assert "mfa_recovery_codes" not in tables
    assert "webauthn_credentials" not in tables
    assert json.loads(legacy) == []


def test_phase36_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
