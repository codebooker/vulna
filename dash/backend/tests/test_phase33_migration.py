"""Phase 33 migration coverage for prior-head upgrades and fresh installs."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _alembic(database: Path, *args: str) -> None:
    env = {
        **os.environ,
        "VULNA_DATABASE_URL": f"sqlite+aiosqlite:///{database}",
    }
    subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def test_phase33_upgrades_prior_head_and_downgrades(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "d6e7f8a9b0c1")
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations (
                id, name, slug, default_timezone, settings_json,
                retention_policy_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                "12345678123456781234567812345678",
                "Existing",
                "existing",
                "UTC",
                "{}",
                "{}",
            ),
        )
    _alembic(database, "upgrade", "head")
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT experience_profile, feature_overrides_json "
            "FROM organizations WHERE slug = 'existing'"
        ).fetchone()
    assert row == ("small_business", "{}")

    _alembic(database, "downgrade", "d6e7f8a9b0c1")
    with sqlite3.connect(database) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(organizations)")
        }
    assert "experience_profile" not in columns
    assert "feature_overrides_json" not in columns


def test_phase33_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
