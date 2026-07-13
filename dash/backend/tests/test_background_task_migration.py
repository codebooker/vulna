"""Worker-gate migration upgrade, fresh-install, and downgrade checks."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _alembic(database: Path, *args: str) -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter/test arguments
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env={**os.environ, "VULNA_DATABASE_URL": f"sqlite+aiosqlite:///{database}"},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_background_task_upgrade_and_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "e3f4a5b6c7d8")
    _alembic(database, "upgrade", "f4a5b6c7d8e9")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        task_columns = {
            row[1] for row in connection.execute("PRAGMA table_info('background_tasks')")
        }
    assert {"background_tasks", "worker_heartbeats"} <= tables
    assert {"idempotency_key", "lease_expires_at", "dead_lettered_at"} <= task_columns

    _alembic(database, "downgrade", "e3f4a5b6c7d8")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "background_tasks" not in tables
    assert "worker_heartbeats" not in tables


def test_background_task_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
