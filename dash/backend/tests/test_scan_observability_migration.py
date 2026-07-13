"""Scan-observability upgrade, backfill, backup/restore, and downgrade coverage."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.release_gate
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


def test_observability_upgrade_backfill_backup_and_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "scan-observability.db"
    _alembic(database, "upgrade", "f0a1b2c3d4e5")
    org_id, site_id, probe_id, job_id = (uuid.uuid4().hex for _ in range(4))
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy scans', 'legacy-scans', 'UTC', '{}', '{}')
            """,
            (org_id,),
        )
        connection.execute(
            """
            INSERT INTO sites (id, organization_id, name, code, timezone, tags)
            VALUES (?, ?, 'Main', 'MAIN', 'UTC', '[]')
            """,
            (site_id, org_id),
        )
        connection.execute(
            """
            INSERT INTO probes
                (id, organization_id, site_id, name, status, certificate_fingerprint,
                 capabilities_json, health_json, upgrade_channel)
            VALUES (?, ?, ?, 'Legacy Scout', 'ENROLLED', ?, '{}', '{}', 'stable')
            """,
            (probe_id, org_id, site_id, "a" * 64),
        )
        connection.execute(
            """
            INSERT INTO scan_jobs
                (id, organization_id, site_id, probe_id, mode, status,
                 requested_targets_json, workflow_json, limits_json, policy_version,
                 envelope_json, job_signature, not_before, expires_at, summary_json)
            VALUES (?, ?, ?, ?, 'VULNERABILITY_ASSESSMENT', 'COMPLETED',
                    '["192.0.2.1"]', '[]', '{}', 1, '{}', 'legacy',
                    '2026-07-01T00:00:00+00:00', '2026-07-01T03:00:00+00:00', '{}')
            """,
            (job_id, org_id, site_id, probe_id),
        )
        connection.commit()

    _alembic(database, "upgrade", "0b1c2d3e4f5a")
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT progress_percent, progress_json, failure_log_json
            FROM scan_jobs WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
        assert row == (100, "{}", "[]")
        connection.execute(
            """
            UPDATE scan_jobs
            SET progress_percent = 66,
                progress_json = '{"stages_completed":2,"stages_total":3}',
                failure_log_json = '[{"code":"scanner_error","message":"safe"}]'
            WHERE id = ?
            """,
            (job_id,),
        )
        connection.commit()
        restored_path = tmp_path / "scan-observability-restored.db"
        with sqlite3.connect(restored_path) as restored:
            connection.backup(restored)
    with sqlite3.connect(restored_path) as restored:
        assert restored.execute(
            "SELECT progress_percent FROM scan_jobs WHERE id = ?", (job_id,)
        ).fetchone() == (66,)
        assert (
            "scanner_error"
            in restored.execute(
                "SELECT failure_log_json FROM scan_jobs WHERE id = ?", (job_id,)
            ).fetchone()[0]
        )

    _alembic(database, "downgrade", "f0a1b2c3d4e5")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_jobs)")}
        assert "progress_percent" not in columns
        assert "failure_log_json" not in columns
        assert connection.execute("SELECT COUNT(*) FROM scan_jobs").fetchone() == (1,)


def test_scan_observability_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
