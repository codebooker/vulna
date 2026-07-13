"""Phase 42 prior-head backfill, backup/restore, fresh install, and downgrade checks."""

from __future__ import annotations

import json
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


def test_phase42_upgrade_backfills_and_survives_backup(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "b6c7d8e9f0a1")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    probe_id = uuid.uuid4().hex
    job_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-phase42', 'UTC', '{}', '{}')
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
                 capabilities_json, health_json, upgrade_channel, pentest_enabled)
            VALUES (?, ?, ?, 'legacy-scout', 'ENROLLED', ?, '[]', '{}', 'stable', 0)
            """,
            (probe_id, org_id, site_id, "f" * 64),
        )
        connection.execute(
            """
            INSERT INTO scan_jobs
                (id, organization_id, site_id, probe_id, mode, status,
                 requested_targets_json, workflow_json, limits_json, policy_version,
                 envelope_json, job_signature, not_before, expires_at,
                 summary_json, verifies_finding_ids_json)
            VALUES (?, ?, ?, ?, 'VULNERABILITY_ASSESSMENT', 'COMPLETED',
                    '["10.0.0.1/32"]', '[]', '{}', 1, '{}', 'legacy-signature',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T01:00:00+00:00', '{}', '[]')
            """,
            (job_id, org_id, site_id, probe_id),
        )
        connection.commit()

    _alembic(database, "upgrade", "c7d8e9f0a1b2")
    with sqlite3.connect(database) as connection:
        probe = connection.execute(
            """
            SELECT credentialed_scans_enabled, encryption_public_key_b64
            FROM probes WHERE id = ?
            """,
            (probe_id,),
        ).fetchone()
        job = connection.execute(
            """
            SELECT asset_id, credential_protocols_json FROM scan_jobs WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert probe == (0, None)
        assert job is not None and job[0] is None and json.loads(job[1]) == []
        assert {
            "credential_records",
            "credential_secret_versions",
            "credential_assignments",
            "credential_tests",
            "credential_usage_audit",
            "software_inventory_items",
            "software_inventory_history",
            "eol_intelligence_records",
            "eol_overrides",
        } <= tables

        restored_database = tmp_path / "restored.db"
        with sqlite3.connect(restored_database) as restored:
            connection.backup(restored)
    with sqlite3.connect(restored_database) as restored:
        assert restored.execute(
            "SELECT credentialed_scans_enabled FROM probes WHERE id = ?", (probe_id,)
        ).fetchone() == (0,)
        assert restored.execute(
            "SELECT credential_protocols_json FROM scan_jobs WHERE id = ?", (job_id,)
        ).fetchone() == ("[]",)

    _alembic(database, "downgrade", "b6c7d8e9f0a1")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        probe_columns = {row[1] for row in connection.execute("PRAGMA table_info('probes')")}
        job_columns = {row[1] for row in connection.execute("PRAGMA table_info('scan_jobs')")}
        assert connection.execute(
            "SELECT name FROM probes WHERE id = ?", (probe_id,)
        ).fetchone() == ("legacy-scout",)
    assert "credential_records" not in tables
    assert "credentialed_scans_enabled" not in probe_columns
    assert "credential_protocols_json" not in job_columns


def test_phase42_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
