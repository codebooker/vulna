"""Phase 43 deadline backfill, backup/restore, fresh install, and downgrade checks."""

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


def _insert_finding(
    connection: sqlite3.Connection,
    *,
    finding_id: str,
    org_id: str,
    site_id: str,
    severity: str,
    due_at: str | None,
) -> None:
    connection.execute(
        """
        INSERT INTO findings
            (id, organization_id, site_id, scanner_name, canonical_finding_key,
             finding_type, title, severity, cve_ids_json, cwe_ids_json,
             confidence, validation_status, evidence_json, references_json,
             status, reopened_count, known_exploited, first_seen_at, due_at)
        VALUES (?, ?, ?, 'legacy', ?, 'VULNERABILITY', 'Legacy finding', ?,
                '[]', '[]', 50, 'UNVALIDATED', '{}', '[]', 'NEW', 0, 0,
                '2026-01-01T00:00:00+00:00', ?)
        """,
        (finding_id, org_id, site_id, uuid.uuid4().hex, severity, due_at),
    )


def test_phase43_upgrade_backfills_deadlines_and_survives_backup(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "c7d8e9f0a1b2")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    preserved_id = uuid.uuid4().hex
    fallback_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-phase43', 'UTC', '{}', '{}')
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
        _insert_finding(
            connection,
            finding_id=preserved_id,
            org_id=org_id,
            site_id=site_id,
            severity="CRITICAL",
            due_at="2026-04-01T00:00:00+00:00",
        )
        _insert_finding(
            connection,
            finding_id=fallback_id,
            org_id=org_id,
            site_id=site_id,
            severity="HIGH",
            due_at=None,
        )
        connection.commit()

    _alembic(database, "upgrade", "d8e9f0a1b2c3")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        findings = {
            row["id"]: row
            for row in connection.execute(
                """
                SELECT id, due_at, current_sla_calculation_id, sla_started_at
                FROM findings
                """
            )
        }
        assert findings[preserved_id]["due_at"].startswith("2026-04-01")
        assert findings[fallback_id]["due_at"].startswith("2026-01-31")
        assert findings[preserved_id]["current_sla_calculation_id"]
        assert findings[fallback_id]["current_sla_calculation_id"]
        calculations = list(
            connection.execute(
                """
                SELECT finding_id, source, calculation_json
                FROM finding_sla_calculations ORDER BY finding_id
                """
            )
        )
        assert len(calculations) == 2
        assert all(row["source"] == "severity_fallback" for row in calculations)
        by_finding = {
            row["finding_id"]: json.loads(row["calculation_json"])
            for row in calculations
        }
        assert by_finding[preserved_id]["preserved_existing_due_at"] is True
        assert by_finding[fallback_id]["days"] == 30
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "sla_policies",
            "finding_sla_calculations",
            "sla_exceptions",
            "sla_history",
            "remediation_guidance",
            "ticket_connectors",
            "ticket_syncs",
            "ticket_sync_events",
        } <= tables

        restored_database = tmp_path / "restored.db"
        with sqlite3.connect(restored_database) as restored:
            connection.backup(restored)
    with sqlite3.connect(restored_database) as restored:
        assert restored.execute("SELECT COUNT(*) FROM finding_sla_calculations").fetchone() == (2,)
        assert restored.execute(
            "SELECT due_at FROM findings WHERE id = ?", (fallback_id,)
        ).fetchone()[0].startswith("2026-01-31")

    _alembic(database, "downgrade", "c7d8e9f0a1b2")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        finding_columns = {row[1] for row in connection.execute("PRAGMA table_info('findings')")}
        assert "finding_sla_calculations" not in tables
        assert "ticket_connectors" not in tables
        assert "current_sla_calculation_id" not in finding_columns
        assert connection.execute(
            "SELECT due_at FROM findings WHERE id = ?", (fallback_id,)
        ).fetchone()[0].startswith("2026-01-31")


def test_phase43_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
