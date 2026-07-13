"""Phase 44 asset-state backfill, backup/restore, fresh install, and downgrade checks."""

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


def test_phase44_upgrade_backfills_asset_state_and_survives_backup(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "d8e9f0a1b2c3")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    assessed_id = uuid.uuid4().hex
    discovered_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-phase44', 'UTC', '{}', '{}')
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
        for asset_id, assessed_at in (
            (assessed_id, "2026-07-01T00:00:00+00:00"),
            (discovered_id, None),
        ):
            connection.execute(
                """
                INSERT INTO assets
                    (id, organization_id, site_id, canonical_name, asset_type, status,
                     identity_confidence, tags_json, metadata_json, context_json,
                     environment, criticality, data_classification, internet_exposed,
                     first_seen_at, last_seen_at, last_assessed_at)
                VALUES (?, ?, ?, 'legacy', 'UNKNOWN', 'ACTIVE', 50, '[]', '{}', '{}',
                        'unknown', 'unknown', 'unknown', 0,
                        '2026-06-01T00:00:00+00:00',
                        '2026-07-01T00:00:00+00:00', ?)
                """,
                (asset_id, org_id, site_id, assessed_at),
            )
        connection.commit()

    _alembic(database, "upgrade", "e9f0a1b2c3d4")
    with sqlite3.connect(database) as connection:
        states = dict(connection.execute("SELECT asset_id, state FROM asset_inventory_states"))
        assert states[assessed_id] == "assessed"
        assert states[discovered_id] == "discovered"
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "inventory_connectors",
            "connector_runs",
            "asset_observations",
            "asset_source_links",
            "asset_inventory_states",
            "inventory_lifecycle_events",
            "reconciliation_candidates",
            "daily_finding_aggregates",
            "analytics_cache_entries",
            "report_templates",
            "report_template_schedules",
            "report_template_runs",
        } <= tables
        restored_database = tmp_path / "restored.db"
        with sqlite3.connect(restored_database) as restored:
            connection.backup(restored)
    with sqlite3.connect(restored_database) as restored:
        assert restored.execute("SELECT COUNT(*) FROM asset_inventory_states").fetchone() == (2,)

    _alembic(database, "downgrade", "d8e9f0a1b2c3")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "asset_inventory_states" not in tables
        assert "report_templates" not in tables
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone() == (2,)


def test_phase44_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
