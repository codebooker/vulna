"""Phase 41 upgrade backfill, fresh-install, and bounded downgrade checks."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
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


def test_phase41_upgrade_backfills_profiles_and_scores(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "a5b6c7d8e9f0")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    asset_id = uuid.uuid4().hex
    finding_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-risk-org', 'UTC', '{}', '{}')
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
            INSERT INTO assets
                (id, organization_id, site_id, canonical_name, asset_type, status,
                 identity_confidence, tags_json, metadata_json, environment, criticality,
                 data_classification, internet_exposed, context_json)
            VALUES (?, ?, ?, 'legacy-host', 'SERVER', 'ACTIVE', 80, '[]', '{}',
                    'production', 'mission_critical', 'restricted', 1, '{}')
            """,
            (asset_id, org_id, site_id),
        )
        connection.execute(
            """
            INSERT INTO findings
                (id, organization_id, site_id, asset_id, scanner_name,
                 canonical_finding_key, finding_type, title, severity, cvss_score,
                 cve_ids_json, cwe_ids_json, confidence, validation_status,
                 evidence_json, references_json, status, reopened_count,
                 known_exploited, epss_score, false_positive_reason)
            VALUES (?, ?, ?, ?, 'legacy', ?, 'VULNERABILITY', 'Legacy critical',
                    'CRITICAL', 10.0, ?, '[]', 100, 'CONFIRMED_EXPLOITABLE',
                    '{}', '[]', 'FALSE_POSITIVE', 0, 1, 1.0,
                    'Validated as a scanner signature mismatch')
            """,
            (finding_id, org_id, site_id, asset_id, uuid.uuid4().hex, json.dumps(["CVE-2026-1"])),
        )
        connection.commit()

    _alembic(database, "upgrade", "b6c7d8e9f0a1")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        profile = connection.execute(
            "SELECT name, version, is_default, weights_json FROM risk_profiles"
        ).fetchone()
        assert profile is not None
        assert (profile["name"], profile["version"], profile["is_default"]) == (
            "Vulna default",
            1,
            1,
        )
        assert len(json.loads(profile["weights_json"])) == 8
        finding = connection.execute(
            """
            SELECT current_score_snapshot_id, risk_score, risk_profile_version,
                   risk_input_hash, risk_scored_at
            FROM findings WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()
        assert finding is not None
        assert finding["current_score_snapshot_id"]
        assert finding["risk_score"] == 100.0
        assert finding["risk_profile_version"] == 1
        assert len(finding["risk_input_hash"]) == 64
        assert finding["risk_scored_at"]
        snapshot = connection.execute(
            "SELECT source_values_json, factors_json FROM finding_score_snapshots"
        ).fetchone()
        assert snapshot is not None
        assert json.loads(snapshot["source_values_json"])["severity"] == "critical"
        assert len(json.loads(snapshot["factors_json"])) == 8
        decision = connection.execute(
            """
            SELECT decision_type, status, reason, evidence_json, previous_status
            FROM finding_decisions
            """
        ).fetchone()
        assert decision is not None
        assert (decision["decision_type"], decision["status"], decision["previous_status"]) == (
            "false_positive",
            "active",
            "new",
        )
        assert decision["reason"] == "Validated as a scanner signature mismatch"
        assert json.loads(decision["evidence_json"])[0]["type"] == "migration_record"

        restored_database = tmp_path / "restored.db"
        with sqlite3.connect(restored_database) as restored_connection:
            connection.backup(restored_connection)

    with sqlite3.connect(restored_database) as restored_connection:
        restored_score = restored_connection.execute(
            "SELECT risk_score, risk_input_hash FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        restored_decisions = restored_connection.execute(
            "SELECT COUNT(*) FROM finding_decisions WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()[0]
    assert restored_score is not None
    assert restored_score[0] == 100.0
    assert len(restored_score[1]) == 64
    assert restored_decisions == 1

    _alembic(database, "downgrade", "a5b6c7d8e9f0")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        finding_columns = {row[1] for row in connection.execute("PRAGMA table_info('findings')")}
        title = connection.execute(
            "SELECT title FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()[0]
    assert "risk_profiles" not in tables
    assert "finding_score_snapshots" not in tables
    assert "risk_score" not in finding_columns
    assert title == "Legacy critical"


def test_phase41_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
