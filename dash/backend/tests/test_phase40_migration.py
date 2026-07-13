"""Phase 40 upgrade, legacy-tag backfill, fresh install, and downgrade checks."""

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


def test_phase40_upgrade_backfills_tags_and_downgrades(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.db"
    _alembic(database, "upgrade", "f4a5b6c7d8e9")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    asset_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-org', 'UTC', '{}', '{}')
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
                 identity_confidence, tags_json, metadata_json)
            VALUES (?, ?, ?, 'legacy-host', 'server', 'active', 80, ?, ?)
            """,
            (
                asset_id,
                org_id,
                site_id,
                json.dumps(["Payment Tier", " payment   tier ", "Linux"]),
                json.dumps({"scanner": {"source": "legacy"}}),
            ),
        )
        connection.commit()

    _alembic(database, "upgrade", "a5b6c7d8e9f0")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        asset = connection.execute(
            """
            SELECT environment, criticality, data_classification, internet_exposed,
                   context_json, tags_json, metadata_json
            FROM assets WHERE id = ?
            """,
            (asset_id,),
        ).fetchone()
        assert asset is not None
        assert (asset["environment"], asset["criticality"], asset["data_classification"]) == (
            "unknown",
            "unknown",
            "unknown",
        )
        assert asset["internet_exposed"] == 0
        assert json.loads(asset["context_json"]) == {}
        assert json.loads(asset["tags_json"]) == [
            "Payment Tier",
            " payment   tier ",
            "Linux",
        ]
        assert json.loads(asset["metadata_json"]) == {"scanner": {"source": "legacy"}}

        tags = connection.execute(
            "SELECT id, name, normalized_name FROM asset_tags ORDER BY normalized_name"
        ).fetchall()
        assert [(row["name"], row["normalized_name"]) for row in tags] == [
            ("Linux", "linux"),
            ("Payment Tier", "payment tier"),
        ]
        assignments = connection.execute(
            "SELECT source, metadata_json FROM asset_tag_assignments ORDER BY metadata_json"
        ).fetchall()
        assert len(assignments) == 2
        assert {row["source"] for row in assignments} == {"migrated"}
        metadata = [json.loads(row["metadata_json"]) for row in assignments]
        assert all(
            value["asset_metadata"] == {"scanner": {"source": "legacy"}} for value in metadata
        )

    _alembic(database, "downgrade", "f4a5b6c7d8e9")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        asset_columns = {row[1] for row in connection.execute("PRAGMA table_info('assets')")}
        tags_json = connection.execute(
            "SELECT tags_json FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()[0]
    assert "asset_groups" not in tables
    assert "asset_tags" not in tables
    assert "environment" not in asset_columns
    assert json.loads(tags_json) == ["Payment Tier", " payment   tier ", "Linux"]


def test_phase40_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
