"""Release-gate coverage for audit-integrity and authorization backfills."""

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


def test_governance_upgrade_safely_retires_legacy_authorizations(tmp_path: Path) -> None:
    database = tmp_path / "governance-upgrade.db"
    _alembic(database, "upgrade", "job1lease2fence")
    organization_id = uuid.uuid4().hex
    roe_id = uuid.uuid4().hex
    event_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'Legacy Org', 'legacy-governance', 'UTC', '{}', '{}')
            """,
            (organization_id,),
        )
        connection.execute(
            """
            INSERT INTO rules_of_engagement
                (id, organization_id, name, allowed_actions_json,
                 prohibited_actions_json, allowed_hours_json, evidence_policy_json,
                 data_retention_days, session_policy_json, cleanup_required,
                 version, created_at, updated_at)
            VALUES (?, ?, 'Legacy RoE', '[]', '[]', '{}', '{}', 30, '{}', 1, 1,
                    '2026-01-01 00:00:00', '2026-01-01 00:00:00')
            """,
            (roe_id, organization_id),
        )
        connection.execute(
            """
            INSERT INTO audit_events
                (id, organization_id, actor_type, action, metadata_json, created_at)
            VALUES (?, ?, 'system', 'legacy.event', '{}', '2026-01-01 00:00:00')
            """,
            (event_id, organization_id),
        )
        connection.commit()

    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
    with sqlite3.connect(database) as connection:
        authorization = connection.execute(
            """
            SELECT authorization_source,
                   effective_until > effective_from,
                   effective_until < CURRENT_TIMESTAMP,
                   authorized_modules_json
              FROM rules_of_engagement
             WHERE id = ?
            """,
            (roe_id,),
        ).fetchone()
        assert authorization == ("legacy", 1, 1, "[]")

        audit = connection.execute(
            """
            SELECT integrity_algorithm, integrity_key_id, chain_sequence, previous_hash
              FROM audit_events
             WHERE id = ?
            """,
            (event_id,),
        ).fetchone()
        assert audit == ("legacy-sha256-v1", "legacy", 1, "0" * 64)

    _alembic(database, "downgrade", "job1lease2fence")
