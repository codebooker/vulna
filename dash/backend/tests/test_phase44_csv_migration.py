"""Phase 44 CSV source upgrade, backup/restore, and downgrade coverage."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from app.core.config import get_settings
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret

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


def test_csv_source_upgrade_backup_restore_and_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "csv-upgrade.db"
    _alembic(database, "upgrade", "e9f0a1b2c3d4")
    org_id = uuid.uuid4().hex
    site_id = uuid.uuid4().hex
    connector_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES (?, 'CSV Org', 'csv-org', 'UTC', '{}', '{}')
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
            INSERT INTO inventory_connectors
                (id, organization_id, site_id, name, connector_type, config_json, enabled)
            VALUES (?, ?, ?, 'CSV', 'csv', '{}', 0)
            """,
            (connector_id, org_id, site_id),
        )
        connection.commit()

    _alembic(database, "upgrade", "f0a1b2c3d4e5")
    source = b"id,hostname\nasset-1,web-01\n"
    ciphertext = encrypt_secret(
        get_settings().secret_key,
        SecretPurpose.INVENTORY_CSV_SOURCE,
        base64.b64encode(source).decode("ascii"),
    )
    source_sha256 = hashlib.sha256(source).hexdigest()
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(inventory_connectors)")}
        assert {
            "encrypted_source_data",
            "source_filename",
            "source_sha256",
            "source_size_bytes",
            "source_uploaded_at",
            "source_uploaded_by_user_id",
        } <= columns
        connection.execute(
            """
            UPDATE inventory_connectors
            SET encrypted_source_data = ?, source_filename = 'assets.csv',
                source_sha256 = ?, source_size_bytes = ?
            WHERE id = ?
            """,
            (ciphertext, source_sha256, len(source), connector_id),
        )
        connection.commit()
        restored_path = tmp_path / "csv-restored.db"
        with sqlite3.connect(restored_path) as restored:
            connection.backup(restored)
    with sqlite3.connect(restored_path) as restored:
        restored_row = restored.execute(
            """
            SELECT encrypted_source_data, source_filename, source_sha256, source_size_bytes
            FROM inventory_connectors
            """
        ).fetchone()
        assert restored_row is not None
        assert restored_row[1:] == ("assets.csv", source_sha256, len(source))
        encoded = decrypt_secret(
            get_settings().secret_key,
            SecretPurpose.INVENTORY_CSV_SOURCE,
            restored_row[0],
        )
        assert base64.b64decode(encoded, validate=True) == source

    _alembic(database, "downgrade", "e9f0a1b2c3d4")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(inventory_connectors)")}
        assert "encrypted_source_data" not in columns
        assert connection.execute("SELECT COUNT(*) FROM inventory_connectors").fetchone() == (1,)
