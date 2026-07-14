"""cve_product_index upgrade/backfill/downgrade and fresh-install coverage."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
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


def test_cve_product_index_upgrade_backfill_and_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "cve.db"
    _alembic(database, "upgrade", "0b1c2d3e4f5a")

    cpe_matches = json.dumps(
        [
            {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*", "vulnerable": True},  # hw: skip
        ]
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO cve_records
                (cve_id, cpe_matches_json, cwe_ids_json, references_json, source, rejected)
            VALUES (?, ?, '[]', '[]', 'nvd', 0)
            """,
            ("CVE-2021-41773", cpe_matches),
        )
        connection.commit()

    _alembic(database, "upgrade", "cve1prod2idx3")
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT product, cve_id FROM cve_product_index ORDER BY product"
        ).fetchall()
        # The application and OS products are backfilled; the hardware CPE is not.
        assert rows == [
            ("http_server", "CVE-2021-41773"),
            ("linux_kernel", "CVE-2021-41773"),
        ]

    _alembic(database, "downgrade", "0b1c2d3e4f5a")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "cve_product_index" not in tables


def test_cve_product_index_fresh_install_matches_metadata(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "check")
