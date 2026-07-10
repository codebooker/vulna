"""End-to-end startup test: the application lifespan creates tables and seeds
the bootstrap administrator, and that administrator can then log in.

This exercises the real global engine and lifespan wiring (unlike the other
tests, which override the DB dependency), so it uses a throwaway temp-file
SQLite database and resets global engine state afterwards.
"""

from __future__ import annotations

from pathlib import Path

import app.db.session as session_module
import pytest
from app.core.config import get_settings
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "startup.db"
    monkeypatch.setenv("VULNA_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("VULNA_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("VULNA_ADMIN_EMAIL", "startup-admin@example.com")
    monkeypatch.setenv("VULNA_ADMIN_PASSWORD", "a-strong-bootstrap-password")
    # Force fresh settings and engine bound to the temp database.
    get_settings.cache_clear()
    monkeypatch.setattr(session_module, "_engine", None)
    monkeypatch.setattr(session_module, "_sessionmaker", None)
    yield
    # Reset global state so subsequent tests rebuild their own engine/settings.
    session_module._engine = None
    session_module._sessionmaker = None
    get_settings.cache_clear()


def test_lifespan_creates_schema_and_bootstraps_admin(isolated_env: None) -> None:
    app = create_app()
    with TestClient(app) as http_client:  # runs startup + shutdown lifespan
        health = http_client.get("/health")
        assert health.status_code == 200

        login = http_client.post(
            "/api/v1/auth/login",
            json={
                "email": "startup-admin@example.com",
                "password": "a-strong-bootstrap-password",
            },
        )
        assert login.status_code == 200
        assert login.json()["access_token"]
