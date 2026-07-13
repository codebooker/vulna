"""Production configuration fail-closed regression tests."""

from __future__ import annotations

import pytest
from app.core.config import Settings, get_settings
from app.main import create_app


def _production(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "production",
        "secret_key": "token-signing-0123456789-ABCDEFGH",
        "master_key": "evidence-key-9876543210-HGFEDCBA",
        "postgres_password": "database-Password-2468",
    }
    values.update(overrides)
    return Settings(**values)


def test_production_requires_distinct_non_placeholder_secrets() -> None:
    _production().validate_for_startup()

    for overrides in (
        {"secret_key": None},
        {"secret_key": "change-me-token-signing-secret-012345"},
        {"master_key": None},
        {"master_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"postgres_password": "short"},
        {"bootstrap_admin_password": "test-only-admin-password"},
        {"auto_create_tables": True},
    ):
        with pytest.raises(RuntimeError):
            _production(**overrides).validate_for_startup()


def test_non_production_retains_explicit_developer_flexibility() -> None:
    Settings(env="development", secret_key=None, master_key=None).validate_for_startup()


def test_trusted_proxy_default_is_loopback_only() -> None:
    assert Settings().trusted_proxies == "127.0.0.1/32,::1/128"


def test_production_api_docs_are_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNA_ENV", "production")
    monkeypatch.delenv("VULNA_EXPOSE_API_DOCS", raising=False)
    get_settings.cache_clear()
    try:
        application = create_app()
        assert application.docs_url is None
        assert application.openapi_url is None

        monkeypatch.setenv("VULNA_EXPOSE_API_DOCS", "true")
        get_settings.cache_clear()
        application = create_app()
        assert application.docs_url == "/docs"
        assert application.openapi_url == "/openapi.json"
    finally:
        get_settings.cache_clear()
