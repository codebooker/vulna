"""Application configuration loaded from the environment.

No secrets are hard-coded. Values come from environment variables (see
``.env.example`` at the repository root). Only non-sensitive, presentational
settings are given defaults here; anything sensitive must be supplied explicitly.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="VULNA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Presentational / non-sensitive settings with safe defaults.
    app_name: str = "VulnaDash"
    env: str = "development"
    log_level: str = "info"

    # Comma-separated list of allowed CORS origins.
    cors_origins: str = "http://localhost:5173"

    @property
    def version(self) -> str:
        """The running application version."""
        from app import __version__

        return __version__

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins parsed into a list, ignoring blanks."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()
