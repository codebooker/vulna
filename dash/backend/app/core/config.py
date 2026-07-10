"""Application configuration loaded from the environment.

No secrets are hard-coded. Values come from environment variables (see
``.env.example`` at the repository root). Only non-sensitive, presentational
settings are given defaults here; anything sensitive must be supplied explicitly.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
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

    # ---- Database -----------------------------------------------------------
    # A full SQLAlchemy URL may be supplied directly; otherwise it is assembled
    # from the discrete POSTGRES_* variables. Both prefixed and unprefixed
    # environment names are accepted so the shared ``.env`` works for every
    # service.
    database_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VULNA_DATABASE_URL", "DATABASE_URL"),
    )
    postgres_host: str = Field(
        default="postgres", validation_alias=AliasChoices("VULNA_POSTGRES_HOST", "POSTGRES_HOST")
    )
    postgres_port: int = Field(
        default=5432, validation_alias=AliasChoices("VULNA_POSTGRES_PORT", "POSTGRES_PORT")
    )
    postgres_db: str = Field(
        default="vulna", validation_alias=AliasChoices("VULNA_POSTGRES_DB", "POSTGRES_DB")
    )
    postgres_user: str = Field(
        default="vulna", validation_alias=AliasChoices("VULNA_POSTGRES_USER", "POSTGRES_USER")
    )
    postgres_password: str = Field(
        default="", validation_alias=AliasChoices("VULNA_POSTGRES_PASSWORD", "POSTGRES_PASSWORD")
    )

    # Echo SQL statements (development debugging only).
    db_echo: bool = False

    # ---- Authentication / tokens -------------------------------------------
    # Secret used to sign session/API tokens. Required for authentication to
    # function; there is intentionally no default so a secret is never shipped.
    secret_key: str | None = None
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 720  # 12 hours

    # ---- Administrator bootstrap -------------------------------------------
    # If both are provided and no administrator exists yet, a first admin user
    # is created at startup. Never hard-code these; supply via the environment.
    bootstrap_admin_email: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VULNA_ADMIN_EMAIL", "VULNA_BOOTSTRAP_ADMIN_EMAIL"),
    )
    bootstrap_admin_password: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VULNA_ADMIN_PASSWORD", "VULNA_BOOTSTRAP_ADMIN_PASSWORD"),
    )

    # Default organization seeded on first startup. The MVP exposes a single
    # organization but the schema preserves organization boundaries throughout.
    default_org_name: str = "Default Organization"
    default_org_slug: str = "default"

    # When true, create database tables from the ORM metadata at startup
    # instead of relying on Alembic migrations. Useful for local/dev and tests;
    # production should run migrations and leave this disabled.
    auto_create_tables: bool = False

    # ---- VulnaScout enrollment / PKI ---------------------------------------
    # Internal certificate authority used to sign VulnaScout client
    # certificates. Generated on first use if missing (dev) or via `vulna
    # ca-init`. Keep the CA private key secret and backed up.
    ca_key_path: str = "/var/lib/vulna/keys/ca_key.pem"
    ca_cert_path: str = "/var/lib/vulna/keys/ca_cert.pem"
    # Bounded validity for issued client certificates (days).
    client_cert_validity_days: int = 90
    # One-time enrollment tokens expire after this many minutes.
    enrollment_token_ttl_minutes: int = 15
    # A probe is considered offline if it has not sent a heartbeat within this
    # many seconds.
    probe_offline_after_seconds: int = 180
    # Header, set by the mTLS-terminating reverse proxy (Caddy), carrying the
    # SHA-256 fingerprint of the verified client certificate. The API trusts
    # this header only because it is never exposed directly to probes; only the
    # proxy can reach it. See docs/threat-model.md.
    probe_cert_fingerprint_header: str = "x-vulna-client-cert-fingerprint"

    # ---- Job / policy signing (Ed25519) ------------------------------------
    # Key pair used to sign job envelopes and local policy documents. Probes
    # hold only the public key and reject unsigned or altered jobs/policies.
    # Generated on first use if missing; keep the private key secret and backed
    # up.
    job_signing_key_path: str = "/var/lib/vulna/keys/job_signing_ed25519"
    job_signing_pubkey_path: str = "/var/lib/vulna/keys/job_signing_ed25519.pub"
    # Default job time window (minutes) applied when a request omits explicit
    # not_before/expires_at.
    job_default_ttl_minutes: int = 240

    # ---- VulnaWatch intelligence feeds (Phase 7) ---------------------------
    # Upstream feed endpoints (overridable, e.g. for an internal mirror). NVD
    # accepts an optional API key to raise its rate limit; never hard-code it.
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_feed_url: str = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    # A feed with no successful sync within this many hours is reported "stale".
    feed_stale_after_hours: int = 48
    # EPSS probability at/above which a change crossing it raises an event.
    epss_alert_threshold: float = 0.5

    # ---- Reports (Phase 8) --------------------------------------------------
    # Directory where generated report artifacts (PDF/CSV/JSON) are stored.
    reports_dir: str = "/var/lib/vulna/reports"
    # Generated reports are considered downloadable until this many days pass.
    report_ttl_days: int = 90

    @property
    def version(self) -> str:
        """The running application version."""
        from app import __version__

        return __version__

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins parsed into a list, ignoring blanks."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def sqlalchemy_database_uri(self) -> str:
        """Return the async SQLAlchemy database URL.

        Uses ``database_url`` verbatim when supplied, otherwise assembles an
        asyncpg URL from the discrete PostgreSQL settings.
        """
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    def require_secret_key(self) -> str:
        """Return the token signing secret or raise if it is not configured."""
        if not self.secret_key:
            raise RuntimeError(
                "VULNA_SECRET_KEY is not set. Generate one (e.g. `openssl rand -base64 48`) "
                "and provide it via the environment before enabling authentication."
            )
        return self.secret_key


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()
