"""Application configuration loaded from the environment.

No secrets are hard-coded. Values come from environment variables (see
``.env.example`` at the repository root). Only non-sensitive, presentational
settings are given defaults here; anything sensitive must be supplied explicitly.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

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
    access_token_expire_minutes: int = 15
    invitation_token_ttl_hours: int = 72
    password_reset_token_ttl_minutes: int = 60
    webauthn_rp_id: str | None = None
    webauthn_rp_name: str = "Vulna"
    webauthn_origin: str | None = None
    # Public HTTPS origin used for OIDC redirect URIs and SAML SP metadata.
    # Development falls back to the incoming request origin; production SSO
    # configuration requires this value to prevent host-header ambiguity.
    sso_public_base_url: str | None = None
    sso_state_ttl_minutes: int = 10
    scim_token_ttl_days: int = 365
    scim_rate_limit_per_minute: int = 300
    scim_max_page_size: int = 200

    # Master key for encrypting sensitive evidence (raw scanner output) at rest.
    # When set (VULNA_MASTER_KEY), stored artifacts are encrypted; when unset
    # (e.g. local dev), they are stored in plaintext. Any string is accepted — a
    # Fernet key is derived from it.
    master_key: str | None = None

    # Dedicated database-backed scheduler/worker services.
    scheduler_enabled: bool = True
    scheduler_interval_seconds: int = Field(default=60, ge=1, le=86_400)
    background_worker_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    background_task_lease_seconds: int = Field(default=300, ge=3, le=86_400)
    background_task_max_attempts: int = Field(default=5, ge=1, le=100)
    background_task_backpressure_limit: int = Field(default=10_000, ge=1)

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
    deployment_profile: Literal["small_business", "enterprise", "custom"] = "small_business"

    # Public base URL of the orchestrator (e.g. https://vulna.example.com), used
    # to build remote-Scout install commands. Falls back to the request's base URL
    # when unset.
    public_base_url: str | None = None
    # Release tag shared with Compose image selection (bare or v-prefixed). It is
    # also used to generate endpoint installer URLs; the package version remains
    # only a development fallback.
    release_version: str | None = Field(
        default=None, validation_alias=AliasChoices("VULNA_VERSION")
    )

    # Networks (comma-separated IPs/CIDRs) whose forwarded headers the API trusts.
    # The mTLS-terminating proxy always sits on the internal/private network, so
    # the default trusts loopback + RFC1918/ULA. Forwarding headers (X-Forwarded-*,
    # the probe fingerprint) from any other peer are ignored, so an untrusted peer
    # cannot spoof the source address or TLS/mTLS state. Set to your proxy's exact
    # address behind an existing reverse proxy.
    trusted_proxies: str = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"

    # ---- Single-host deployment (Phase 17) ---------------------------------
    # When enabled (set by the single-host Compose profile), first-run bootstrap
    # also ensures a default site and mints a one-time, auto-approve enrollment
    # token for the co-located local Scout, written to bootstrap_dir for the
    # Scout container to consume. Off for distributed deployments.
    bootstrap_local_scout: bool = False
    bootstrap_dir: str = "/var/lib/vulna/bootstrap"
    default_site_name: str = "Local Site"
    default_site_code: str = "LOCAL"
    local_scout_name: str = "local-scout"
    local_scout_token_ttl_minutes: int = 60

    # ---- VulnaRelay central WireGuard egress -------------------------------
    # The scanner-free relay appliance connects to this public UDP endpoint.
    # When unset, the host from public_base_url with UDP/51820 is used.
    relay_endpoint: str | None = None
    relay_control_url: str | None = None
    relay_listen_port: int = 51820
    relay_offline_after_seconds: int = 30
    relay_tunnel_cidr: str = "10.254.0.0/24"
    # Shared only between the API and the privileged relay-egress controller.
    # The public relay appliance never receives this token.
    relay_egress_token: str | None = None
    relay_server_public_key_path: str = "/var/lib/vulna/relay/server.pub"
    # Central scanner bound to relay-backed networks in the single-host profile.
    relay_scanner_probe_name: str = "local-scout"

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
    epss_feed_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    # A feed with no successful sync within this many hours is reported "stale".
    feed_stale_after_hours: int = 48
    # EPSS probability at/above which a change crossing it raises an event.
    epss_alert_threshold: float = 0.5

    # ---- Updates (Phase 24) -------------------------------------------------
    # Display-only in the web UI: the running app never fetches or applies
    # releases (that would make it a package-execution channel). Updates are
    # applied by the operator with the signed-manifest-verifying `vulna` CLI.
    update_channel: str = "stable"

    # ---- Backups (Phase 25) -------------------------------------------------
    # Display-only in the web UI. Backups are created, verified, and restored by
    # the operator with the `vulna backup` CLI (encrypted bundles with a
    # user-controlled recovery passphrase); the app never handles the passphrase.
    backup_retention_days: int = 30

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
    def trusted_proxy_networks(self) -> list[Any]:
        """Trusted-proxy networks parsed from ``trusted_proxies``."""
        from app.services.networking import parse_trusted_proxies

        return parse_trusted_proxies(self.trusted_proxies)

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
