"""Shared pytest fixtures for the VulnaDash backend.

Tests run against an in-memory SQLite database using a ``StaticPool`` so the
schema and data persist for the lifetime of a single test, all within the
test's event loop. The FastAPI ``get_session`` dependency is overridden to bind
to that database, so no PostgreSQL instance is required.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

# A signing secret must exist before any settings are loaded. This is a test-only
# value and is never used outside the suite.
os.environ.setdefault("VULNA_SECRET_KEY", "test-only-secret-do-not-use-in-production")
os.environ.setdefault("VULNA_ENV", "test")
os.environ.setdefault("VULNA_WEBAUTHN_ORIGIN", "http://localhost")
os.environ.setdefault("VULNA_WEBAUTHN_RP_ID", "localhost")

# Point the internal CA and job-signing key at a writable temp directory so
# enrollment/signing tests do not touch /var/lib/vulna.
_CA_DIR = Path(tempfile.gettempdir()) / "vulna-test-ca"
os.environ.setdefault("VULNA_CA_KEY_PATH", str(_CA_DIR / "ca_key.pem"))
os.environ.setdefault("VULNA_CA_CERT_PATH", str(_CA_DIR / "ca_cert.pem"))
os.environ.setdefault("VULNA_JOB_SIGNING_KEY_PATH", str(_CA_DIR / "job_signing"))
os.environ.setdefault("VULNA_JOB_SIGNING_PUBKEY_PATH", str(_CA_DIR / "job_signing.pub"))
_RELAY_DIR = Path(tempfile.gettempdir()) / "vulna-test-relay"
_RELAY_DIR.mkdir(parents=True, exist_ok=True)
(_RELAY_DIR / "server.pub").write_text("test-wireguard-server-public-key\n")
os.environ.setdefault("VULNA_RELAY_SERVER_PUBLIC_KEY_PATH", str(_RELAY_DIR / "server.pub"))
os.environ.setdefault("VULNA_RELAY_ENDPOINT", "relay.test:51820")
os.environ.setdefault("VULNA_RELAY_CONTROL_URL", "https://relay.test:8443")
os.environ.setdefault("VULNA_RELAY_EGRESS_TOKEN", "test-only-relay-egress-token")

# Write generated report artifacts under a temp directory, never /var/lib/vulna.
os.environ.setdefault("VULNA_REPORTS_DIR", str(Path(tempfile.gettempdir()) / "vulna-test-reports"))

import app.models  # noqa: F401  (register models on the metadata)
import pytest
import pytest_asyncio
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import get_session
from app.main import create_app
from app.models.enums import UserRole
from app.models.organization import Organization
from app.models.user import User
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

TEST_PASSWORD = "correct horse battery staple"


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """A fresh in-memory SQLite engine with the full schema created."""
    eng = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@pytest_asyncio.fixture
async def db_session(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """A session for arranging and inspecting database state directly in tests."""
    async with sessionmaker() as session:
        yield session


@pytest_asyncio.fixture
async def client(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """An HTTP client bound to the app with the DB dependency overridden.

    The ASGI transport does not run the application lifespan, so startup
    bootstrap/table-creation is handled by the ``engine`` fixture instead.
    """
    application = create_app()

    async def override_get_session() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    application.dependency_overrides[get_session] = override_get_session
    # Present as loopback so trusted-proxy checks (Phase 23) treat the test client
    # like the mTLS-terminating proxy on the internal network.
    transport = ASGITransport(app=application, client=("127.0.0.1", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


@pytest_asyncio.fixture
async def untrusted_client(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """An HTTP client whose peer address is a public IP (an untrusted proxy peer),
    used to prove that forwarded/fingerprint headers are ignored from it."""
    application = create_app()

    async def override_get_session() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    application.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=application, client=("203.0.113.7", 40000))
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


@pytest_asyncio.fixture
async def organization(db_session: AsyncSession) -> Organization:
    """A default organization to own test users and resources."""
    org = Organization(name="Test Org", slug="test-org", default_timezone="UTC")
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


UserFactory = Callable[..., Awaitable[User]]


@pytest_asyncio.fixture
async def make_user(db_session: AsyncSession, organization: Organization) -> UserFactory:
    """Factory fixture that creates a user with a given role."""
    counter = {"n": 0}

    async def _make(
        role: UserRole = UserRole.VIEWER,
        *,
        email: str | None = None,
        password: str = TEST_PASSWORD,
        is_active: bool = True,
    ) -> User:
        counter["n"] += 1
        user = User(
            organization_id=organization.id,
            email=email or f"user{counter['n']}@example.com",
            hashed_password=hash_password(password),
            full_name=f"User {counter['n']}",
            role=role,
            is_active=is_active,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _make


def auth_headers(user: User) -> dict[str, str]:
    """Build an Authorization header carrying a valid token for ``user``."""
    token = create_access_token(
        get_settings(),
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin(make_user: UserFactory) -> User:
    return await make_user(UserRole.ADMINISTRATOR)


@pytest_asyncio.fixture
async def viewer(make_user: UserFactory) -> User:
    return await make_user(UserRole.VIEWER)


@pytest.fixture
def admin_headers(admin: User) -> dict[str, str]:
    return auth_headers(admin)


@pytest.fixture
def viewer_headers(viewer: User) -> dict[str, str]:
    return auth_headers(viewer)


@pytest_asyncio.fixture
async def pentest_approver_headers(make_user: UserFactory) -> dict[str, str]:
    """A distinct approval-only identity for separation-of-duties tests."""
    approver = await make_user(UserRole.PENTEST_APPROVER)
    return auth_headers(approver)


# --- Probe / enrollment helpers ------------------------------------------------

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def generate_csr_pem() -> str:
    """Generate a fresh EC private key and return a PEM CSR (as a probe would)."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vulnascout")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def probe_cert_headers(fingerprint: str) -> dict[str, str]:
    """Build the proxy-injected client-cert header for probe authentication."""
    return {get_settings().probe_cert_fingerprint_header: fingerprint}


def job_attempt_headers(response: Response) -> dict[str, str]:
    """Copy the lease/fencing headers from a Scout job-offer response."""
    headers = response.headers
    return {
        "X-Vulna-Attempt-ID": headers["X-Vulna-Attempt-ID"],
        "X-Vulna-Lease-ID": headers["X-Vulna-Lease-ID"],
        "X-Vulna-Fencing-Token": headers["X-Vulna-Fencing-Token"],
    }


async def start_job_attempt(
    client: AsyncClient, probe_id: str, fingerprint: str
) -> tuple[str, dict[str, str]]:
    """Offer, accept, and start the next job exactly as a current Scout does."""
    headers = probe_cert_headers(fingerprint)
    offered = await client.post(f"/api/v1/probes/{probe_id}/jobs/next", headers=headers)
    assert offered.status_code == 200, offered.text
    headers.update(job_attempt_headers(offered))
    job_id = offered.json()["job_id"]
    for state in ("accepted", "running"):
        response = await client.post(
            f"/api/v1/probes/{probe_id}/jobs/{job_id}/status",
            json={"status": state},
            headers=headers,
        )
        assert response.status_code == 204, response.text
    return job_id, headers


EnrolledProbe = dict[str, str]


@pytest_asyncio.fixture
async def enroll_probe(
    client: AsyncClient, admin_headers: dict[str, str]
) -> Callable[..., Awaitable[EnrolledProbe]]:
    """Factory that provisions a site, mints a token, and enrolls a probe.

    Returns a dict with ``probe_id``, ``site_id``, ``fingerprint``, and the
    issued ``certificate_pem``.
    """

    async def _enroll(site_code: str = "SITE1", probe_name: str = "probe-a") -> EnrolledProbe:
        site = await client.post(
            "/api/v1/sites", json={"name": "Site", "code": site_code}, headers=admin_headers
        )
        site_id = site.json()["id"]
        token_resp = await client.post(
            "/api/v1/probes/enrollment-tokens",
            json={"site_id": site_id, "probe_name": probe_name},
            headers=admin_headers,
        )
        secret = token_resp.json()["token"]
        enroll = await client.post(
            "/api/v1/probes/enroll",
            json={"token": secret, "csr_pem": generate_csr_pem()},
        )
        body = enroll.json()
        return {
            "probe_id": body["probe_id"],
            "site_id": body["site_id"],
            "fingerprint": body["certificate_fingerprint"],
            "certificate_pem": body["certificate_pem"],
            "token": secret,
        }

    return _enroll
