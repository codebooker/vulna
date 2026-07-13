"""First-run bootstrap: seed the default organization and administrator.

Both operations are idempotent so they are safe to run on every startup and
from the ``vulna bootstrap-admin`` CLI command. Credentials are read from the
environment (never hard-coded); if no admin credentials are configured, the
admin is simply not created and a message is returned to the caller.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password import hash_password
from app.core.config import Settings
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import ActorType, ExperienceProfile, UserRole
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.site import Site
from app.models.user import User
from app.services.audit import record_audit
from app.services.ca import get_ca
from app.services.enrollment import generate_token

# The login schema validates credentials with pydantic's EmailStr, which rejects
# special-use / reserved domains (e.g. .test, .local, .example). Seed the admin
# with the SAME validator so a configured address that cannot be used to log in
# is caught up front with a clear error, instead of silently creating an
# administrator that can never authenticate.
_EMAIL_ADAPTER: TypeAdapter[str] = TypeAdapter(EmailStr)


class BootstrapError(RuntimeError):
    """Raised when bootstrap configuration is invalid and must be corrected."""


def _validate_admin_email(email: str) -> str:
    try:
        return _EMAIL_ADAPTER.validate_python(email.strip())
    except ValidationError as exc:
        reason = exc.errors()[0].get("msg", "invalid email address")
        raise BootstrapError(
            f"VULNA_ADMIN_EMAIL '{email}' cannot be used to log in: {reason}. "
            "Use a real, routable email address (reserved domains such as .test, "
            ".local, and .example are rejected by login)."
        ) from exc


async def ensure_default_organization(session: AsyncSession, settings: Settings) -> Organization:
    """Return the default organization, creating it if it does not exist."""
    result = await session.execute(
        select(Organization).where(Organization.slug == settings.default_org_slug)
    )
    org = result.scalar_one_or_none()
    if org is not None:
        return org

    org = Organization(
        name=settings.default_org_name,
        slug=settings.default_org_slug,
        default_timezone="UTC",
        experience_profile=ExperienceProfile(settings.deployment_profile),
    )
    session.add(org)
    await session.flush()
    record_audit(
        session,
        action="organization.created",
        actor_type=ActorType.SYSTEM,
        organization_id=org.id,
        target_type="organization",
        target_id=org.id,
        metadata={"reason": "bootstrap", "slug": org.slug},
    )
    return org


async def ensure_bootstrap_admin(session: AsyncSession, settings: Settings) -> User | None:
    """Create the first administrator from configured credentials, if needed.

    Returns the created user, or ``None`` when creation was skipped (either an
    administrator already exists or no bootstrap credentials were configured).
    """
    email = settings.bootstrap_admin_email
    password = settings.bootstrap_admin_password
    if not email or not password:
        return None

    # Validate before doing any work so a bad address fails fast with a clear
    # message rather than seeding an administrator that login will reject.
    validated_email = _validate_admin_email(email)

    # Skip if any administrator already exists.
    existing_admins = await session.scalar(
        select(func.count()).select_from(User).where(User.role == UserRole.ADMINISTRATOR)
    )
    if existing_admins:
        return None

    org = await ensure_default_organization(session, settings)

    normalized_email = validated_email.strip().lower()
    admin = User(
        organization_id=org.id,
        email=normalized_email,
        hashed_password=hash_password(password),
        full_name="Administrator",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )
    session.add(admin)
    await session.flush()
    record_audit(
        session,
        action="user.bootstrap_admin_created",
        actor_type=ActorType.SYSTEM,
        organization_id=org.id,
        target_type="user",
        target_id=admin.id,
        metadata={"email": normalized_email, "role": UserRole.ADMINISTRATOR.value},
    )
    return admin


async def ensure_default_site(session: AsyncSession, org: Organization, settings: Settings) -> Site:
    """Return the organization's default site, creating it if none exists."""
    result = await session.execute(
        select(Site).where(Site.organization_id == org.id, Site.code == settings.default_site_code)
    )
    site = result.scalar_one_or_none()
    if site is not None:
        return site
    site = Site(
        organization_id=org.id,
        name=settings.default_site_name,
        code=settings.default_site_code,
        timezone="UTC",
    )
    session.add(site)
    await session.flush()
    record_audit(
        session,
        action="site.created",
        actor_type=ActorType.SYSTEM,
        organization_id=org.id,
        target_type="site",
        target_id=site.id,
        metadata={"reason": "single_host_bootstrap", "code": site.code},
    )
    return site


async def ensure_local_scout_enrollment(session: AsyncSession, settings: Settings) -> None:
    """For the single-host profile, ensure a default site and a valid one-time
    auto-approve enrollment token for the co-located local Scout.

    The token secret is written to ``bootstrap_dir/local-scout-enroll.token``
    (0600) for the Scout container to consume — never returned via the API or the
    browser. Idempotent: does nothing once the local Scout is enrolled, and it
    re-mints only when there is no valid unused token.
    """
    if not settings.bootstrap_local_scout:
        return

    # Materialize the internal CA now so the co-located reverse proxy can load it
    # into its mTLS trust pool at startup (otherwise the CA is created lazily on
    # first enrollment, after the proxy has already tried to read it).
    get_ca(settings)

    org = await ensure_default_organization(session, settings)
    site = await ensure_default_site(session, org, settings)

    # Already enrolled? Nothing to do.
    enrolled = await session.scalar(
        select(func.count())
        .select_from(Probe)
        .where(Probe.organization_id == org.id, Probe.name == settings.local_scout_name)
    )
    if enrolled:
        return

    now = datetime.now(UTC)
    # Reuse a still-valid, unused token if one exists.
    existing = await session.scalar(
        select(EnrollmentToken).where(
            EnrollmentToken.site_id == site.id,
            EnrollmentToken.probe_name == settings.local_scout_name,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
    )
    if existing is not None:
        return

    generated = generate_token()
    token = EnrollmentToken(
        organization_id=org.id,
        site_id=site.id,
        token_hash=generated.token_hash,
        short_code=generated.short_code,
        probe_name=settings.local_scout_name,
        description="Co-located local Scout (single-host deployment).",
        auto_approve=True,
        expires_at=now + timedelta(minutes=settings.local_scout_token_ttl_minutes),
    )
    session.add(token)
    await session.flush()

    # Hand the secret to the local Scout via a 0600 file on the shared volume.
    os.makedirs(settings.bootstrap_dir, exist_ok=True)
    token_path = os.path.join(settings.bootstrap_dir, "local-scout-enroll.token")
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(generated.secret)

    record_audit(
        session,
        action="probe.local_scout_token_minted",
        actor_type=ActorType.SYSTEM,
        organization_id=org.id,
        target_type="enrollment_token",
        target_id=token.id,
        metadata={"site_id": str(site.id), "short_code": generated.short_code},
    )


async def run_bootstrap(session: AsyncSession, settings: Settings) -> None:
    """Ensure the default org, admin, and (single-host) local Scout enrollment."""
    await ensure_default_organization(session, settings)
    await ensure_bootstrap_admin(session, settings)
    await ensure_local_scout_enrollment(session, settings)
