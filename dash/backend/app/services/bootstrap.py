"""First-run bootstrap: seed the default organization and administrator.

Both operations are idempotent so they are safe to run on every startup and
from the ``vulna bootstrap-admin`` CLI command. Credentials are read from the
environment (never hard-coded); if no admin credentials are configured, the
admin is simply not created and a message is returned to the caller.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password import hash_password
from app.core.config import Settings
from app.models.enums import ActorType, UserRole
from app.models.organization import Organization
from app.models.user import User
from app.services.audit import record_audit


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

    # Skip if any administrator already exists.
    existing_admins = await session.scalar(
        select(func.count()).select_from(User).where(User.role == UserRole.ADMINISTRATOR)
    )
    if existing_admins:
        return None

    org = await ensure_default_organization(session, settings)

    normalized_email = email.strip().lower()
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


async def run_bootstrap(session: AsyncSession, settings: Settings) -> None:
    """Ensure the default organization and (if configured) the admin exist."""
    await ensure_default_organization(session, settings)
    await ensure_bootstrap_admin(session, settings)
