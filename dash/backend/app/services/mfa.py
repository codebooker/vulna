"""TOTP, recovery-code, MFA policy, and session-strength services."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import cast

import pyotp
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password import hash_password, verify_password
from app.core.config import Settings
from app.models.mfa import MfaPolicy, MfaRecoveryCode, TotpFactor, WebAuthnCredential
from app.models.organization import Organization
from app.models.session import UserSession
from app.models.user import User
from app.services import notifications as notification_core
from app.services import notify
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret
from app.services.sessions import revoke_user_sessions

RECOVERY_CODE_COUNT = 10


@dataclass(frozen=True)
class Policy:
    mode: str = "optional"
    required_roles: tuple[str, ...] = ()
    grace_period_days: int = 7


async def get_policy(session: AsyncSession, organization_id: uuid.UUID) -> MfaPolicy:
    row = await session.scalar(
        select(MfaPolicy).where(MfaPolicy.organization_id == organization_id)
    )
    if row is None:
        row = MfaPolicy(
            organization_id=organization_id,
            mode="optional",
            required_roles_json=[],
            grace_period_days=7,
        )
        session.add(row)
        await session.flush()
    return row


def policy_value(row: MfaPolicy) -> Policy:
    return Policy(
        mode=row.mode,
        required_roles=tuple(row.required_roles_json or []),
        grace_period_days=row.grace_period_days,
    )


def policy_dict(row: MfaPolicy) -> dict[str, object]:
    return asdict(policy_value(row))


def required_for_user(policy: MfaPolicy, user: User) -> bool:
    if policy.mode != "required":
        return False
    roles = set(policy.required_roles_json or [])
    return not roles or user.role.value in roles


async def active_totp(session: AsyncSession, user: User) -> TotpFactor | None:
    return cast(
        TotpFactor | None,
        await session.scalar(
            select(TotpFactor).where(
                TotpFactor.user_id == user.id,
                TotpFactor.organization_id == user.organization_id,
                TotpFactor.confirmed_at.is_not(None),
                TotpFactor.disabled_at.is_(None),
            )
        )
    )


async def active_webauthn(
    session: AsyncSession, user: User
) -> list[WebAuthnCredential]:
    return list(
        (
            await session.execute(
                select(WebAuthnCredential).where(
                    WebAuthnCredential.user_id == user.id,
                    WebAuthnCredential.organization_id == user.organization_id,
                    WebAuthnCredential.disabled_at.is_(None),
                )
            )
        ).scalars()
    )


async def recovery_count(session: AsyncSession, user: User) -> int:
    count = await session.scalar(
        select(func.count())
        .select_from(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.organization_id == user.organization_id,
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    return count or 0


async def methods(session: AsyncSession, user: User) -> list[str]:
    values: list[str] = []
    if await active_totp(session, user):
        values.append("totp")
    if await active_webauthn(session, user):
        values.append("webauthn")
    if await recovery_count(session, user):
        values.append("recovery_code")
    return values


def _new_recovery_code() -> str:
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)
    )


async def generate_recovery_codes(
    session: AsyncSession, user: User, count: int = RECOVERY_CODE_COUNT
) -> list[str]:
    await session.execute(
        update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.organization_id == user.organization_id,
            MfaRecoveryCode.used_at.is_(None),
        )
        .values(used_at=datetime.now(UTC))
    )
    codes = [_new_recovery_code() for _ in range(count)]
    session.add_all(
        [
            MfaRecoveryCode(
                organization_id=user.organization_id,
                user_id=user.id,
                code_hash=hash_password(code),
            )
            for code in codes
        ]
    )
    user.recovery_codes_json = []
    user.recovery_codes_generated_at = datetime.now(UTC)
    await session.flush()
    return codes


async def consume_recovery_code(
    session: AsyncSession, user: User, code: str
) -> bool:
    rows = list(
        (
            await session.execute(
                select(MfaRecoveryCode).where(
                    MfaRecoveryCode.user_id == user.id,
                    MfaRecoveryCode.organization_id == user.organization_id,
                    MfaRecoveryCode.used_at.is_(None),
                )
            )
        ).scalars()
    )
    normalized = code.strip().lower()
    for row in rows:
        if verify_password(normalized, row.code_hash):
            row.used_at = datetime.now(UTC)
            await session.flush()
            return True
    return False


async def begin_totp(
    session: AsyncSession, settings: Settings, user: User, organization: Organization
) -> tuple[TotpFactor, str, str]:
    pending = list(
        (
            await session.execute(
                select(TotpFactor).where(
                    TotpFactor.user_id == user.id,
                    TotpFactor.organization_id == user.organization_id,
                    TotpFactor.confirmed_at.is_(None),
                )
            )
        ).scalars()
    )
    for old in pending:
        await session.delete(old)
    secret = pyotp.random_base32()
    factor = TotpFactor(
        organization_id=user.organization_id,
        user_id=user.id,
        label="Authenticator app",
        encrypted_secret=encrypt_secret(
            settings.require_secret_key(), SecretPurpose.TOTP_SEED, secret
        ),
    )
    session.add(factor)
    await session.flush()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name=organization.name,
    )
    return factor, secret, uri


def _matching_totp_timecode(secret: str, code: str, now: datetime) -> int | None:
    totp = pyotp.TOTP(secret)
    current = totp.timecode(now)
    normalized = code.strip().replace(" ", "")
    for offset in (-1, 0, 1):
        if pyotp.utils.strings_equal(totp.at(now, counter_offset=offset), normalized):
            return current + offset
    return None


def verify_totp(
    settings: Settings, factor: TotpFactor, code: str, *, now: datetime | None = None
) -> bool:
    now = now or datetime.now(UTC)
    secret = decrypt_secret(
        settings.require_secret_key(), SecretPurpose.TOTP_SEED, factor.encrypted_secret
    )
    matched = _matching_totp_timecode(secret, code, now)
    if matched is None or (
        factor.last_used_timecode is not None and matched <= factor.last_used_timecode
    ):
        return False
    factor.last_used_timecode = matched
    return True


async def complete_session_mfa(
    session: AsyncSession,
    user_session: UserSession,
    method: str,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    user_session.mfa_pending = False
    user_session.mfa_authenticated_at = now
    current = list(user_session.authentication_methods_json or ["password"])
    if method not in current:
        current.append(method)
    user_session.authentication_methods_json = current
    await session.flush()


async def revoke_other_sessions_for_mfa_change(
    session: AsyncSession, user: User, current_session: UserSession
) -> int:
    return await revoke_user_sessions(
        session,
        user.id,
        reason="MFA configuration changed",
        exclude_session_id=current_session.id,
    )


async def emit_security_notification(
    session: AsyncSession,
    user: User,
    *,
    title: str,
    summary: str,
    severity: str = "warning",
) -> None:
    try:
        await notify.emit_event(
            session,
            user.organization_id,
            notification_core.NotificationEvent(
                type=notification_core.EventType.SECURITY_ALERT,
                title=title,
                summary=summary,
                severity=severity,
                object_type="user",
                object_id=str(user.id),
            ),
        )
    except Exception:  # noqa: BLE001 - security events never break authentication
        return
