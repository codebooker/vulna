"""Verified WebAuthn registration/authentication ceremony helpers."""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from app.core.config import Settings
from app.models.mfa import WebAuthnChallenge, WebAuthnCredential
from app.models.session import UserSession
from app.models.user import User

CHALLENGE_LIFETIME = timedelta(minutes=5)


class WebAuthnConfigurationError(ValueError):
    """Raised when the relying-party origin cannot be configured safely."""


@dataclass(frozen=True)
class RelyingParty:
    rp_id: str
    rp_name: str
    origin: str


def relying_party(settings: Settings, request_origin: str) -> RelyingParty:
    origin = (settings.webauthn_origin or settings.public_base_url or request_origin).rstrip("/")
    parts = urlsplit(origin)
    hostname = parts.hostname
    if not hostname or parts.scheme not in {"http", "https"}:
        raise WebAuthnConfigurationError("WebAuthn needs a valid configured public origin")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise WebAuthnConfigurationError(
            "WebAuthn origin cannot contain a path, query, or fragment"
        )
    local = hostname in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme != "https" and not local:
        raise WebAuthnConfigurationError("WebAuthn requires HTTPS except on localhost")
    rp_id = (settings.webauthn_rp_id or hostname).lower().rstrip(".")
    normalized_host = hostname.lower().rstrip(".")
    if normalized_host != rp_id and not normalized_host.endswith(f".{rp_id}"):
        raise WebAuthnConfigurationError(
            "WebAuthn RP ID must be the public hostname or its parent domain"
        )
    return RelyingParty(
        rp_id=rp_id,
        rp_name=settings.webauthn_rp_name,
        origin=origin,
    )


def credential_id(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _transports(values: list[str]) -> list[AuthenticatorTransport]:
    result: list[AuthenticatorTransport] = []
    for value in values:
        try:
            result.append(AuthenticatorTransport(value))
        except ValueError:
            continue
    return result


async def _new_challenge(
    session: AsyncSession,
    user: User,
    user_session: UserSession,
    purpose: str,
    challenge: bytes,
) -> WebAuthnChallenge:
    now = datetime.now(UTC)
    existing = list(
        (
            await session.execute(
                select(WebAuthnChallenge).where(
                    WebAuthnChallenge.user_id == user.id,
                    WebAuthnChallenge.organization_id == user.organization_id,
                    WebAuthnChallenge.session_id == user_session.id,
                    WebAuthnChallenge.purpose == purpose,
                    WebAuthnChallenge.consumed_at.is_(None),
                )
            )
        ).scalars()
    )
    for row in existing:
        row.consumed_at = now
    value = WebAuthnChallenge(
        organization_id=user.organization_id,
        user_id=user.id,
        session_id=user_session.id,
        purpose=purpose,
        challenge=challenge,
        expires_at=now + CHALLENGE_LIFETIME,
    )
    session.add(value)
    await session.flush()
    return value


async def registration_options(
    session: AsyncSession,
    user: User,
    user_session: UserSession,
    rp: RelyingParty,
) -> tuple[WebAuthnChallenge, dict[str, object]]:
    credentials = list(
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
    challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=rp.rp_id,
        rp_name=rp.rp_name,
        user_id=user.id.bytes,
        user_name=user.email,
        user_display_name=user.full_name or user.email,
        challenge=challenge,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64.urlsafe_b64decode(
                    credential.credential_id
                    + "=" * (-len(credential.credential_id) % 4)
                ),
                transports=_transports(credential.transports_json),
            )
            for credential in credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    stored = await _new_challenge(session, user, user_session, "registration", challenge)
    return stored, json.loads(options_to_json(options))


async def authentication_options(
    session: AsyncSession,
    user: User,
    user_session: UserSession,
    rp: RelyingParty,
) -> tuple[WebAuthnChallenge, dict[str, object]]:
    credentials = list(
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
    if not credentials:
        raise ValueError("No WebAuthn credential is enrolled")
    challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=rp.rp_id,
        challenge=challenge,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64.urlsafe_b64decode(
                    credential.credential_id
                    + "=" * (-len(credential.credential_id) % 4)
                ),
                transports=_transports(credential.transports_json),
            )
            for credential in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    stored = await _new_challenge(session, user, user_session, "authentication", challenge)
    return stored, json.loads(options_to_json(options))


async def consume_challenge(
    session: AsyncSession,
    challenge_id: uuid.UUID,
    user: User,
    user_session: UserSession,
    purpose: str,
) -> WebAuthnChallenge:
    row = await session.scalar(
        select(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.id == challenge_id,
            WebAuthnChallenge.organization_id == user.organization_id,
            WebAuthnChallenge.user_id == user.id,
            WebAuthnChallenge.session_id == user_session.id,
            WebAuthnChallenge.purpose == purpose,
        )
        .with_for_update()
    )
    now = datetime.now(UTC)
    if (
        row is None
        or row.consumed_at is not None
        or (row.expires_at.replace(tzinfo=UTC) if row.expires_at.tzinfo is None else row.expires_at)
        <= now
    ):
        raise ValueError("WebAuthn challenge is invalid, expired, or already used")
    row.consumed_at = now
    await session.flush()
    return row


def verify_registration(
    credential: dict[str, object], challenge: WebAuthnChallenge, rp: RelyingParty
) -> VerifiedRegistration:
    return verify_registration_response(
        credential=credential,
        expected_challenge=challenge.challenge,
        expected_rp_id=rp.rp_id,
        expected_origin=rp.origin,
        require_user_verification=True,
    )


def verify_authentication(
    credential_payload: dict[str, object],
    challenge: WebAuthnChallenge,
    credential: WebAuthnCredential,
    rp: RelyingParty,
) -> VerifiedAuthentication:
    return verify_authentication_response(
        credential=credential_payload,
        expected_challenge=challenge.challenge,
        expected_rp_id=rp.rp_id,
        expected_origin=rp.origin,
        credential_public_key=credential.credential_public_key,
        credential_current_sign_count=credential.sign_count,
        require_user_verification=True,
    )
