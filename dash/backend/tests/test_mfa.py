"""Phase 36 MFA, WebAuthn, throttling, and step-up acceptance tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from app.auth.password import hash_password
from app.auth.tokens import decode_access_token
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.enums import UserRole
from app.models.mfa import (
    AuthenticationThrottle,
    MfaRecoveryCode,
    TotpFactor,
    WebAuthnChallenge,
    WebAuthnCredential,
)
from app.models.organization import Organization
from app.models.session import UserSession
from app.models.user import User
from app.services import mfa as mfa_service
from app.services import webauthn as webauthn_service
from app.services.secret_crypto import (
    SecretDecryptionError,
    SecretPurpose,
    decrypt_secret,
    encrypt_secret,
)
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, UserFactory

pytestmark = pytest.mark.release_gate


async def _login(client: AsyncClient, user: User) -> dict[str, object]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


def _headers(token: object) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _enroll_totp(
    client: AsyncClient, user: User
) -> tuple[str, list[str], str, str]:
    login = await _login(client, user)
    headers = _headers(login["access_token"])
    setup = await client.post("/api/v1/mfa/totp/setup", headers=headers)
    assert setup.status_code == 200
    body = setup.json()
    secret = body["secret"]
    # Confirm with the prior time step so the current code remains valid for
    # the first full sign-in ceremony and replay protection can be asserted.
    prior_code = pyotp.TOTP(secret).at(datetime.now(UTC) - timedelta(seconds=30))
    confirm = await client.post(
        "/api/v1/mfa/totp/confirm",
        json={"factor_id": body["factor_id"], "code": prior_code},
        headers=headers,
    )
    assert confirm.status_code == 200
    result = confirm.json()
    return (
        secret,
        result["recovery_codes"]["codes"],
        body["provisioning_uri"],
        result["verification"]["access_token"],
    )


def test_totp_ciphertext_is_purpose_bound() -> None:
    master = "phase36-purpose-bound-master-key"
    plaintext = "JBSWY3DPEHPK3PXP"
    ciphertext = encrypt_secret(master, SecretPurpose.TOTP_SEED, plaintext)
    assert plaintext not in ciphertext
    assert decrypt_secret(master, SecretPurpose.TOTP_SEED, ciphertext) == plaintext
    with pytest.raises(SecretDecryptionError):
        decrypt_secret("different-key", SecretPurpose.TOTP_SEED, ciphertext)


def test_webauthn_relying_party_requires_https_and_matching_host() -> None:
    with pytest.raises(webauthn_service.WebAuthnConfigurationError):
        webauthn_service.relying_party(
            get_settings().model_copy(update={"webauthn_origin": "http://vulna.example.com"}),
            "http://vulna.example.com",
        )
    with pytest.raises(webauthn_service.WebAuthnConfigurationError):
        webauthn_service.relying_party(
            get_settings().model_copy(
                update={
                    "webauthn_origin": "https://vulna.example.com",
                    "webauthn_rp_id": "other.example.com",
                }
            ),
            "https://vulna.example.com",
        )
    valid = webauthn_service.relying_party(
        get_settings().model_copy(
            update={
                "webauthn_origin": "https://vulna.example.com",
                "webauthn_rp_id": "example.com",
            }
        ),
        "https://vulna.example.com",
    )
    assert valid.rp_id == "example.com"


async def test_totp_enrollment_sign_in_replay_and_recovery_are_safe(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="mfa@example.com")
    secret, recovery_codes, provisioning_uri, _ = await _enroll_totp(client, user)
    assert provisioning_uri.startswith("otpauth://totp/")
    assert user.email.replace("@", "%40") in provisioning_uri
    assert len(recovery_codes) == 10

    factor = await db_session.scalar(select(TotpFactor).where(TotpFactor.user_id == user.id))
    assert factor is not None
    assert factor.confirmed_at is not None
    assert secret not in factor.encrypted_secret
    recovery_rows = list(
        (
            await db_session.execute(
                select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)
            )
        ).scalars()
    )
    assert len(recovery_rows) == 10
    assert all(code not in {row.code_hash for row in recovery_rows} for code in recovery_codes)

    pending = await _login(client, user)
    assert pending["mfa_required"] is True
    assert pending["mfa_methods"] == ["totp", "recovery_code"]
    pending_headers = _headers(pending["access_token"])
    assert (await client.get("/api/v1/auth/me", headers=pending_headers)).status_code == 401

    code = pyotp.TOTP(secret).now()
    verified = await client.post(
        "/api/v1/mfa/totp/verify", json={"code": code}, headers=pending_headers
    )
    assert verified.status_code == 200
    verified_headers = _headers(verified.json()["access_token"])
    assert (await client.get("/api/v1/auth/me", headers=verified_headers)).status_code == 200

    replay_login = await _login(client, user)
    replay = await client.post(
        "/api/v1/mfa/totp/verify",
        json={"code": code},
        headers=_headers(replay_login["access_token"]),
    )
    assert replay.status_code == 401
    assert replay.json()["detail"] == "Verification failed"

    recovery_login = await _login(client, user)
    recovered = await client.post(
        "/api/v1/mfa/recovery/verify",
        json={"code": recovery_codes[0]},
        headers=_headers(recovery_login["access_token"]),
    )
    assert recovered.status_code == 200
    assert recovered.json()["recovery_codes_remaining"] == 9
    reused_login = await _login(client, user)
    reused = await client.post(
        "/api/v1/mfa/recovery/verify",
        json={"code": recovery_codes[0]},
        headers=_headers(reused_login["access_token"]),
    )
    assert reused.status_code == 401
    serialized = json.dumps(
        [factor.__dict__, *[row.__dict__ for row in recovery_rows]], default=str
    )
    assert all(code not in serialized for code in recovery_codes)

    actions = set((await db_session.execute(select(AuditEvent.action))).scalars())
    assert {"auth.mfa_totp_enrolled", "auth.mfa_succeeded"}.issubset(actions)


async def test_required_policy_grace_then_fail_closed_enrollment(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    admin = await make_user(UserRole.ADMINISTRATOR, email="mfa-policy@example.com")
    login = await _login(client, admin)
    headers = _headers(login["access_token"])
    updated = await client.patch(
        "/api/v1/mfa/policy",
        json={"mode": "required", "grace_period_days": 7},
        headers=headers,
    )
    assert updated.status_code == 200
    await db_session.refresh(admin)
    assert admin.mfa_grace_expires_at is not None
    original_grace = admin.mfa_grace_expires_at
    repeated = await client.patch(
        "/api/v1/mfa/policy",
        json={"mode": "required", "grace_period_days": 7},
        headers=headers,
    )
    assert repeated.status_code == 200
    await db_session.refresh(admin)
    assert admin.mfa_grace_expires_at == original_grace

    during_grace = await _login(client, admin)
    assert during_grace["mfa_required"] is False
    assert during_grace["mfa_enrollment_required"] is True
    admin.mfa_grace_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    legacy_codes = await mfa_service.generate_recovery_codes(db_session, admin, count=1)
    await db_session.commit()

    expired = await _login(client, admin)
    assert expired["mfa_required"] is True
    assert expired["mfa_enrollment_required"] is True
    pending_headers = _headers(expired["access_token"])
    assert (await client.get("/api/v1/auth/me", headers=pending_headers)).status_code == 401
    recovery_denied = await client.post(
        "/api/v1/mfa/recovery/verify",
        json={"code": legacy_codes[0]},
        headers=pending_headers,
    )
    assert recovery_denied.status_code == 401
    assert (await client.get("/api/v1/mfa/status", headers=pending_headers)).status_code == 200
    assert (await client.post("/api/v1/mfa/totp/setup", headers=pending_headers)).status_code == 200


async def test_login_throttle_is_durable_hashed_and_generic(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="throttle@example.com")
    for _ in range(5):
        failure = await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": "not-the-password"},
        )
        assert failure.status_code == 401
        assert failure.json()["detail"] == "Invalid email or password"
    blocked = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": TEST_PASSWORD},
    )
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Invalid email or password"
    assert int(blocked.headers["retry-after"]) > 0

    rows = list((await db_session.execute(select(AuthenticationThrottle))).scalars())
    assert {row.key_type for row in rows} == {"account", "ip"}
    assert all(len(row.key_hash) == 64 for row in rows)
    assert user.email not in json.dumps([row.__dict__ for row in rows], default=str)


async def test_step_up_rejects_stale_session(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    admin = await make_user(UserRole.ADMINISTRATOR, email="stale-step-up@example.com")
    login = await _login(client, admin)
    claims = decode_access_token(get_settings(), str(login["access_token"]))
    stored = await db_session.get(UserSession, uuid.UUID(str(claims["sid"])))
    assert stored is not None
    stored.authenticated_at = datetime.now(UTC) - timedelta(minutes=16)
    await db_session.commit()
    denied = await client.patch(
        "/api/v1/mfa/policy",
        json={"mode": "optional"},
        headers=_headers(login["access_token"]),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "step_up_required"


async def test_webauthn_challenge_is_short_lived_owned_and_single_use(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    owner = await make_user(email="key-owner@example.com")
    owner_login = await _login(client, owner)
    options = await client.post(
        "/api/v1/mfa/webauthn/register/options",
        headers=_headers(owner_login["access_token"]),
    )
    assert options.status_code == 200
    body = options.json()
    assert body["public_key"]["rp"]["id"] == "localhost"
    assert body["public_key"]["authenticatorSelection"]["userVerification"] == "required"
    challenge = await db_session.get(WebAuthnChallenge, uuid.UUID(body["challenge_id"]))
    assert challenge is not None
    expires = (
        challenge.expires_at.replace(tzinfo=UTC)
        if challenge.expires_at.tzinfo is None
        else challenge.expires_at
    )
    created = (
        challenge.created_at.replace(tzinfo=UTC)
        if challenge.created_at.tzinfo is None
        else challenge.created_at
    )
    assert timedelta(minutes=4, seconds=55) <= expires - created <= timedelta(minutes=5, seconds=5)

    intruder = await make_user(email="key-intruder@example.com")
    intruder_login = await _login(client, intruder)
    intruder_claims = decode_access_token(get_settings(), str(intruder_login["access_token"]))
    intruder_session = await db_session.get(
        UserSession, uuid.UUID(str(intruder_claims["sid"]))
    )
    owner_claims = decode_access_token(get_settings(), str(owner_login["access_token"]))
    owner_session = await db_session.get(UserSession, uuid.UUID(str(owner_claims["sid"])))
    assert intruder_session is not None and owner_session is not None
    with pytest.raises(ValueError):
        await webauthn_service.consume_challenge(
            db_session, challenge.id, intruder, intruder_session, "registration"
        )
    consumed = await webauthn_service.consume_challenge(
        db_session, challenge.id, owner, owner_session, "registration"
    )
    assert consumed.consumed_at is not None
    with pytest.raises(ValueError):
        await webauthn_service.consume_challenge(
            db_session, challenge.id, owner, owner_session, "registration"
        )


async def test_mfa_credentials_cannot_cross_organizations(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    admin = await make_user(UserRole.ADMINISTRATOR, email="mfa-admin@example.com")
    login = await _login(client, admin)
    foreign_org = Organization(name="Foreign", slug="foreign-mfa", default_timezone="UTC")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_user = User(
        organization_id=foreign_org.id,
        email="foreign-mfa@example.com",
        hashed_password=hash_password(TEST_PASSWORD),
        full_name="Foreign User",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )
    db_session.add(foreign_user)
    await db_session.flush()
    foreign_credential = WebAuthnCredential(
        organization_id=foreign_org.id,
        user_id=foreign_user.id,
        credential_id="foreign-credential",
        credential_public_key=b"foreign-public-key",
        sign_count=0,
        label="Foreign key",
        transports_json=["usb"],
        device_type="single_device",
        backed_up=False,
    )
    db_session.add(foreign_credential)
    await db_session.commit()

    headers = _headers(login["access_token"])
    listed = await client.get("/api/v1/mfa/webauthn/credentials", headers=headers)
    assert listed.status_code == 200
    assert all(row["id"] != str(foreign_credential.id) for row in listed.json())
    denied = await client.delete(
        f"/api/v1/mfa/webauthn/credentials/{foreign_credential.id}", headers=headers
    )
    assert denied.status_code == 404
    await db_session.refresh(foreign_credential)
    assert foreign_credential.disabled_at is None


async def test_required_user_cannot_remove_the_last_strong_factor(
    client: AsyncClient,
    make_user: UserFactory,
) -> None:
    admin = await make_user(UserRole.ADMINISTRATOR, email="last-factor@example.com")
    _, _, _, access = await _enroll_totp(client, admin)
    headers = _headers(access)
    required = await client.patch(
        "/api/v1/mfa/policy", json={"mode": "required"}, headers=headers
    )
    assert required.status_code == 200
    denied = await client.delete("/api/v1/mfa/totp", headers=headers)
    assert denied.status_code == 409
    assert "another strong factor" in denied.json()["detail"]


async def test_phase36_interfaces_are_in_openapi(client: AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    for path in (
        "/api/v1/mfa/status",
        "/api/v1/mfa/totp/setup",
        "/api/v1/mfa/totp/confirm",
        "/api/v1/mfa/totp/verify",
        "/api/v1/mfa/recovery/verify",
        "/api/v1/mfa/webauthn/register/options",
        "/api/v1/mfa/webauthn/register/verify",
        "/api/v1/mfa/webauthn/authenticate/options",
        "/api/v1/mfa/webauthn/authenticate/verify",
        "/api/v1/mfa/policy",
    ):
        assert path in paths
