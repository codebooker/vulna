"""Phase 37 OIDC, SAML, JIT, tenant isolation, and lockout-safety tests."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest
from app.auth.password import hash_password
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.enums import (
    AccountStatus,
    AuthenticationSource,
    IdentityProviderProtocol,
    SiteAccessMode,
    SsoPolicyMode,
    UserRole,
)
from app.models.mfa import TotpFactor
from app.models.organization import Organization
from app.models.sso import (
    ExternalIdentityLink,
    IdentityGroupMapping,
    IdentityProvider,
    SamlReplayRecord,
    SsoPolicy,
    SsoProtocolState,
)
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment
from app.services import sso
from app.services.secret_crypto import (
    SecretDecryptionError,
    SecretPurpose,
    decrypt_secret,
    encrypt_secret,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, UserFactory

pytestmark = pytest.mark.release_gate


def _b64int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _oidc_token(
    provider: IdentityProvider,
    *,
    nonce: str,
    issuer: str | None = None,
    audience: str | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks: dict[str, object] = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "phase37-test-key",
                "use": "sig",
                "alg": "RS256",
                "n": _b64int(numbers.n),
                "e": _b64int(numbers.e),
            }
        ]
    }
    now = datetime.now(UTC)
    token = pyjwt.encode(
        {
            "iss": issuer or provider.issuer,
            "aud": audience or provider.client_id,
            "sub": "subject-123",
            "email": "oidc-user@example.com",
            "email_verified": True,
            "nonce": nonce,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "amr": ["pwd", "mfa"],
        },
        key,
        algorithm="RS256",
        headers={"kid": "phase37-test-key"},
    )
    return {"id_token": token}, jwks


def _certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 37 IdP")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _idp_metadata(certificate: str) -> str:
    stripped = "".join(line for line in certificate.splitlines() if "CERTIFICATE" not in line)
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
      <ds:X509Certificate>{stripped}</ds:X509Certificate>
    </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example/sso" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


async def _provider(
    db_session: AsyncSession,
    organization: Organization,
    *,
    protocol: IdentityProviderProtocol = IdentityProviderProtocol.OIDC,
    enabled: bool = False,
) -> IdentityProvider:
    now = datetime.now(UTC)
    provider = IdentityProvider(
        organization_id=organization.id,
        name="Example IdP",
        slug=f"example-{uuid.uuid4().hex[:8]}",
        protocol=protocol,
        enabled=enabled,
        jit_provisioning=True,
        default_role=UserRole.VIEWER,
        preset="generic",
        issuer="https://issuer.example/" if protocol == IdentityProviderProtocol.OIDC else None,
        client_id="vulna-client" if protocol == IdentityProviderProtocol.OIDC else None,
        scopes_json=["openid", "email"],
        validated_at=now if enabled else None,
        last_test_succeeded_at=now if enabled else None,
    )
    db_session.add(provider)
    await db_session.commit()
    await db_session.refresh(provider)
    return provider


def test_sso_secrets_are_cryptographically_purpose_bound() -> None:
    master = "phase37-master-secret"
    value = encrypt_secret(master, SecretPurpose.OIDC_CLIENT_SECRET, "client-secret")
    assert "client-secret" not in value
    assert decrypt_secret(master, SecretPurpose.OIDC_CLIENT_SECRET, value) == "client-secret"
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(master, SecretPurpose.SAML_SP_PRIVATE_KEY, value)


async def test_provider_api_redacts_secrets_and_cannot_cross_organizations(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    created = await client.post(
        "/api/v1/identity/providers",
        headers=admin_headers,
        json={
            "name": "Company OIDC",
            "slug": "company-oidc",
            "protocol": "oidc",
            "issuer": "https://login.example/",
            "client_id": "vulna",
            "client_secret": "do-not-return-this",
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["has_client_secret"] is True
    assert "client_secret" not in body
    assert "encrypted_client_secret" not in body
    stored = await db_session.get(IdentityProvider, uuid.UUID(body["id"]))
    assert stored is not None and stored.encrypted_client_secret
    assert "do-not-return-this" not in stored.encrypted_client_secret

    foreign_org = Organization(name="Foreign", slug="foreign-sso", default_timezone="UTC")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign = IdentityProvider(
        organization_id=foreign_org.id,
        name="Foreign",
        slug="foreign",
        protocol=IdentityProviderProtocol.OIDC,
        enabled=False,
        jit_provisioning=False,
        default_role=UserRole.VIEWER,
        preset="generic",
        issuer="https://foreign.example/",
        client_id="foreign-client",
        scopes_json=["openid"],
    )
    db_session.add(foreign)
    await db_session.commit()
    denied = await client.patch(
        f"/api/v1/identity/providers/{foreign.id}",
        headers=admin_headers,
        json={"name": "Stolen"},
    )
    assert denied.status_code == 404
    await db_session.refresh(foreign)
    assert foreign.name == "Foreign"


async def test_oidc_discovery_and_authorization_use_exact_issuer_nonce_and_pkce(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = await client.post(
        "/api/v1/identity/providers",
        headers=admin_headers,
        json={
            "name": "Strict OIDC",
            "slug": "strict-oidc",
            "protocol": "oidc",
            "issuer": "https://issuer.example/",
            "client_id": "vulna-client",
            "client_secret": "test-secret",
        },
    )
    provider_id = created.json()["id"]

    async def discovery(_url: str, *, allow_private: bool) -> dict[str, object]:
        assert allow_private is False
        return {
            "issuer": "https://issuer.example/",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    monkeypatch.setattr(sso, "_fetch_json", discovery)
    validated = await client.post(
        f"/api/v1/identity/providers/{provider_id}/validate",
        headers=admin_headers,
    )
    assert validated.status_code == 200
    started = await client.post(
        f"/api/v1/identity/providers/{provider_id}/test",
        headers=admin_headers,
        json={"return_path": "/#identity"},
    )
    assert started.status_code == 200
    params = parse_qs(urlsplit(started.json()["authorization_url"]).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["state"][0]) >= 32
    assert len(params["nonce"][0]) >= 32
    state_row = await db_session.scalar(select(SsoProtocolState))
    assert state_row is not None
    assert state_row.state_hash != params["state"][0]
    assert params["nonce"][0] not in (state_row.encrypted_nonce or "")
    assert params["code_challenge"][0] not in (state_row.encrypted_pkce_verifier or "")


async def test_oidc_id_token_rejects_wrong_issuer_audience_and_nonce(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    good_tokens, jwks = _oidc_token(provider, nonce="expected")
    claims = sso.validate_oidc_id_token(provider, good_tokens, jwks, nonce="expected")
    assert claims["sub"] == "subject-123"
    assert sso.sso_has_mfa(claims) is True

    wrong_issuer, issuer_keys = _oidc_token(
        provider, nonce="expected", issuer="https://attacker.example/"
    )
    with pytest.raises(sso.SsoError):
        sso.validate_oidc_id_token(provider, wrong_issuer, issuer_keys, nonce="expected")
    wrong_audience, audience_keys = _oidc_token(
        provider, nonce="expected", audience="different-client"
    )
    with pytest.raises(sso.SsoError):
        sso.validate_oidc_id_token(provider, wrong_audience, audience_keys, nonce="expected")
    with pytest.raises(sso.SsoError):
        sso.validate_oidc_id_token(provider, good_tokens, jwks, nonce="different")


async def test_enforcement_requires_tested_provider_and_strong_mfa_break_glass(
    client: AsyncClient,
    admin: User,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    provider = await _provider(db_session, organization, enabled=True)
    denied = await client.put(
        "/api/v1/identity/policy",
        headers=admin_headers,
        json={"mode": "enforced", "identity_provider_id": str(provider.id)},
    )
    assert denied.status_code == 409
    assert "break-glass" in denied.json()["detail"]

    admin.is_break_glass = False
    admin.account_status = AccountStatus.ACTIVE
    admin.authentication_source = AuthenticationSource.LOCAL
    admin.hashed_password = hash_password(TEST_PASSWORD)
    db_session.add(
        TotpFactor(
            organization_id=organization.id,
            user_id=admin.id,
            label="Break glass",
            encrypted_secret=encrypt_secret(
                get_settings().require_secret_key(),
                SecretPurpose.TOTP_SEED,
                "JBSWY3DPEHPK3PXP",
            ),
            confirmed_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    protected = await client.put(
        f"/api/v1/identity/break-glass/{admin.id}",
        headers=admin_headers,
        json={"enabled": True},
    )
    assert protected.status_code == 200
    enabled = await client.put(
        "/api/v1/identity/policy",
        headers=admin_headers,
        json={"mode": "enforced", "identity_provider_id": str(provider.id)},
    )
    assert enabled.status_code == 200
    assert enabled.json()["enforcement_ready"] is True

    ordinary = await make_user(email="local-denied@example.com")
    local_denied = await client.post(
        "/api/v1/auth/login",
        json={"email": ordinary.email, "password": TEST_PASSWORD},
    )
    assert local_denied.status_code == 401
    assert local_denied.json()["detail"] == "Invalid email or password"

    break_glass_login = await client.post(
        "/api/v1/auth/login",
        json={"email": admin.email, "password": TEST_PASSWORD},
    )
    assert break_glass_login.status_code == 200
    assert break_glass_login.json()["mfa_required"] is True
    actions = set((await db_session.execute(select(AuditEvent.action))).scalars())
    assert "auth.login_denied_sso_enforced" in actions
    assert "auth.break_glass_login" in actions


async def test_saml_metadata_is_strict_encrypted_and_supports_certificate_rollover(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    created = await client.post(
        "/api/v1/identity/providers",
        headers=admin_headers,
        json={
            "name": "Company SAML",
            "slug": "company-saml",
            "protocol": "saml",
            "want_assertions_encrypted": True,
        },
    )
    assert created.status_code == 201
    provider_id = created.json()["id"]
    imported = await client.post(
        f"/api/v1/identity/providers/{provider_id}/saml-metadata",
        headers=admin_headers,
        json={"metadata_xml": _idp_metadata(_certificate())},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["has_idp_certificate"] is True
    assert imported.json()["has_sp_certificate"] is True
    provider = await db_session.get(IdentityProvider, uuid.UUID(provider_id))
    assert provider is not None
    next_cert = _certificate()
    rotated = await client.patch(
        f"/api/v1/identity/providers/{provider_id}",
        headers=admin_headers,
        json={"next_idp_certificate": next_cert},
    )
    assert rotated.status_code == 200
    await db_session.refresh(provider)
    config = sso.saml_settings(get_settings(), provider, base_url="https://vulna.example")
    assert config["strict"] is True
    assert config["security"]["authnRequestsSigned"] is True
    assert config["security"]["wantAssertionsSigned"] is True
    assert config["security"]["wantAssertionsEncrypted"] is True
    assert len(config["idp"]["x509certMulti"]["signing"]) == 2
    assert next_cert not in json.dumps(provider.__dict__, default=str)
    metadata = sso.sp_metadata(get_settings(), provider, base_url="https://vulna.example")
    assert "AssertionConsumerService" in metadata


async def test_saml_replay_identifiers_are_single_use(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization, protocol=IdentityProviderProtocol.SAML)
    await sso.record_saml_identifiers(db_session, provider, ["message-1", "assertion-1"])
    await db_session.flush()
    with pytest.raises(sso.SsoError):
        await sso.record_saml_identifiers(db_session, provider, ["assertion-1"])
    assert await db_session.scalar(select(func.count()).select_from(SamlReplayRecord)) == 2


async def test_jit_requires_verified_email_and_creates_stable_link(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    with pytest.raises(sso.SsoError):
        await sso.resolve_sso_user(
            db_session,
            provider,
            {"sub": "unverified", "email": "unverified@example.com"},
        )
    claims = {
        "sub": "stable-subject",
        "email": "jit@example.com",
        "email_verified": True,
        "name": "JIT User",
    }
    first = await sso.resolve_sso_user(db_session, provider, claims)
    second = await sso.resolve_sso_user(db_session, provider, claims)
    assert second.id == first.id
    assert first.authentication_source == AuthenticationSource.JIT
    assert first.hashed_password is None
    assert await db_session.scalar(select(func.count()).select_from(ExternalIdentityLink)) == 1


async def test_jit_role_downgrades_when_idp_group_is_removed(
    db_session: AsyncSession, organization: Organization, make_user: UserFactory
) -> None:
    """A JIT user promoted via an IdP group is downgraded to the provider default
    once the identity no longer matches any role-granting group."""
    provider = await _provider(db_session, organization)  # default_role=VIEWER
    await make_user(UserRole.ADMINISTRATOR)
    db_session.add(
        IdentityGroupMapping(
            organization_id=organization.id,
            identity_provider_id=provider.id,
            external_group="admins",
            role=UserRole.ADMINISTRATOR,
        )
    )
    await db_session.commit()

    base = {"sub": "person-1", "email": "person@example.com", "email_verified": True}
    promoted = await sso.resolve_sso_user(db_session, provider, {**base, "groups": ["admins"]})
    assert promoted.role == UserRole.ADMINISTRATOR

    # Same identity, no longer in the "admins" group → must fall back to default.
    demoted = await sso.resolve_sso_user(db_session, provider, {**base, "groups": []})
    assert demoted.id == promoted.id
    assert demoted.role == UserRole.VIEWER


async def test_jit_group_change_cannot_demote_the_last_active_administrator(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    db_session.add(
        IdentityGroupMapping(
            organization_id=organization.id,
            identity_provider_id=provider.id,
            external_group="admins",
            role=UserRole.ADMINISTRATOR,
        )
    )
    await db_session.commit()
    claims = {
        "sub": "only-admin",
        "email": "only-admin@example.com",
        "email_verified": True,
        "groups": ["admins"],
    }
    user = await sso.resolve_sso_user(db_session, provider, claims)
    assert user.role == UserRole.ADMINISTRATOR

    with pytest.raises(sso.SsoError, match="last active administrator"):
        await sso.resolve_sso_user(db_session, provider, {**claims, "groups": []})
    assert user.role == UserRole.ADMINISTRATOR


async def test_mapping_replacement_resets_linked_jit_role_and_site_access(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    provider = await _provider(db_session, organization)
    site = (
        await client.post(
            "/api/v1/sites",
            headers=admin_headers,
            json={"name": "Mapped", "code": "MAP"},
        )
    ).json()
    db_session.add(
        IdentityGroupMapping(
            organization_id=organization.id,
            identity_provider_id=provider.id,
            external_group="operators",
            role=UserRole.SECURITY_OPERATOR,
            site_ids_json=[site["id"]],
        )
    )
    await db_session.commit()
    user = await sso.resolve_sso_user(
        db_session,
        provider,
        {
            "sub": "mapped-user",
            "email": "mapped-user@example.com",
            "email_verified": True,
            "groups": ["operators"],
        },
    )
    before_version = user.auth_version
    assert user.role == UserRole.SECURITY_OPERATOR
    assert user.site_access_mode == SiteAccessMode.ASSIGNED

    replaced = await client.put(
        f"/api/v1/identity/providers/{provider.id}/group-mappings",
        headers=admin_headers,
        json=[],
    )

    assert replaced.status_code == 200, replaced.text
    await db_session.refresh(user)
    assert user.role == UserRole.VIEWER
    # Claims are unavailable during an administrative mapping replacement, so
    # revoke all site access until the disabled provider is re-tested and the
    # next signed login supplies the user's current groups.
    assert user.site_access_mode == SiteAccessMode.ASSIGNED
    assert user.auth_version == before_version + 1
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(UserSiteAssignment)
            .where(UserSiteAssignment.user_id == user.id)
        )
        == 0
    )


async def test_jit_default_role_fails_closed_for_legacy_privileged_provider(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    # Simulate a provider persisted before the API restricted JIT defaults.
    provider.default_role = UserRole.ADMINISTRATOR
    await db_session.commit()

    user = await sso.resolve_sso_user(
        db_session,
        provider,
        {
            "sub": "legacy-provider-user",
            "email": "legacy-provider-user@example.com",
            "email_verified": True,
        },
    )
    assert user.role == UserRole.VIEWER


async def test_provider_api_rejects_privileged_jit_default(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    response = await client.post(
        "/api/v1/identity/providers",
        headers=admin_headers,
        json={
            "name": "Unsafe defaults",
            "slug": "unsafe-defaults",
            "protocol": "oidc",
            "issuer": "https://login.example/",
            "client_id": "vulna",
            "default_role": "administrator",
        },
    )
    assert response.status_code == 422
    assert "default JIT role must be Viewer" in response.text


async def test_public_provider_listing_follows_policy_without_leaking_configuration(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    provider = await _provider(db_session, organization, enabled=True)
    db_session.add(
        SsoPolicy(
            organization_id=organization.id,
            mode=SsoPolicyMode.OPTIONAL,
            identity_provider_id=provider.id,
        )
    )
    await db_session.commit()
    listed = await client.get("/api/v1/sso/providers?organization=test-org")
    assert listed.status_code == 200
    assert listed.json() == [
        {
            "id": str(provider.id),
            "name": provider.name,
            "slug": provider.slug,
            "protocol": "oidc",
        }
    ]
    assert "issuer" not in listed.text and "client" not in listed.text


async def test_phase37_openapi_and_capability_status(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    schema = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/identity/providers",
        "/api/v1/identity/policy",
        "/api/v1/sso/providers/{provider_id}/start",
        "/api/v1/sso/oidc/{provider_id}/callback",
        "/api/v1/sso/saml/{provider_id}/acs",
        "/api/v1/sso/saml/{provider_id}/metadata",
    ):
        assert path in schema["paths"]
    capabilities = (await client.get("/api/v1/system/capabilities", headers=admin_headers)).json()
    item = next(value for value in capabilities["capabilities"] if value["key"] == "enterprise_sso")
    assert item["status"] == "available"
    assert item["production_ready"] is False


async def test_break_glass_flag_is_visible_but_never_secret(
    client: AsyncClient, admin: User, admin_headers: dict[str, str]
) -> None:
    response = await client.get("/api/v1/users", headers=admin_headers)
    assert response.status_code == 200
    record = next(item for item in response.json()["items"] if item["id"] == str(admin.id))
    assert record["is_break_glass"] is False
    assert "hashed_password" not in record


async def test_sso_state_cannot_be_reused(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    state_row, secret, _nonce, _verifier = sso.new_protocol_state(
        get_settings(),
        provider,
        protocol=IdentityProviderProtocol.OIDC,
        purpose="login",
        return_path="/#overview",
        initiated_by_user_id=None,
    )
    db_session.add(state_row)
    await db_session.commit()
    consumed = await sso.consume_protocol_state(db_session, secret, IdentityProviderProtocol.OIDC)
    assert consumed.id == state_row.id
    await db_session.commit()
    with pytest.raises(sso.SsoError):
        await sso.consume_protocol_state(db_session, secret, IdentityProviderProtocol.OIDC)


async def test_external_link_cannot_cross_organization(
    db_session: AsyncSession, organization: Organization
) -> None:
    provider = await _provider(db_session, organization)
    foreign_org = Organization(name="Other", slug="other-link", default_timezone="UTC")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_user = User(
        organization_id=foreign_org.id,
        email="foreign-link@example.com",
        hashed_password=hash_password(TEST_PASSWORD),
        role=UserRole.VIEWER,
        is_active=True,
        account_status=AccountStatus.ACTIVE,
        authentication_source=AuthenticationSource.LOCAL,
    )
    db_session.add(foreign_user)
    await db_session.flush()
    db_session.add(
        ExternalIdentityLink(
            organization_id=organization.id,
            identity_provider_id=provider.id,
            user_id=foreign_user.id,
            subject="cross-org-subject",
            email_at_link=foreign_user.email,
        )
    )
    await db_session.commit()
    with pytest.raises(sso.SsoError):
        await sso.resolve_sso_user(
            db_session,
            provider,
            {"sub": "cross-org-subject", "email_verified": True},
        )


async def test_enforced_policy_preserves_at_least_one_break_glass_user(
    client: AsyncClient,
    admin: User,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    provider = await _provider(db_session, organization, enabled=True)
    admin.is_break_glass = True
    admin.account_status = AccountStatus.ACTIVE
    admin.authentication_source = AuthenticationSource.LOCAL
    db_session.add(
        TotpFactor(
            organization_id=organization.id,
            user_id=admin.id,
            label="Protected",
            encrypted_secret=encrypt_secret(
                get_settings().require_secret_key(),
                SecretPurpose.TOTP_SEED,
                "JBSWY3DPEHPK3PXP",
            ),
            confirmed_at=datetime.now(UTC),
        )
    )
    db_session.add(
        SsoPolicy(
            organization_id=organization.id,
            mode=SsoPolicyMode.ENFORCED,
            identity_provider_id=provider.id,
        )
    )
    await db_session.commit()
    denied = await client.put(
        f"/api/v1/identity/break-glass/{admin.id}",
        headers=admin_headers,
        json={"enabled": False},
    )
    assert denied.status_code == 409
    await db_session.refresh(admin)
    assert admin.is_break_glass is True


async def test_viewer_cannot_administer_identity(
    client: AsyncClient,
    viewer_headers: dict[str, str],
) -> None:
    assert (
        await client.get("/api/v1/identity/providers", headers=viewer_headers)
    ).status_code == 403
    assert (
        await client.put(
            "/api/v1/identity/policy",
            headers=viewer_headers,
            json={"mode": "disabled"},
        )
    ).status_code == 403


def test_return_paths_cannot_redirect_off_site() -> None:
    assert sso.normalize_return_path("/#identity") == "/#identity"
    for value in ("https://attacker.example", "//attacker.example/path", "/\\attacker"):
        with pytest.raises(sso.SsoError):
            sso.normalize_return_path(value)
