"""Strict OIDC/SAML flows, JIT linking, and SSO enforcement safeguards."""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client  # type: ignore[import-untyped]
from authlib.jose import JoseError, jwt  # type: ignore[import-untyped]
from authlib.oidc.core import CodeIDToken  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from defusedxml.ElementTree import fromstring as safe_xml_fromstring
from joserfc.errors import JoseError as JoseRFCError
from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import-untyped]
from onelogin.saml2.idp_metadata_parser import (  # type: ignore[import-untyped]
    OneLogin_Saml2_IdPMetadataParser,
)
from onelogin.saml2.settings import OneLogin_Saml2_Settings  # type: ignore[import-untyped]
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import (
    AccountStatus,
    AuthenticationSource,
    IdentityProviderProtocol,
    SiteAccessMode,
    SsoPolicyMode,
    UserRole,
)
from app.models.mfa import TotpFactor, WebAuthnCredential
from app.models.sso import (
    ExternalIdentityLink,
    IdentityGroupMapping,
    IdentityProvider,
    IdentityProviderTest,
    SamlReplayRecord,
    SsoPolicy,
    SsoProtocolState,
)
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment
from app.services import authorization, notifications
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret

OIDC_PRESET_SCOPES: dict[str, list[str]] = {
    "generic": ["openid", "profile", "email", "groups"],
    "entra": ["openid", "profile", "email"],
    "google": ["openid", "profile", "email"],
    "okta": ["openid", "profile", "email", "groups"],
    "keycloak": ["openid", "profile", "email", "groups"],
}
_MFA_AMR = {"mfa", "otp", "hwk", "swk", "fido", "webauthn"}


class SsoError(ValueError):
    """A safe-to-return SSO configuration or protocol failure."""


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def hash_protocol_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_return_path(value: str) -> str:
    value = value.strip() or "/"
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        raise SsoError("return_path must be a local application path")
    return value


def public_base_url(settings: Settings, request_base_url: str) -> str:
    base = (
        settings.sso_public_base_url or settings.public_base_url or request_base_url
    ).rstrip("/")
    parts = urlsplit(base)
    if not parts.hostname or parts.scheme not in {"http", "https"}:
        raise SsoError("The SSO public base URL is invalid")
    if settings.env == "production" and parts.scheme != "https":
        raise SsoError("Production SSO requires an HTTPS public base URL")
    return base


async def get_policy(session: AsyncSession, organization_id: uuid.UUID) -> SsoPolicy:
    policy = await session.scalar(
        select(SsoPolicy).where(SsoPolicy.organization_id == organization_id)
    )
    if policy is None:
        policy = SsoPolicy(
            organization_id=organization_id,
            mode=SsoPolicyMode.DISABLED,
        )
        session.add(policy)
        await session.flush()
    return policy


async def active_break_glass_users(
    session: AsyncSession, organization_id: uuid.UUID
) -> list[User]:
    """Return active local administrators that have a usable strong factor."""
    candidates = list(
        (
            await session.execute(
                select(User).where(
                    User.organization_id == organization_id,
                    User.is_break_glass.is_(True),
                    User.role == UserRole.ADMINISTRATOR,
                    User.account_status == AccountStatus.ACTIVE,
                    User.is_active.is_(True),
                    User.authentication_source == AuthenticationSource.LOCAL,
                    User.hashed_password.is_not(None),
                )
            )
        ).scalars()
    )
    if not candidates:
        return []
    ids = [user.id for user in candidates]
    totp_ids = set(
        (
            await session.execute(
                select(TotpFactor.user_id).where(
                    TotpFactor.user_id.in_(ids),
                    TotpFactor.confirmed_at.is_not(None),
                    TotpFactor.disabled_at.is_(None),
                )
            )
        ).scalars()
    )
    webauthn_ids = set(
        (
            await session.execute(
                select(WebAuthnCredential.user_id).where(
                    WebAuthnCredential.user_id.in_(ids),
                    WebAuthnCredential.disabled_at.is_(None),
                )
            )
        ).scalars()
    )
    strong_ids = totp_ids | webauthn_ids
    return [user for user in candidates if user.id in strong_ids]


async def enforcement_readiness(
    session: AsyncSession,
    organization_id: uuid.UUID,
    provider_id: uuid.UUID | None,
) -> tuple[bool, list[str], IdentityProvider | None]:
    reasons: list[str] = []
    provider = None
    if provider_id is None:
        reasons.append("Select an identity provider")
    else:
        provider = await session.scalar(
            select(IdentityProvider).where(
                IdentityProvider.id == provider_id,
                IdentityProvider.organization_id == organization_id,
            )
        )
        if provider is None:
            reasons.append("Identity provider was not found")
        else:
            if provider.validated_at is None:
                reasons.append("Validate provider discovery or metadata")
            if provider.last_test_succeeded_at is None:
                reasons.append("Complete a successful administrator test login")
            if not provider.enabled:
                reasons.append("Enable the identity provider")
    if not await active_break_glass_users(session, organization_id):
        reasons.append("Configure an active local administrator with strong MFA as break-glass")
    return not reasons, reasons, provider


async def local_login_permitted(session: AsyncSession, user: User) -> bool:
    policy = await get_policy(session, user.organization_id)
    if policy.mode != SsoPolicyMode.ENFORCED:
        return True
    if not user.is_break_glass:
        return False
    active = await active_break_glass_users(session, user.organization_id)
    return any(item.id == user.id for item in active)


async def ensure_break_glass_eligibility_can_be_removed(
    session: AsyncSession, user: User
) -> None:
    """Reject changes that would strand an enforced organization without recovery."""
    if not user.is_break_glass:
        return
    policy = await get_policy(session, user.organization_id)
    if policy.mode != SsoPolicyMode.ENFORCED:
        return
    remaining = [
        candidate
        for candidate in await active_break_glass_users(session, user.organization_id)
        if candidate.id != user.id
    ]
    if not remaining:
        raise SsoError(
            "SSO enforcement requires another active local administrator with strong MFA "
            "before this break-glass safeguard can be removed"
        )


def provider_scopes(provider: IdentityProvider) -> list[str]:
    scopes = [str(value).strip() for value in (provider.scopes_json or []) if str(value).strip()]
    if not scopes:
        scopes = OIDC_PRESET_SCOPES.get(provider.preset, OIDC_PRESET_SCOPES["generic"])
    if "openid" not in scopes:
        scopes.insert(0, "openid")
    return list(dict.fromkeys(scopes))


def _pin_destination(url: str, *, allow_private: bool) -> tuple[str, str, str]:
    try:
        host, ip = notifications.resolve_validated(url, allow_private=allow_private)
    except notifications.NotificationError as exc:
        raise SsoError(str(exc).replace("Webhook", "Identity provider")) from exc
    return host, ip, notifications.pin_url_to_ip(url, ip)


async def _fetch_json(url: str, *, allow_private: bool) -> dict[str, Any]:
    host, _ip, pinned = _pin_destination(url, allow_private=allow_private)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.get(
            pinned,
            headers={"Host": host, "Accept": "application/json"},
            extensions={"sni_hostname": host},
        )
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise SsoError("Identity provider returned an invalid JSON document")
    return cast(dict[str, Any], data)


def _require_https_url(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise SsoError(f"OIDC discovery is missing {field}")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise SsoError(f"OIDC {field} must be an absolute HTTPS URL")
    return value


async def validate_oidc_discovery(provider: IdentityProvider) -> dict[str, Any]:
    if provider.protocol != IdentityProviderProtocol.OIDC or not provider.issuer:
        raise SsoError("This provider is not configured for OIDC")
    discovery_url = provider.discovery_url or (
        f"{provider.issuer.rstrip('/')}/.well-known/openid-configuration"
    )
    metadata = await _fetch_json(discovery_url, allow_private=provider.allow_private_network)
    if metadata.get("issuer") != provider.issuer:
        raise SsoError("OIDC discovery issuer does not exactly match the configured issuer")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _require_https_url(metadata.get(field), field)
    algorithms = metadata.get("id_token_signing_alg_values_supported") or []
    if algorithms and (not isinstance(algorithms, list) or set(algorithms) <= {"none"}):
        raise SsoError("OIDC provider does not advertise a signed ID-token algorithm")
    methods = metadata.get("code_challenge_methods_supported") or []
    if methods and "S256" not in methods:
        raise SsoError("OIDC provider does not support PKCE S256")
    provider.discovery_url = discovery_url
    provider.oidc_metadata_json = metadata
    provider.validated_at = utcnow()
    return metadata


def new_protocol_state(
    settings: Settings,
    provider: IdentityProvider,
    *,
    protocol: IdentityProviderProtocol,
    purpose: str,
    return_path: str,
    initiated_by_user_id: uuid.UUID | None,
) -> tuple[SsoProtocolState, str, str | None, str | None]:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32) if protocol == IdentityProviderProtocol.OIDC else None
    verifier = secrets.token_urlsafe(64) if protocol == IdentityProviderProtocol.OIDC else None
    secret = settings.require_secret_key()
    row = SsoProtocolState(
        organization_id=provider.organization_id,
        identity_provider_id=provider.id,
        state_hash=hash_protocol_value(state),
        protocol=protocol,
        purpose=purpose,
        encrypted_nonce=(
            encrypt_secret(secret, SecretPurpose.OIDC_FLOW_SECRET, nonce) if nonce else None
        ),
        encrypted_pkce_verifier=(
            encrypt_secret(secret, SecretPurpose.OIDC_FLOW_SECRET, verifier)
            if verifier
            else None
        ),
        return_path=normalize_return_path(return_path),
        initiated_by_user_id=initiated_by_user_id,
        expires_at=utcnow() + timedelta(minutes=settings.sso_state_ttl_minutes),
    )
    return row, state, nonce, verifier


def oidc_authorization_url(
    provider: IdentityProvider,
    metadata: dict[str, Any],
    *,
    redirect_uri: str,
    state: str,
    nonce: str,
    verifier: str,
) -> str:
    endpoint = str(metadata["authorization_endpoint"])
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    client = AsyncOAuth2Client(
        client_id=provider.client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(provider_scopes(provider)),
    )
    url, _ = client.create_authorization_url(
        endpoint,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
        code_challenge_method="S256",
        response_type="code",
    )
    return str(url)


async def consume_protocol_state(
    session: AsyncSession,
    state: str,
    protocol: IdentityProviderProtocol,
) -> SsoProtocolState:
    row = await session.scalar(
        select(SsoProtocolState)
        .where(SsoProtocolState.state_hash == hash_protocol_value(state))
        .with_for_update()
    )
    if (
        row is None
        or row.protocol != protocol
        or row.consumed_at is not None
        or aware(row.expires_at) <= utcnow()
    ):
        raise SsoError("SSO state is invalid, expired, or already used")
    row.consumed_at = utcnow()
    return row


async def exchange_oidc_code(
    settings: Settings,
    provider: IdentityProvider,
    state: SsoProtocolState,
    *,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    if not provider.client_id or not provider.encrypted_client_secret:
        raise SsoError("OIDC client credentials are incomplete")
    metadata = dict(provider.oidc_metadata_json or {})
    token_endpoint = _require_https_url(metadata.get("token_endpoint"), "token_endpoint")
    jwks_uri = _require_https_url(metadata.get("jwks_uri"), "jwks_uri")
    master = settings.require_secret_key()
    verifier = decrypt_secret(
        master, SecretPurpose.OIDC_FLOW_SECRET, state.encrypted_pkce_verifier or ""
    )
    nonce = decrypt_secret(master, SecretPurpose.OIDC_FLOW_SECRET, state.encrypted_nonce or "")
    client_secret = decrypt_secret(
        master, SecretPurpose.OIDC_CLIENT_SECRET, provider.encrypted_client_secret
    )
    host, _ip, pinned = _pin_destination(
        token_endpoint, allow_private=provider.allow_private_network
    )
    advertised_methods = metadata.get("token_endpoint_auth_methods_supported")
    supported_methods = (
        [str(value) for value in advertised_methods]
        if isinstance(advertised_methods, list)
        else ["client_secret_basic"]
    )
    method = next(
        (
            value
            for value in ("client_secret_basic", "client_secret_post")
            if value in supported_methods
        ),
        None,
    )
    if method is None:
        raise SsoError("OIDC provider does not support an enabled client authentication method")
    body: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": provider.client_id,
        "code_verifier": verifier,
    }
    if method == "client_secret_post":
        body["client_secret"] = client_secret
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        request_kwargs: dict[str, Any] = {
            "data": body,
            "headers": {"Host": host, "Accept": "application/json"},
            "extensions": {"sni_hostname": host},
        }
        if method != "client_secret_post":
            request_kwargs["auth"] = (provider.client_id, client_secret)
        response = await client.post(pinned, **request_kwargs)
        response.raise_for_status()
        tokens = response.json()
    if not isinstance(tokens, dict) or not isinstance(tokens.get("id_token"), str):
        raise SsoError("OIDC token response did not include an ID token")
    jwks = await _fetch_json(jwks_uri, allow_private=provider.allow_private_network)
    return validate_oidc_id_token(provider, tokens, jwks, nonce=nonce)


def validate_oidc_id_token(
    provider: IdentityProvider,
    tokens: dict[str, Any],
    jwks: dict[str, Any],
    *,
    nonce: str,
) -> dict[str, Any]:
    """Verify signature and all authorization-code ID-token binding claims."""
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or not provider.client_id or not provider.issuer:
        raise SsoError("OIDC token response is incomplete")
    try:
        claims = jwt.decode(
            id_token,
            jwks,
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "value": provider.issuer},
                "aud": {"essential": True, "value": provider.client_id},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "sub": {"essential": True},
            },
            claims_params={
                "nonce": nonce,
                "client_id": provider.client_id,
                "access_token": tokens.get("access_token"),
            },
        )
        if claims.header.get("alg") in {None, "none"}:
            raise SsoError("Unsigned OIDC ID tokens are not accepted")
        claims.validate(leeway=60)
    except (JoseError, JoseRFCError, ValueError) as exc:
        raise SsoError("OIDC ID token validation failed") from exc
    return dict(claims)


def _strip_pem_certificate(value: str) -> str:
    return "".join(
        line.strip()
        for line in value.strip().splitlines()
        if line.strip() and "CERTIFICATE" not in line
    )


def normalize_x509_certificate(value: str) -> str:
    """Parse an IdP certificate and return canonical PEM without accepting junk."""
    stripped = _strip_pem_certificate(value)
    if not stripped:
        raise SsoError("SAML signing certificate is empty")
    wrapped = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        stripped[index : index + 64] for index in range(0, len(stripped), 64)
    ) + "\n-----END CERTIFICATE-----\n"
    try:
        certificate = x509.load_pem_x509_certificate(wrapped.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SsoError("SAML signing certificate is invalid") from exc
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _generate_sp_keypair(provider: IdentityProvider, settings: Settings) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = utcnow()
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Vulna SAML SP {provider.id}")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    master = settings.require_secret_key()
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    provider.encrypted_sp_certificate = encrypt_secret(
        master, SecretPurpose.SAML_SP_CERTIFICATE, cert_pem
    )
    provider.encrypted_sp_private_key = encrypt_secret(
        master, SecretPurpose.SAML_SP_PRIVATE_KEY, key_pem
    )


def import_saml_metadata(
    settings: Settings,
    provider: IdentityProvider,
    metadata_xml: str,
    *,
    entity_id: str | None = None,
) -> None:
    if provider.protocol != IdentityProviderProtocol.SAML:
        raise SsoError("This provider is not configured for SAML")
    if "<!DOCTYPE" in metadata_xml.upper() or "<!ENTITY" in metadata_xml.upper():
        raise SsoError("SAML metadata must not contain DTD or entity declarations")
    try:
        safe_xml_fromstring(metadata_xml)
        parsed = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml, entity_id=entity_id)
        idp = parsed["idp"]
        sso_url = idp["singleSignOnService"]["url"]
        cert = idp.get("x509cert")
    except Exception as exc:  # noqa: BLE001 - normalize toolkit parse errors
        raise SsoError("SAML metadata is invalid or incomplete") from exc
    if not idp.get("entityId") or not cert:
        raise SsoError("SAML metadata must include an entity ID and signing certificate")
    _require_https_url(sso_url, "singleSignOnService")
    if idp.get("singleLogoutService", {}).get("url"):
        _require_https_url(idp["singleLogoutService"]["url"], "singleLogoutService")
    provider.idp_entity_id = str(idp["entityId"])
    provider.idp_sso_url = str(sso_url)
    provider.idp_slo_url = cast(dict[str, Any], idp.get("singleLogoutService") or {}).get("url")
    provider.encrypted_idp_certificate = encrypt_secret(
        settings.require_secret_key(),
        SecretPurpose.SAML_IDP_CERTIFICATE,
        normalize_x509_certificate(str(cert)),
    )
    if not provider.encrypted_sp_private_key or not provider.encrypted_sp_certificate:
        _generate_sp_keypair(provider, settings)
    provider.validated_at = utcnow()


def saml_settings(
    settings: Settings,
    provider: IdentityProvider,
    *,
    base_url: str,
) -> dict[str, Any]:
    if not all(
        [
            provider.idp_entity_id,
            provider.idp_sso_url,
            provider.encrypted_idp_certificate,
            provider.encrypted_sp_certificate,
            provider.encrypted_sp_private_key,
        ]
    ):
        raise SsoError("SAML provider metadata and SP key material are incomplete")
    encrypted_idp_certificate = provider.encrypted_idp_certificate
    encrypted_sp_certificate = provider.encrypted_sp_certificate
    encrypted_sp_private_key = provider.encrypted_sp_private_key
    if not (
        encrypted_idp_certificate
        and encrypted_sp_certificate
        and encrypted_sp_private_key
    ):
        raise SsoError("SAML provider key material is incomplete")
    master = settings.require_secret_key()
    idp_cert = decrypt_secret(
        master, SecretPurpose.SAML_IDP_CERTIFICATE, encrypted_idp_certificate
    )
    signing_certs = [_strip_pem_certificate(idp_cert)]
    if provider.encrypted_next_idp_certificate:
        signing_certs.append(
            _strip_pem_certificate(
                decrypt_secret(
                    master,
                    SecretPurpose.SAML_IDP_CERTIFICATE,
                    provider.encrypted_next_idp_certificate,
                )
            )
        )
    provider_id = str(provider.id)
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{base_url}/api/v1/sso/saml/{provider_id}/metadata",
            "assertionConsumerService": {
                "url": f"{base_url}/api/v1/sso/saml/{provider_id}/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "x509cert": decrypt_secret(
                master, SecretPurpose.SAML_SP_CERTIFICATE, encrypted_sp_certificate
            ),
            "privateKey": decrypt_secret(
                master, SecretPurpose.SAML_SP_PRIVATE_KEY, encrypted_sp_private_key
            ),
        },
        "idp": {
            "entityId": provider.idp_entity_id,
            "singleSignOnService": {
                "url": provider.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": provider.idp_slo_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": signing_certs[0],
            "x509certMulti": {"signing": signing_certs, "encryption": signing_certs[:1]},
        },
        "security": {
            "authnRequestsSigned": True,
            "signMetadata": True,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": provider.want_assertions_encrypted,
            "wantNameIdEncrypted": False,
            "rejectUnsolicitedResponsesWithInResponseTo": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def saml_request_data(
    base_url: str,
    path: str,
    *,
    post_data: dict[str, str] | None = None,
    query_data: dict[str, str] | None = None,
) -> dict[str, Any]:
    parts = urlsplit(base_url)
    return {
        "https": "on" if parts.scheme == "https" else "off",
        "http_host": parts.netloc,
        "server_port": str(parts.port or (443 if parts.scheme == "https" else 80)),
        "script_name": path,
        "get_data": query_data or {},
        "post_data": post_data or {},
    }


def saml_auth(
    settings: Settings,
    provider: IdentityProvider,
    *,
    base_url: str,
    path: str,
    post_data: dict[str, str] | None = None,
    query_data: dict[str, str] | None = None,
) -> OneLogin_Saml2_Auth:
    return OneLogin_Saml2_Auth(
        saml_request_data(base_url, path, post_data=post_data, query_data=query_data),
        saml_settings(settings, provider, base_url=base_url),
    )


def sp_metadata(settings: Settings, provider: IdentityProvider, *, base_url: str) -> str:
    saml = OneLogin_Saml2_Settings(saml_settings(settings, provider, base_url=base_url))
    metadata = saml.get_sp_metadata()
    errors = saml.validate_metadata(metadata)
    if errors:
        raise SsoError("Generated SAML SP metadata failed validation")
    return str(metadata)


async def record_saml_identifiers(
    session: AsyncSession,
    provider: IdentityProvider,
    identifiers: list[str | None],
    *,
    expires_at: datetime | None = None,
) -> None:
    expires = expires_at or (utcnow() + timedelta(hours=24))
    for identifier in {value for value in identifiers if value}:
        digest = hash_protocol_value(str(identifier))
        existing = await session.scalar(
            select(SamlReplayRecord.id).where(SamlReplayRecord.identifier_hash == digest)
        )
        if existing is not None:
            raise SsoError("SAML response or assertion was already consumed")
        session.add(
            SamlReplayRecord(
                organization_id=provider.organization_id,
                identity_provider_id=provider.id,
                identifier_hash=digest,
                expires_at=expires,
            )
        )


def _claim_groups(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("groups") or claims.get("group") or []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(value) for value in raw if isinstance(value, (str, int))]
    return []


async def resolve_sso_user(
    session: AsyncSession,
    provider: IdentityProvider,
    claims: dict[str, Any],
) -> User:
    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise SsoError("Identity response did not contain a stable subject")
    link = await session.scalar(
        select(ExternalIdentityLink).where(
            ExternalIdentityLink.identity_provider_id == provider.id,
            ExternalIdentityLink.subject == subject,
            ExternalIdentityLink.organization_id == provider.organization_id,
        )
    )
    user = await session.get(User, link.user_id) if link else None
    if user is not None and user.organization_id != provider.organization_id:
        raise SsoError("External identity organization mismatch")

    email = str(claims.get("email") or "").strip().lower() or None
    email_verified = claims.get("email_verified") is True
    if user is None:
        if not email or not email_verified:
            raise SsoError("A verified email is required to link or provision this identity")
        user = await session.scalar(
            select(User).where(
                User.organization_id == provider.organization_id,
                User.email == email,
            )
        )
        if user is None:
            if not provider.jit_provisioning:
                raise SsoError("No Vulna account is linked to this identity")
            user = User(
                organization_id=provider.organization_id,
                email=email,
                hashed_password=None,
                full_name=str(claims.get("name") or "").strip()[:255] or None,
                role=provider.default_role,
                is_active=True,
                account_status=AccountStatus.ACTIVE,
                authentication_source=AuthenticationSource.JIT,
                site_access_mode=SiteAccessMode.ALL,
                activated_at=utcnow(),
            )
            session.add(user)
            await session.flush()
        link = ExternalIdentityLink(
            organization_id=provider.organization_id,
            identity_provider_id=provider.id,
            user_id=user.id,
            subject=subject,
            email_at_link=email,
        )
        session.add(link)
    if user.account_status != AccountStatus.ACTIVE or not user.is_active:
        raise SsoError("This account is not active")

    mappings = list(
        (
            await session.execute(
                select(IdentityGroupMapping).where(
                    IdentityGroupMapping.identity_provider_id == provider.id,
                    IdentityGroupMapping.organization_id == provider.organization_id,
                    IdentityGroupMapping.external_group.in_(_claim_groups(claims)),
                )
            )
        ).scalars()
    )
    mapped_roles = {mapping.role for mapping in mappings if mapping.role is not None}
    if len(mapped_roles) > 1:
        raise SsoError("External groups map to conflicting roles")
    if mapped_roles and user.authentication_source == AuthenticationSource.JIT:
        user.role = mapped_roles.pop()
    site_ids = {
        uuid.UUID(value)
        for mapping in mappings
        for value in (mapping.site_ids_json or [])
    }
    if site_ids and user.authentication_source == AuthenticationSource.JIT:
        user.site_access_mode = SiteAccessMode.ASSIGNED
        await session.execute(
            delete(UserSiteAssignment).where(UserSiteAssignment.user_id == user.id)
        )
        session.add_all(
            [
                UserSiteAssignment(
                    organization_id=user.organization_id,
                    user_id=user.id,
                    site_id=site_id,
                    assigned_by_user_id=None,
                )
                for site_id in sorted(site_ids, key=str)
            ]
        )
    if user.authentication_source == AuthenticationSource.JIT:
        await authorization.sync_user_compatibility_grants(session, user)
    now = utcnow()
    user.last_login_at = now
    if link is not None:
        link.last_login_at = now
    await session.flush()
    return user


def sso_has_mfa(claims: dict[str, Any]) -> bool:
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    return bool({str(value).lower() for value in amr} & _MFA_AMR)


def mark_successful_test(
    session: AsyncSession,
    provider: IdentityProvider,
    state: SsoProtocolState,
) -> None:
    if state.purpose != "test":
        return
    now = utcnow()
    provider.last_test_succeeded_at = now
    provider.last_tested_by_user_id = state.initiated_by_user_id
    session.add(
        IdentityProviderTest(
            organization_id=provider.organization_id,
            identity_provider_id=provider.id,
            tested_by_user_id=state.initiated_by_user_id,
            test_type="login",
            succeeded=True,
            detail="Identity-provider test login succeeded",
        )
    )
