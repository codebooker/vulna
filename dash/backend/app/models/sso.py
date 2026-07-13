"""Phase 37 organization SSO configuration and protocol state."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import IdentityProviderProtocol, SsoPolicyMode, UserRole


class IdentityProvider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An organization-owned OIDC or SAML identity provider.

    Reusable client secrets, certificates, and private keys are encrypted with
    independent HKDF purposes and are never serialized by the API.
    """

    __tablename__ = "identity_providers"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_identity_provider_org_slug"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    protocol: Mapped[IdentityProviderProtocol] = mapped_column(
        Enum(
            IdentityProviderProtocol,
            native_enum=False,
            length=16,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    default_role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=UserRole.VIEWER,
    )
    preset: Mapped[str] = mapped_column(String(32), nullable=False, default="generic")
    allow_private_network: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # OIDC fields.
    issuer: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    discovery_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    encrypted_client_secret: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    scopes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    oidc_metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # SAML fields. Certificates are encrypted because deployments may treat
    # identity infrastructure material as confidential configuration.
    idp_entity_id: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    idp_sso_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    idp_slo_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    encrypted_idp_certificate: Mapped[str | None] = mapped_column(String(16384), nullable=True)
    encrypted_next_idp_certificate: Mapped[str | None] = mapped_column(
        String(16384), nullable=True
    )
    encrypted_sp_certificate: Mapped[str | None] = mapped_column(String(16384), nullable=True)
    encrypted_sp_private_key: Mapped[str | None] = mapped_column(String(16384), nullable=True)
    want_assertions_encrypted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_succeeded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class SsoPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One organization-level sign-in policy."""

    __tablename__ = "sso_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    mode: Mapped[SsoPolicyMode] = mapped_column(
        Enum(
            SsoPolicyMode,
            native_enum=False,
            length=16,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=SsoPolicyMode.DISABLED,
    )
    identity_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="SET NULL"), nullable=True
    )


class ExternalIdentityLink(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stable external subject-to-local-user link."""

    __tablename__ = "external_identity_links"
    __table_args__ = (
        UniqueConstraint("identity_provider_id", "subject", name="uq_external_identity_subject"),
        UniqueConstraint("identity_provider_id", "user_id", name="uq_external_identity_user"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject: Mapped[str] = mapped_column(String(1024), nullable=False)
    email_at_link: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityGroupMapping(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Exact external group mapping to the compatibility role and sites."""

    __tablename__ = "identity_group_mappings"
    __table_args__ = (
        UniqueConstraint(
            "identity_provider_id", "external_group", name="uq_identity_group_mapping"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_group: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[UserRole | None] = mapped_column(
        Enum(UserRole, native_enum=False, length=32, validate_strings=True), nullable=True
    )
    site_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class IdentityProviderTest(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Immutable validation/test-login history used by enforcement gates."""

    __tablename__ = "identity_provider_tests"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    test_type: Mapped[str] = mapped_column(String(32), nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class SsoProtocolState(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Short-lived, single-use state for OIDC PKCE/nonce and SAML request IDs."""

    __tablename__ = "sso_protocol_states"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    protocol: Mapped[IdentityProviderProtocol] = mapped_column(
        Enum(
            IdentityProviderProtocol,
            native_enum=False,
            length=16,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    purpose: Mapped[str] = mapped_column(String(16), nullable=False, default="login")
    encrypted_nonce: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    encrypted_pkce_verifier: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    return_path: Mapped[str] = mapped_column(String(1024), nullable=False, default="/")
    initiated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SamlReplayRecord(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Hashed message/assertion identifiers rejected on reuse."""

    __tablename__ = "saml_replay_records"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identifier_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
