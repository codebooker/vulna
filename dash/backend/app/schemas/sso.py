"""OIDC and SAML SSO administration and browser-flow schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, HttpUrl, model_validator

from app.models.enums import IdentityProviderProtocol, SsoPolicyMode, UserRole


class IdentityProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")
    protocol: IdentityProviderProtocol
    preset: Literal["generic", "entra", "google", "okta", "keycloak"] = "generic"
    jit_provisioning: bool = False
    default_role: UserRole = UserRole.VIEWER
    allow_private_network: bool = False
    issuer: HttpUrl | None = None
    discovery_url: HttpUrl | None = None
    client_id: str | None = Field(default=None, min_length=1, max_length=512)
    client_secret: str | None = Field(default=None, min_length=1, max_length=4096)
    scopes: list[str] = Field(default_factory=list, max_length=32)
    want_assertions_encrypted: bool = False

    @model_validator(mode="after")
    def protocol_fields(self) -> IdentityProviderCreate:
        if self.protocol == IdentityProviderProtocol.OIDC and not (
            self.issuer and self.client_id
        ):
            raise ValueError("OIDC providers require issuer and client_id")
        if self.protocol == IdentityProviderProtocol.SAML and any(
            (self.issuer, self.discovery_url, self.client_id, self.client_secret)
        ):
            raise ValueError("SAML providers must be configured through metadata import")
        return self


class IdentityProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    preset: Literal["generic", "entra", "google", "okta", "keycloak"] | None = None
    jit_provisioning: bool | None = None
    default_role: UserRole | None = None
    allow_private_network: bool | None = None
    issuer: HttpUrl | None = None
    discovery_url: HttpUrl | None = None
    client_id: str | None = Field(default=None, min_length=1, max_length=512)
    client_secret: str | None = Field(default=None, min_length=1, max_length=4096)
    scopes: list[str] | None = Field(default=None, max_length=32)
    want_assertions_encrypted: bool | None = None
    next_idp_certificate: str | None = Field(default=None, min_length=1, max_length=12000)


class IdentityProviderRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    protocol: IdentityProviderProtocol
    enabled: bool
    jit_provisioning: bool
    default_role: UserRole
    preset: str
    allow_private_network: bool
    issuer: str | None
    discovery_url: str | None
    client_id: str | None
    scopes: list[str]
    idp_entity_id: str | None
    idp_sso_url: str | None
    idp_slo_url: str | None
    want_assertions_encrypted: bool
    has_client_secret: bool
    has_idp_certificate: bool
    has_next_idp_certificate: bool
    has_sp_certificate: bool
    validated_at: datetime | None
    last_test_succeeded_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SamlMetadataImport(BaseModel):
    metadata_xml: str = Field(min_length=1, max_length=1_000_000)
    entity_id: str | None = Field(default=None, max_length=2048)


class IdentityProviderEnable(BaseModel):
    enabled: bool


class GroupMappingWrite(BaseModel):
    external_group: str = Field(min_length=1, max_length=512)
    role: UserRole | None = None
    site_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)


class GroupMappingRead(BaseModel):
    id: uuid.UUID
    external_group: str
    role: UserRole | None
    site_ids: list[uuid.UUID]


class SsoPolicyRead(BaseModel):
    mode: SsoPolicyMode
    identity_provider_id: uuid.UUID | None
    break_glass_user_ids: list[uuid.UUID]
    enforcement_ready: bool
    readiness_reasons: list[str]


class SsoPolicyUpdate(BaseModel):
    mode: SsoPolicyMode
    identity_provider_id: uuid.UUID | None = None


class BreakGlassUpdate(BaseModel):
    enabled: bool


class PublicIdentityProvider(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    protocol: IdentityProviderProtocol


class SsoStartRequest(BaseModel):
    return_path: str = Field(default="/#overview", max_length=1024)


class SsoStartResponse(BaseModel):
    authorization_url: str
    expires_at: datetime


class OidcCallbackRequest(BaseModel):
    code: str = Field(min_length=1, max_length=4096)
    state: str = Field(min_length=16, max_length=1024)


class SsoSessionResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    session_id: uuid.UUID
    return_path: str = "/"
    mfa_required: bool = False


class SsoTestRecordRead(BaseModel):
    id: uuid.UUID
    test_type: str
    succeeded: bool
    detail: str | None
    tested_by_user_id: uuid.UUID | None
    created_at: datetime


class SsoLoginHint(BaseModel):
    email: EmailStr | None = None
