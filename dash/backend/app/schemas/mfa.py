"""Phase 36 MFA, recovery, WebAuthn, and policy API schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class MfaStatusRead(BaseModel):
    required: bool
    enrolled: bool
    grace_expires_at: datetime | None
    totp: bool
    webauthn_credentials: int
    recovery_codes_remaining: int
    methods: list[str]


class TotpSetupRead(BaseModel):
    factor_id: uuid.UUID
    secret: str
    provisioning_uri: str
    expires_in: int = 600


class TotpCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class TotpConfirmRequest(TotpCodeRequest):
    factor_id: uuid.UUID


class RecoveryCodesRead(BaseModel):
    codes: list[str]
    shown_once: bool = True


class MfaVerifyResult(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - protocol label, not a secret
    expires_in: int
    method: str
    recovery_codes_remaining: int | None = None


class TotpConfirmRead(BaseModel):
    verification: MfaVerifyResult
    recovery_codes: RecoveryCodesRead


class MfaPolicyRead(BaseModel):
    mode: Literal["optional", "required"]
    required_roles: list[str]
    grace_period_days: int


class MfaPolicyUpdate(BaseModel):
    mode: Literal["optional", "required"] | None = None
    required_roles: list[str] | None = Field(default=None, max_length=20)
    grace_period_days: int | None = Field(default=None, ge=1, le=30)


class WebAuthnBeginRead(BaseModel):
    challenge_id: uuid.UUID
    public_key: dict[str, Any]


class WebAuthnRegistrationFinish(BaseModel):
    challenge_id: uuid.UUID
    credential: dict[str, Any]
    label: str = Field(default="Security key", min_length=1, max_length=255)


class WebAuthnAuthenticationFinish(BaseModel):
    challenge_id: uuid.UUID
    credential: dict[str, Any]


class WebAuthnCredentialRead(BaseModel):
    id: uuid.UUID
    label: str
    device_type: str
    backed_up: bool
    transports: list[str]
    created_at: datetime
    last_used_at: datetime | None


class WebAuthnRegistrationRead(BaseModel):
    credential: WebAuthnCredentialRead
    verification: MfaVerifyResult
    recovery_codes: RecoveryCodesRead | None = None
