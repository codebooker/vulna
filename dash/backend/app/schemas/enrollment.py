"""Enrollment schemas: token creation and the probe enrollment exchange."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class EnrollmentTokenCreate(BaseModel):
    """Admin request to mint a one-time enrollment token for a site."""

    site_id: uuid.UUID
    probe_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)


class EnrollmentTokenCreated(BaseModel):
    """Response containing the one-time token secret (shown only once)."""

    id: uuid.UUID
    site_id: uuid.UUID
    probe_name: str
    token: str = Field(description="The enrollment secret — store it now; it is not retrievable")
    short_code: str = Field(description="Human-readable code for out-of-band verification")
    expires_at: datetime


class EnrollRequest(BaseModel):
    """Probe-submitted enrollment: a valid token and a PEM certificate request."""

    token: str = Field(min_length=1, max_length=512)
    csr_pem: str = Field(description="PEM-encoded PKCS#10 certificate-signing request")


class EnrollResponse(BaseModel):
    """The issued client certificate and the material the probe must persist."""

    probe_id: uuid.UUID
    site_id: uuid.UUID
    certificate_pem: str = Field(description="Issued client certificate (PEM)")
    ca_certificate_pem: str = Field(description="Orchestrator CA certificate (PEM)")
    certificate_fingerprint: str
    certificate_expires_at: datetime
    signing_public_key_b64: str = Field(
        description="Base64 raw Ed25519 public key used to verify jobs and policy"
    )
