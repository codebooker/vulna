"""Credential vault encryption, deterministic assignment resolution, and job envelopes."""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_context import AssetGroupMembership, AssetTagAssignment
from app.models.credential import (
    CredentialAssignment,
    CredentialRecord,
    CredentialSecretVersion,
)
from app.models.enums import (
    CredentialAssignmentTarget,
    CredentialAuthType,
    CredentialProtocol,
)
from app.services.secret_crypto import SecretPurpose, decrypt_secret, encrypt_secret

_ENVELOPE_INFO = b"vulna-scout-credential-envelope-v1"
_SSH_METADATA = {"port", "host_key_fingerprint", "connect_timeout_seconds"}
_WINRM_METADATA = {
    "port",
    "https",
    "tls_server_name",
    "ca_certificate_pem",
    "connect_timeout_seconds",
    "authentication",
}


class CredentialError(ValueError):
    """A vault value or assignment cannot be used safely."""


class CredentialResolutionError(CredentialError):
    """A required protocol has no unambiguous assignment."""


def _bounded_integer(
    metadata: dict[str, Any], key: str, default: int, minimum: int, maximum: int
) -> int:
    value = metadata.get(key, default)
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        raise CredentialError(f"{key} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CredentialError(f"{key} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise CredentialError(f"{key} must be between {minimum} and {maximum}")
    return parsed


@dataclass(frozen=True)
class ResolvedCredential:
    protocol: CredentialProtocol
    record: CredentialRecord | None
    version: CredentialSecretVersion | None
    matched_level: CredentialAssignmentTarget | None
    candidates: tuple[uuid.UUID, ...] = ()

    @property
    def conflict(self) -> bool:
        return len(self.candidates) > 1


def _purpose(protocol: CredentialProtocol) -> SecretPurpose:
    if protocol == CredentialProtocol.SSH:
        return SecretPurpose.CREDENTIAL_SSH_SECRET
    return SecretPurpose.CREDENTIAL_WINRM_SECRET


def validate_credential_material(
    protocol: CredentialProtocol,
    auth_type: CredentialAuthType,
    secret: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Return allowlisted transport metadata or fail closed."""
    allowed = _SSH_METADATA if protocol == CredentialProtocol.SSH else _WINRM_METADATA
    unknown = set(metadata) - allowed
    if unknown:
        raise CredentialError(f"Unsupported credential metadata: {', '.join(sorted(unknown))}")
    if any(key.lower() in {"secret", "password", "private_key", "token"} for key in metadata):
        raise CredentialError("Secret values belong in the one-way secret field")

    normalized = dict(metadata)
    if protocol == CredentialProtocol.SSH:
        if auth_type not in {CredentialAuthType.PASSWORD, CredentialAuthType.SSH_PRIVATE_KEY}:
            raise CredentialError("SSH supports password or private-key authentication")
        fingerprint = str(normalized.get("host_key_fingerprint", "")).strip()
        if not fingerprint.startswith("SHA256:") or len(fingerprint) > 255:
            raise CredentialError("SSH credentials require a SHA256 host-key fingerprint")
        normalized["host_key_fingerprint"] = fingerprint
        normalized["port"] = _bounded_integer(normalized, "port", 22, 1, 65535)
        if auth_type == CredentialAuthType.SSH_PRIVATE_KEY:
            try:
                raw = secret.encode("utf-8")
                try:
                    serialization.load_ssh_private_key(raw, password=None)
                except ValueError:
                    serialization.load_pem_private_key(raw, password=None)
            except (TypeError, ValueError) as exc:
                raise CredentialError("SSH private key is not a supported unencrypted key") from exc
    else:
        if auth_type != CredentialAuthType.PASSWORD:
            raise CredentialError("WinRM currently supports password authentication")
        if normalized.get("https", True) is not True:
            raise CredentialError("WinRM credential delivery requires HTTPS")
        normalized["https"] = True
        normalized["port"] = _bounded_integer(normalized, "port", 5986, 1, 65535)
        normalized["authentication"] = str(normalized.get("authentication", "ntlm")).lower()
        if normalized["authentication"] not in {"ntlm", "basic"}:
            raise CredentialError("WinRM authentication must be 'ntlm' or 'basic'")
        if not normalized.get("tls_server_name") and not normalized.get("ca_certificate_pem"):
            raise CredentialError(
                "WinRM requires a TLS server name or pinned CA certificate; "
                "verification cannot be skipped"
            )
        tls_server_name = normalized.get("tls_server_name")
        if tls_server_name is not None and (
            not isinstance(tls_server_name, str)
            or len(tls_server_name) > 255
            or any(character.isspace() for character in tls_server_name)
        ):
            raise CredentialError("WinRM TLS server name is invalid")
        ca_certificate = normalized.get("ca_certificate_pem")
        if ca_certificate is not None and (
            not isinstance(ca_certificate, str)
            or len(ca_certificate) > 65_536
            or "-----BEGIN CERTIFICATE-----" not in ca_certificate
        ):
            raise CredentialError("WinRM pinned CA certificate is invalid")

    normalized["connect_timeout_seconds"] = _bounded_integer(
        normalized, "connect_timeout_seconds", 30, 1, 120
    )
    return normalized


async def latest_secret_version(
    session: AsyncSession, credential_id: uuid.UUID
) -> CredentialSecretVersion | None:
    return cast(
        CredentialSecretVersion | None,
        await session.scalar(
            select(CredentialSecretVersion)
            .where(
                CredentialSecretVersion.credential_id == credential_id,
                CredentialSecretVersion.retired_at.is_(None),
            )
            .order_by(CredentialSecretVersion.version.desc())
            .limit(1)
        ),
    )


async def store_secret_version(
    session: AsyncSession,
    record: CredentialRecord,
    secret: str,
    *,
    master_secret: str,
    created_by: uuid.UUID | None,
) -> CredentialSecretVersion:
    current = await latest_secret_version(session, record.id)
    next_version = 1
    if current is not None:
        current.retired_at = datetime.now(UTC)
        next_version = current.version + 1
    version = CredentialSecretVersion(
        organization_id=record.organization_id,
        credential_id=record.id,
        version=next_version,
        encrypted_secret=encrypt_secret(master_secret, _purpose(record.protocol), secret),
        created_by_user_id=created_by,
    )
    session.add(version)
    await session.flush()
    return version


async def _resolution_targets(
    session: AsyncSession,
    asset: Asset,
    *,
    network_id: uuid.UUID | None,
    preset_key: str | None,
) -> list[tuple[CredentialAssignmentTarget, set[str]]]:
    groups = {
        str(value)
        for value in (
            await session.scalars(
                select(AssetGroupMembership.group_id).where(
                    AssetGroupMembership.organization_id == asset.organization_id,
                    AssetGroupMembership.asset_id == asset.id,
                )
            )
        ).all()
    }
    tags = {
        str(value)
        for value in (
            await session.scalars(
                select(AssetTagAssignment.tag_id).where(
                    AssetTagAssignment.organization_id == asset.organization_id,
                    AssetTagAssignment.asset_id == asset.id,
                )
            )
        ).all()
    }
    return [
        (CredentialAssignmentTarget.ASSET, {str(asset.id)}),
        (CredentialAssignmentTarget.GROUP, groups),
        (CredentialAssignmentTarget.TAG, tags),
        (
            CredentialAssignmentTarget.NETWORK,
            {str(network_id)} if network_id is not None else set(),
        ),
        (CredentialAssignmentTarget.SITE, {str(asset.site_id)}),
        (
            CredentialAssignmentTarget.PRESET,
            {preset_key} if preset_key is not None else set(),
        ),
    ]


async def resolve_credential(
    session: AsyncSession,
    asset: Asset,
    protocol: CredentialProtocol,
    *,
    network_id: uuid.UUID | None = None,
    preset_key: str | None = None,
) -> ResolvedCredential:
    for level, target_ids in await _resolution_targets(
        session, asset, network_id=network_id, preset_key=preset_key
    ):
        if not target_ids:
            continue
        rows = list(
            (
                await session.execute(
                    select(CredentialRecord)
                    .join(
                        CredentialAssignment,
                        CredentialAssignment.credential_id == CredentialRecord.id,
                    )
                    .where(
                        CredentialRecord.organization_id == asset.organization_id,
                        CredentialRecord.protocol == protocol,
                        CredentialRecord.is_active.is_(True),
                        CredentialAssignment.organization_id == asset.organization_id,
                        CredentialAssignment.target_type == level,
                        CredentialAssignment.target_id.in_(target_ids),
                        CredentialAssignment.enabled.is_(True),
                    )
                    .order_by(CredentialRecord.id)
                )
            ).scalars()
        )
        unique = {row.id: row for row in rows}
        if len(unique) > 1:
            return ResolvedCredential(
                protocol=protocol,
                record=None,
                version=None,
                matched_level=level,
                candidates=tuple(sorted(unique, key=str)),
            )
        if len(unique) == 1:
            record = next(iter(unique.values()))
            version = await latest_secret_version(session, record.id)
            if version is None:
                continue
            return ResolvedCredential(protocol, record, version, level, (record.id,))
    return ResolvedCredential(protocol, None, None, None)


async def resolve_required_credentials(
    session: AsyncSession,
    asset: Asset,
    protocols: list[CredentialProtocol],
    *,
    network_id: uuid.UUID | None = None,
    preset_key: str | None = None,
) -> list[ResolvedCredential]:
    resolved = [
        await resolve_credential(
            session, asset, protocol, network_id=network_id, preset_key=preset_key
        )
        for protocol in dict.fromkeys(protocols)
    ]
    for item in resolved:
        if item.conflict:
            level = item.matched_level.value if item.matched_level else "unknown"
            raise CredentialResolutionError(
                f"Multiple {item.protocol.value} credentials match at the "
                f"{level} level; resolve the conflict before starting a job"
            )
        if item.record is None or item.version is None:
            raise CredentialResolutionError(
                f"No active {item.protocol.value} credential is assigned to this asset"
            )
    return resolved


def decrypt_resolved_secret(resolved: ResolvedCredential, *, master_secret: str) -> str:
    if resolved.record is None or resolved.version is None:
        raise CredentialResolutionError("credential resolution is incomplete")
    return decrypt_secret(
        master_secret,
        _purpose(resolved.record.protocol),
        resolved.version.encrypted_secret,
    )


def build_scout_credential_envelope(
    *,
    job_id: uuid.UUID,
    probe_id: uuid.UUID,
    probe_public_key_b64: str,
    expires_at: str,
    credentials: list[tuple[ResolvedCredential, str]],
) -> dict[str, str]:
    """Encrypt plaintext once to the enrolled Scout public key and discard it."""
    try:
        public_bytes = base64.b64decode(probe_public_key_b64, validate=True)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    except (ValueError, TypeError) as exc:
        raise CredentialError("Scout encryption public key is invalid; re-enroll it") from exc

    payload = {
        "version": 1,
        "job_id": str(job_id),
        "probe_id": str(probe_id),
        "expires_at": expires_at,
        "credentials": [
            {
                "credential_id": str(item.record.id),
                "secret_version_id": str(item.version.id),
                "protocol": item.protocol.value,
                "auth_type": item.record.auth_type.value,
                "username": item.record.username,
                "secret": secret,
                "metadata": item.record.metadata_json,
            }
            for item, secret in credentials
            if item.record is not None and item.version is not None
        ],
    }
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(public_key)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_ENVELOPE_INFO).derive(shared)
    nonce = os.urandom(12)
    aad = f"{job_id}:{probe_id}".encode("ascii")
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "version": "1",
        "algorithm": "X25519-HKDF-SHA256-CHACHA20POLY1305",
        "ephemeral_public_key_b64": base64.b64encode(ephemeral_public).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
