"""Phase 42 credential isolation, Scout envelopes, inventory, and EOL coverage."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime

import pytest
from app.models.asset import Asset, AssetIdentifier
from app.models.credential import (
    CredentialAssignment,
    CredentialRecord,
    CredentialSecretVersion,
    CredentialUsageAudit,
)
from app.models.enums import (
    AssetType,
    CredentialAssignmentTarget,
    CredentialAuthType,
    CredentialProtocol,
    IdentifierType,
    ProbeStatus,
)
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.models.software import SoftwareInventoryHistory
from app.services import credentials as credential_service
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import probe_cert_headers

pytestmark = pytest.mark.release_gate


async def _topology(
    session: AsyncSession, organization: Organization
) -> tuple[Site, Network, Asset, Probe, x25519.X25519PrivateKey]:
    site = Site(
        organization_id=organization.id,
        name="Authenticated Lab",
        code=f"AUTH-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    session.add(site)
    await session.flush()
    network = Network(
        organization_id=organization.id,
        site_id=site.id,
        name="Lab network",
        enabled=True,
        is_default=True,
    )
    session.add(network)
    await session.flush()
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    probe = Probe(
        organization_id=organization.id,
        site_id=site.id,
        name="inventory-scout",
        status=ProbeStatus.ENROLLED,
        certificate_fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
        credentialed_scans_enabled=True,
        encryption_public_key_b64=base64.b64encode(public_key).decode("ascii"),
        capabilities_json=["ssh_inventory", "winrm_inventory"],
        enrolled_at=datetime.now(UTC),
        approved_at=datetime.now(UTC),
    )
    asset = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="linux-lab",
        asset_type=AssetType.SERVER,
    )
    session.add_all([probe, asset])
    await session.flush()
    session.add_all(
        [
            NetworkScout(network_id=network.id, probe_id=probe.id, is_primary=True),
            NetworkScope(
                organization_id=organization.id,
                site_id=site.id,
                network_id=network.id,
                name="lab",
                cidr="10.42.0.0/24",
                enabled=True,
                approved_at=datetime.now(UTC),
                policy_version=1,
            ),
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type=IdentifierType.IP_ADDRESS,
                identifier_value="10.42.0.10",
                confidence=100,
            ),
        ]
    )
    await session.commit()
    return site, network, asset, probe, private_key


def _decrypt_job_envelope(job: ScanJob, private_key: x25519.X25519PrivateKey) -> dict[str, object]:
    envelope = job.envelope_json["credential_envelope"]
    ephemeral = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope["ephemeral_public_key_b64"])
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vulna-scout-credential-envelope-v1",
    ).derive(private_key.exchange(ephemeral))
    plaintext = ChaCha20Poly1305(key).decrypt(
        base64.b64decode(envelope["nonce_b64"]),
        base64.b64decode(envelope["ciphertext_b64"]),
        f"{job.id}:{job.probe_id}".encode("ascii"),
    )
    return json.loads(plaintext)


async def test_one_way_vault_envelope_inventory_and_eol_override(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    _, network, asset, probe, private_key = await _topology(db_session, organization)
    password = "phase42-secret-never-persist-plaintext"
    created = await client.post(
        "/api/v1/credentials",
        headers=admin_headers,
        json={
            "name": "Linux read only",
            "protocol": "ssh",
            "auth_type": "password",
            "username": "inventory",
            "secret": password,
            "metadata": {
                "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "port": 22,
            },
        },
    )
    assert created.status_code == 201, created.text
    credential = created.json()
    assert credential["has_secret"] is True
    assert credential["current_version"] == 1
    assert password not in created.text
    assert "secret" not in credential

    assigned = await client.post(
        f"/api/v1/credentials/{credential['id']}/assignments",
        headers=admin_headers,
        json={"target_type": "asset", "target_id": str(asset.id)},
    )
    assert assigned.status_code == 201, assigned.text

    generic_refusal = await client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            "probe_id": str(probe.id),
            "targets": ["10.42.0.10"],
            "asset_id": str(asset.id),
            "authenticated_protocols": ["ssh"],
        },
    )
    assert generic_refusal.status_code == 422

    response = await client.post(
        "/api/v1/jobs/authenticated",
        headers=admin_headers,
        json={
            "probe_id": str(probe.id),
            "targets": ["10.42.0.10"],
            "asset_id": str(asset.id),
            "network_id": str(network.id),
            "authenticated_protocols": ["ssh"],
        },
    )
    assert response.status_code == 201, response.text
    job = await db_session.get(ScanJob, uuid.UUID(response.json()["id"]))
    assert job is not None
    assert job.credential_protocols_json == ["ssh"]
    assert password not in json.dumps(job.envelope_json)
    payload = _decrypt_job_envelope(job, private_key)
    assert payload["job_id"] == str(job.id)
    assert payload["credentials"][0]["secret"] == password  # type: ignore[index]

    version = await db_session.scalar(
        select(CredentialSecretVersion).where(
            CredentialSecretVersion.credential_id == uuid.UUID(credential["id"])
        )
    )
    assert version is not None
    assert password not in version.encrypted_secret
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(CredentialUsageAudit)
            .where(CredentialUsageAudit.scan_job_id == job.id)
        )
        == 1
    )

    upload = await client.post(
        f"/api/v1/probes/{probe.id}/jobs/{job.id}/results?stage=inventory&scanner=ssh_inventory",
        headers=probe_cert_headers(probe.certificate_fingerprint),
        content=json.dumps(
            {
                "operating_system": {"name": "Debian GNU/Linux", "version": "12"},
                "packages": [
                    {
                        "name": "openssl",
                        "package_key": "openssl",
                        "version": "3.0.17-1",
                        "architecture": "amd64",
                        "product_key": "openssl",
                    },
                    {
                        "name": "curl",
                        "version": "8.10.1",
                        "architecture": "amd64",
                    },
                ],
            }
        ),
    )
    assert upload.status_code == 201, upload.text
    assert upload.json()["packages_added"] == 2
    software = await client.get(f"/api/v1/software?asset_id={asset.id}", headers=admin_headers)
    assert software.status_code == 200, software.text
    assert software.json()["total"] == 2
    assert all(item["eol"]["status"] == "unknown" for item in software.json()["items"])

    openssl = next(item for item in software.json()["items"] if item["package_key"] == "openssl")
    overridden = await client.post(
        f"/api/v1/software/{openssl['id']}/eol-overrides",
        headers=admin_headers,
        json={
            "status": "supported",
            "reason": "Vendor support contract is documented in CMDB-42",
        },
    )
    assert overridden.status_code == 201, overridden.text
    refreshed = await client.get(f"/api/v1/software/{openssl['id']}", headers=admin_headers)
    assert refreshed.json()["eol"] == {
        "status": "supported",
        "eol_date": None,
        "source": "manual_override",
        "source_url": None,
        "overridden": True,
    }

    second_upload = await client.post(
        f"/api/v1/probes/{probe.id}/jobs/{job.id}/results?stage=inventory&scanner=ssh_inventory",
        headers=probe_cert_headers(probe.certificate_fingerprint),
        content=json.dumps(
            {
                "operating_system": {"name": "Debian GNU/Linux", "version": "12"},
                "packages": [
                    {
                        "name": "openssl",
                        "version": "3.0.18-1",
                        "architecture": "amd64",
                        "product_key": "openssl",
                    }
                ],
            }
        ),
    )
    assert second_upload.status_code == 201, second_upload.text
    assert second_upload.json()["packages_updated"] == 1
    assert second_upload.json()["packages_removed"] == 1
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(SoftwareInventoryHistory)
            .where(SoftwareInventoryHistory.asset_id == asset.id)
        )
        == 4
    )

    deactivated = await client.patch(
        f"/api/v1/credentials/{credential['id']}",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert deactivated.status_code == 200, deactivated.text
    await db_session.refresh(job)
    assert job.status.value == "cancelled"
    usage_row = await db_session.scalar(
        select(CredentialUsageAudit).where(CredentialUsageAudit.scan_job_id == job.id)
    )
    assert usage_row is not None
    assert usage_row.status.value == "failed"
    assert usage_row.detail == "credential_deactivated"

    exported = await client.get("/api/v1/portability/export", headers=admin_headers)
    assert exported.status_code == 200, exported.text
    bundle = exported.json()
    assert bundle["schema_version"] == "8"
    assert any(row["id"] == credential["id"] for row in bundle["credential_records"])
    assert len(bundle["software_inventory"]) == 2
    export_text = json.dumps(bundle)
    assert password not in export_text
    assert "encrypted_secret" not in export_text
    assert "ciphertext_b64" not in export_text


async def test_resolution_precedence_conflicts_and_organization_isolation(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site, _, asset, _, _ = await _topology(db_session, organization)

    async def record(name: str) -> CredentialRecord:
        value = CredentialRecord(
            organization_id=organization.id,
            name=name,
            protocol=CredentialProtocol.SSH,
            auth_type=CredentialAuthType.PASSWORD,
            username="inventory",
            metadata_json={"host_key_fingerprint": "SHA256:fixture"},
        )
        db_session.add(value)
        await db_session.flush()
        await credential_service.store_secret_version(
            db_session,
            value,
            f"{name}-secret",
            master_secret="test-only-secret-do-not-use-in-production",
            created_by=None,
        )
        return value

    site_credential = await record("site-default")
    asset_credential = await record("asset-specific")
    conflict_credential = await record("asset-conflict")
    db_session.add_all(
        [
            CredentialAssignment(
                organization_id=organization.id,
                credential_id=site_credential.id,
                target_type=CredentialAssignmentTarget.SITE,
                target_id=str(site.id),
                site_id=site.id,
            ),
            CredentialAssignment(
                organization_id=organization.id,
                credential_id=asset_credential.id,
                target_type=CredentialAssignmentTarget.ASSET,
                target_id=str(asset.id),
                site_id=site.id,
            ),
        ]
    )
    await db_session.commit()
    resolved = await credential_service.resolve_credential(
        db_session, asset, CredentialProtocol.SSH
    )
    assert resolved.record is not None and resolved.record.id == asset_credential.id
    assert resolved.matched_level == CredentialAssignmentTarget.ASSET

    db_session.add(
        CredentialAssignment(
            organization_id=organization.id,
            credential_id=conflict_credential.id,
            target_type=CredentialAssignmentTarget.ASSET,
            target_id=str(asset.id),
            site_id=site.id,
        )
    )
    await db_session.commit()
    preview = await client.post(
        "/api/v1/credentials/resolve-preview",
        headers=admin_headers,
        json={"asset_id": str(asset.id), "protocols": ["ssh"]},
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()[0]["conflict"] is True
    assert preview.json()[0]["matched_level"] == "asset"

    other = Organization(name="Other", slug=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    await db_session.flush()
    foreign = CredentialRecord(
        organization_id=other.id,
        name="foreign-secret-metadata",
        protocol=CredentialProtocol.SSH,
        auth_type=CredentialAuthType.PASSWORD,
        username="foreign-user",
        metadata_json={"host_key_fingerprint": "SHA256:foreign"},
    )
    db_session.add(foreign)
    await db_session.commit()
    hidden = await client.get(f"/api/v1/credentials/{foreign.id}", headers=admin_headers)
    assert hidden.status_code == 404


def test_winrm_transport_metadata_fails_closed_without_tls_verification() -> None:
    with pytest.raises(credential_service.CredentialError, match="TLS server name"):
        credential_service.validate_credential_material(
            CredentialProtocol.WINRM,
            CredentialAuthType.PASSWORD,
            "secret",
            {"https": True, "port": 5986},
        )
    with pytest.raises(credential_service.CredentialError, match="requires HTTPS"):
        credential_service.validate_credential_material(
            CredentialProtocol.WINRM,
            CredentialAuthType.PASSWORD,
            "secret",
            {"https": False, "tls_server_name": "host.example"},
        )
    with pytest.raises(credential_service.CredentialError, match="port must be an integer"):
        credential_service.validate_credential_material(
            CredentialProtocol.SSH,
            CredentialAuthType.PASSWORD,
            "secret",
            {"host_key_fingerprint": "SHA256:test", "port": True},
        )
    with pytest.raises(credential_service.CredentialError, match="pinned CA certificate"):
        credential_service.validate_credential_material(
            CredentialProtocol.WINRM,
            CredentialAuthType.PASSWORD,
            "secret",
            {"https": True, "ca_certificate_pem": "not-a-certificate"},
        )


async def test_phase42_permissions_openapi_and_capability_status(
    client: AsyncClient,
    viewer_headers: dict[str, str],
) -> None:
    denied = await client.post(
        "/api/v1/credentials",
        headers=viewer_headers,
        json={
            "name": "Unauthorized credential",
            "protocol": "ssh",
            "auth_type": "password",
            "username": "inventory",
            "secret": "must-not-be-stored",
            "metadata": {"host_key_fingerprint": "SHA256:test"},
        },
    )
    assert denied.status_code == 403

    openapi = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/credentials",
        "/api/v1/credentials/resolve-preview",
        "/api/v1/credentials/tests",
        "/api/v1/jobs/authenticated",
        "/api/v1/software",
        "/api/v1/probes/{probe_id}/credentialed-scans",
    ):
        assert path in openapi["paths"]

    capabilities = (
        await client.get("/api/v1/system/capabilities", headers=viewer_headers)
    ).json()
    phase42 = next(
        item for item in capabilities["capabilities"] if item["key"] == "authenticated_scanning"
    )
    assert phase42 == {
        "key": "authenticated_scanning",
        "name": "Authenticated scanning and software inventory",
        "status": "available",
        "production_ready": False,
    }
