"""Encrypted CSV inventory upload, parsing, worker, and privacy coverage."""

from __future__ import annotations

import uuid

import pytest
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.background_task import BackgroundTask
from app.models.enums import BackgroundTaskStatus, PassiveConnectorType
from app.models.organization import Organization
from app.models.passive_inventory import AssetObservation, ConnectorRun, InventoryConnector
from app.models.site import Site
from app.services.secret_crypto import SecretDecryptionError, SecretPurpose, decrypt_secret
from app.tasks import runner
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.release_gate


async def test_csv_upload_is_encrypted_one_way_and_collected_by_worker(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = organization.id
    site = Site(
        organization_id=organization_id,
        name="CSV inventory",
        code=f"CSV-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.commit()
    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)

    created = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Quarterly CSV",
            "connector_type": "csv",
            "config": {},
        },
    )
    assert created.status_code == 201, created.text
    connector_id = uuid.UUID(created.json()["id"])
    assert created.json()["has_source_data"] is False

    source = (
        b"id,hostname,ip_address,operating_system\r\n"
        b"asset-1,web-01,192.0.2.10,Linux\r\n"
        b"asset-2,db-01,192.0.2.11,Linux\r\n"
    )
    uploaded = await client.put(
        f"/api/v1/inventory/connectors/{connector_id}/csv",
        headers={
            **admin_headers,
            "Content-Type": "text/csv",
            "X-File-Name": "../quarterly.csv",
        },
        content=source,
    )
    assert uploaded.status_code == 200, uploaded.text
    body = uploaded.json()
    assert body["has_source_data"] is True
    assert body["source_filename"] == "quarterly.csv"
    assert body["source_size_bytes"] == len(source)
    assert source.decode() not in uploaded.text
    stored = await db_session.get(InventoryConnector, connector_id)
    assert stored is not None
    assert stored.encrypted_source_data and source.decode() not in stored.encrypted_source_data
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(
            get_settings().secret_key,
            SecretPurpose.INVENTORY_CONNECTOR_SECRET,
            stored.encrypted_source_data,
        )

    tested = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/test", headers=admin_headers
    )
    assert tested.status_code == 200, tested.text
    assert tested.json()["succeeded"] is True
    assert tested.json()["metadata"]["records_visible"] == 2
    assert tested.json()["metadata"]["headers"] == [
        "id",
        "hostname",
        "ip_address",
        "operating_system",
    ]
    enabled = await client.patch(
        f"/api/v1/inventory/connectors/{connector_id}",
        headers=admin_headers,
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    queued = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/runs",
        headers={**admin_headers, "Idempotency-Key": "csv-quarterly"},
    )
    assert queued.status_code == 202, queued.text
    assert await runner.run_worker_once(get_settings(), "csv-worker") is True
    db_session.expire_all()
    task = await db_session.get(BackgroundTask, uuid.UUID(queued.json()["id"]))
    assert task is not None and task.status == BackgroundTaskStatus.COMPLETED
    assert source.decode() not in str(task.payload_json)
    run = await db_session.scalar(
        select(ConnectorRun).where(ConnectorRun.connector_id == connector_id)
    )
    assert run is not None and run.observations_created == 2
    observations = list(
        (
            await db_session.execute(
                select(AssetObservation).where(AssetObservation.run_id == run.id)
            )
        ).scalars()
    )
    assert {row.source_record_id for row in observations} == {"asset-1", "asset-2"}
    assert all("encrypted_source_data" not in str(row.attributes_json) for row in observations)

    exported = await client.get("/api/v1/portability/export", headers=admin_headers)
    assert exported.status_code == 200, exported.text
    assert exported.json()["inventory_connectors"][0]["has_source_data"] is True
    assert source.decode() not in exported.text
    assert "encrypted_source_data" not in exported.text

    cleared = await client.delete(
        f"/api/v1/inventory/connectors/{connector_id}/csv", headers=admin_headers
    )
    assert cleared.status_code == 200
    assert cleared.json()["has_source_data"] is False
    assert cleared.json()["enabled"] is False
    actions = set(
        (
            await db_session.execute(
                select(AuditEvent.action).where(
                    AuditEvent.organization_id == organization_id,
                    AuditEvent.target_id == str(connector_id),
                )
            )
        ).scalars()
    )
    assert {
        "inventory_connector.csv_uploaded",
        "inventory_connector.csv_cleared",
        "inventory_connector.tested",
    } <= actions


async def test_csv_upload_rejects_unknown_mapping_and_non_csv_connector(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = Site(
        organization_id=organization.id,
        name="CSV rejects",
        code=f"CSVR-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.commit()
    created = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Mapped CSV",
            "connector_type": "csv",
            "config": {
                "source_id_field": "missing",
                "identifier_fields": ["hostname=hostname"],
            },
        },
    )
    rejected = await client.put(
        f"/api/v1/inventory/connectors/{created.json()['id']}/csv",
        headers={**admin_headers, "Content-Type": "text/csv"},
        content=b"id,hostname\n1,host-1\n",
    )
    assert rejected.status_code == 422
    assert "unknown column" in rejected.json()["detail"]

    oversized = await client.put(
        f"/api/v1/inventory/connectors/{created.json()['id']}/csv",
        headers={
            **admin_headers,
            "Content-Type": "text/csv",
            "Content-Length": str(5 * 1024 * 1024 + 1),
        },
        content=b"id,hostname\n1,host-1\n",
    )
    assert oversized.status_code == 413

    secret_mapping = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Secret-shaped CSV mapping",
            "connector_type": "csv",
            "config": {
                "source_id_field": "id",
                "identifier_fields": ["hostname=hostname"],
                "attribute_fields": ["password=password"],
            },
        },
    )
    secret_rejected = await client.put(
        f"/api/v1/inventory/connectors/{secret_mapping.json()['id']}/csv",
        headers={**admin_headers, "Content-Type": "text/csv"},
        content=b"id,hostname,password\n1,host-1,do-not-store\n",
    )
    assert secret_rejected.status_code == 422
    assert "secret-shaped" in secret_rejected.json()["detail"]
    denied = await client.put(
        f"/api/v1/inventory/connectors/{created.json()['id']}/csv",
        headers={**viewer_headers, "Content-Type": "text/csv"},
        content=b"id,hostname\n1,host-1\n",
    )
    assert denied.status_code == 403

    generic = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Not CSV",
            "connector_type": "generic_api",
            "base_url": "https://inventory.example.test",
            "config": {"identifier_fields": ["hostname=hostname"]},
        },
    )
    wrong_type = await client.put(
        f"/api/v1/inventory/connectors/{generic.json()['id']}/csv",
        headers={**admin_headers, "Content-Type": "text/csv"},
        content=b"id,hostname\n1,host-1\n",
    )
    assert wrong_type.status_code == 409

    foreign = Organization(name="Foreign CSV", slug=f"foreign-csv-{uuid.uuid4().hex[:6]}")
    db_session.add(foreign)
    await db_session.flush()
    foreign_site = Site(
        organization_id=foreign.id,
        name="Foreign CSV",
        code=f"FC-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    db_session.add(foreign_site)
    await db_session.flush()
    foreign_connector = InventoryConnector(
        organization_id=foreign.id,
        site_id=foreign_site.id,
        name="Foreign CSV",
        connector_type=PassiveConnectorType.CSV,
        config_json={},
    )
    db_session.add(foreign_connector)
    await db_session.commit()
    hidden = await client.put(
        f"/api/v1/inventory/connectors/{foreign_connector.id}/csv",
        headers={**admin_headers, "Content-Type": "text/csv"},
        content=b"id,hostname\n1,host-1\n",
    )
    assert hidden.status_code == 404

    openapi = (await client.get("/openapi.json")).json()
    source_path = openapi["paths"]["/api/v1/inventory/connectors/{connector_id}/csv"]
    assert {"put", "delete"} <= set(source_path)
