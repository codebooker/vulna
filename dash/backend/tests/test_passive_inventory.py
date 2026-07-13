"""Phase 44 core passive inventory, reconciliation, analytics, and reporting tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from app.core.config import get_settings
from app.models.asset import Asset, AssetIdentifier
from app.models.audit import AuditEvent
from app.models.background_task import BackgroundTask
from app.models.enums import (
    AssetStatus,
    AssetType,
    BackgroundTaskStatus,
    FindingStatus,
    FindingType,
    IdentifierType,
    PassiveConnectorType,
    ReconciliationStatus,
    Severity,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.passive_inventory import (
    AssetObservation,
    ConnectorRun,
    InventoryConnector,
    ReportTemplate,
    ReportTemplateRun,
)
from app.models.site import Site
from app.services import passive_inventory, reconciliation
from app.services.passive_inventory import NormalizedObservation
from app.services.reports import pdf
from app.tasks import runner
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.release_gate


class FakeInventoryAdapter:
    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, object]:
        assert secret == "inventory-secret-never-returned"
        assert source_data is None
        return {"source": connector.connector_type.value, "read_only": True}

    async def collect(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, object],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], dict[str, object]]:
        assert secret == "inventory-secret-never-returned"
        assert cursor == {}
        assert source_data is None
        return (
            [
                NormalizedObservation(
                    source_record_id="source-001",
                    observed_at=datetime.now(UTC),
                    identifiers=[{"type": "cloud_instance_id", "value": "i-phase44"}],
                    attributes={
                        "canonical_name": "passive-host",
                        "asset_type": "cloud_instance",
                        "operating_system": "Linux",
                    },
                )
            ],
            {"next": "cursor-2"},
        )


class LeakyInventoryAdapter(FakeInventoryAdapter):
    async def test(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        source_data: bytes | None,
    ) -> dict[str, object]:
        del connector, source_data
        return {"detail": f"provider echoed {secret}"}


async def _site(session: AsyncSession, organization: Organization, code: str = "P44") -> Site:
    site = Site(
        organization_id=organization.id,
        name="Phase 44",
        code=f"{code}-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    session.add(site)
    await session.commit()
    return site


@pytest.mark.parametrize(
    ("connector_type", "base_url", "config", "secret"),
    [
        (
            "proxmox",
            "https://pve.example.test:8006",
            {
                "api_identity": "vulna@pve!inventory",
                "allow_private": True,
                "include_nodes": True,
                "include_guests": True,
                "include_templates": False,
            },
            "11111111-1111-4111-8111-111111111111",
        ),
        (
            "xcp_ng",
            "https://xo.example.test",
            {"allow_private": True, "include_hosts": True, "include_vms": True},
            "xoa_test_authentication_value_12345",
        ),
        (
            "aws",
            None,
            {
                "partition": "aws",
                "regions": ["us-east-1", "us-west-2"],
                "expected_account_id": "123456789012",
                "include_terminated": False,
            },
            json.dumps(
                {
                    "access_key_id": "EXAMPLEACCESSKEY01",
                    "secret_access_key": "example-secret-access-value",
                }
            ),
        ),
        (
            "azure",
            None,
            {
                "tenant_id": "22222222-2222-4222-8222-222222222222",
                "client_id": "33333333-3333-4333-8333-333333333333",
                "subscription_ids": ["44444444-4444-4444-8444-444444444444"],
                "cloud": "global",
                "include_scale_set_instances": True,
            },
            "example-azure-client-value",
        ),
        (
            "google_cloud",
            None,
            {"project_ids": ["example-project-1"]},
            '{"type":"service_account","private_key":"one-way"}',
        ),
    ],
)
async def test_remaining_provider_configs_cross_the_public_one_way_secret_boundary(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
    connector_type: str,
    base_url: str | None,
    config: dict[str, object],
    secret: str,
) -> None:
    site = await _site(db_session, organization, code="PROVIDER")
    response = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": f"{connector_type} inventory",
            "connector_type": connector_type,
            "base_url": base_url,
            "config": config,
            "secret": secret,
            "interval_minutes": 1440,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["config_json"] == config
    assert response.json()["has_secret"] is True
    assert secret not in response.text


async def test_connector_secret_worker_observation_and_audit(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site = await _site(db_session, organization)
    organization_id = organization.id
    fake = FakeInventoryAdapter()
    monkeypatch.setitem(passive_inventory.ADAPTERS, PassiveConnectorType.AWS, fake)
    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)
    secret = "inventory-secret-never-returned"
    created = await client.post(
        "/api/v1/inventory/connectors",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Cloud inventory",
            "connector_type": "aws",
            "base_url": "https://inventory.example.test",
            "config": {"region": "us-east-1"},
            "secret": secret,
            "interval_minutes": 60,
        },
    )
    assert created.status_code == 201, created.text
    connector_id = uuid.UUID(created.json()["id"])
    assert created.json()["has_secret"] is True
    assert secret not in created.text
    assert "encrypted_secret" not in created.json()
    stored = await db_session.get(InventoryConnector, connector_id)
    assert stored is not None and secret not in str(stored.encrypted_secret)

    monkeypatch.setitem(
        passive_inventory.ADAPTERS,
        PassiveConnectorType.AWS,
        LeakyInventoryAdapter(),
    )
    rejected_leak = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/test", headers=admin_headers
    )
    assert rejected_leak.status_code == 200
    assert rejected_leak.json()["succeeded"] is False
    assert secret not in rejected_leak.text

    monkeypatch.setitem(passive_inventory.ADAPTERS, PassiveConnectorType.AWS, fake)
    tested = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/test", headers=admin_headers
    )
    assert tested.status_code == 200 and tested.json()["succeeded"] is True
    unsafe_enable = await client.patch(
        f"/api/v1/inventory/connectors/{connector_id}",
        headers=admin_headers,
        json={"config": {"region": "us-west-2"}, "enabled": True},
    )
    assert unsafe_enable.status_code == 409
    enabled = await client.patch(
        f"/api/v1/inventory/connectors/{connector_id}",
        headers=admin_headers,
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    queued = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/runs",
        headers={**admin_headers, "Idempotency-Key": "phase44-collect"},
    )
    replay = await client.post(
        f"/api/v1/inventory/connectors/{connector_id}/runs",
        headers={**admin_headers, "Idempotency-Key": "phase44-collect"},
    )
    assert queued.status_code == 202, queued.text
    assert replay.status_code == 202 and replay.json()["id"] == queued.json()["id"]
    assert await runner.run_worker_once(get_settings(), "phase44-worker") is True
    db_session.expire_all()
    task = await db_session.get(BackgroundTask, uuid.UUID(queued.json()["id"]))
    assert task is not None and task.status == BackgroundTaskStatus.COMPLETED
    assert task.payload_json.keys() == {"run_id"}
    assert secret not in str(task.payload_json)
    run = await db_session.scalar(
        select(ConnectorRun).where(ConnectorRun.connector_id == connector_id)
    )
    assert run is not None and run.observations_created == 1
    observation = await db_session.scalar(
        select(AssetObservation).where(AssetObservation.run_id == run.id)
    )
    assert observation is not None and observation.matched_asset_id is not None
    assert observation.identifiers_json == [{"type": "cloud_instance_id", "value": "i-phase44"}]
    assert secret not in str(observation.attributes_json)
    actions = set(
        (
            await db_session.execute(
                select(AuditEvent.action).where(AuditEvent.organization_id == organization_id)
            )
        ).scalars()
    )
    assert {
        "inventory_connector.created",
        "inventory_connector.tested",
        "inventory_connector.updated",
        "inventory_connector.run_queued",
    } <= actions


async def test_reconciliation_thresholds_conflicts_and_reversible_split(
    db_session: AsyncSession, organization: Organization
) -> None:
    site = await _site(db_session, organization, "REC")
    connector = InventoryConnector(
        organization_id=organization.id,
        site_id=site.id,
        name="Reconciliation source",
        connector_type=PassiveConnectorType.CSV,
        config_json={},
    )
    db_session.add(connector)
    await db_session.flush()
    run = ConnectorRun(
        organization_id=organization.id,
        site_id=site.id,
        connector_id=connector.id,
        status="running",
    )
    db_session.add(run)
    await db_session.flush()
    asset = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="existing",
        asset_type=AssetType.SERVER,
        status=AssetStatus.ACTIVE,
    )
    db_session.add(asset)
    await db_session.flush()
    db_session.add_all(
        [
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type=IdentifierType.MAC_ADDRESS,
                identifier_value="AA:BB:CC:DD:EE:FF",
                confidence=95,
            ),
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type=IdentifierType.HOSTNAME,
                identifier_value="existing",
                confidence=75,
            ),
        ]
    )
    await db_session.flush()
    observation = AssetObservation(
        organization_id=organization.id,
        site_id=site.id,
        connector_id=connector.id,
        run_id=run.id,
        source_record_id="auto",
        observed_at=datetime.now(UTC),
        identifiers_json=[
            {"type": "mac_address", "value": "aa:bb:cc:dd:ee:ff"},
            {"type": "hostname", "value": "new-alias"},
        ],
        attributes_json={"canonical_name": "auto"},
        payload_hash="a" * 64,
    )
    db_session.add(observation)
    await db_session.flush()
    candidates = await reconciliation.reconcile_observation(db_session, observation)
    assert len(candidates) == 1
    assert candidates[0].score == 95
    assert candidates[0].status == ReconciliationStatus.AUTO_MERGED
    assert observation.matched_asset_id == asset.id
    assert candidates[0].merge_snapshot_json["version"] == 1
    assert await db_session.scalar(
        select(AssetIdentifier.id).where(
            AssetIdentifier.asset_id == asset.id,
            AssetIdentifier.identifier_value == "new-alias",
        )
    )

    split_asset = await reconciliation.split_candidate(
        db_session,
        candidates[0],
        actor_user_id=uuid.uuid4(),
        now=datetime.now(UTC),
    )
    assert split_asset.id != asset.id
    assert observation.matched_asset_id == split_asset.id
    assert candidates[0].status == ReconciliationStatus.SPLIT
    assert not await db_session.scalar(
        select(AssetIdentifier.id).where(
            AssetIdentifier.asset_id == asset.id,
            AssetIdentifier.identifier_value == "new-alias",
        )
    )
    assert await db_session.scalar(
        select(AssetIdentifier.id).where(
            AssetIdentifier.asset_id == split_asset.id,
            AssetIdentifier.identifier_value == "new-alias",
        )
    )

    conflict = AssetObservation(
        organization_id=organization.id,
        site_id=site.id,
        connector_id=connector.id,
        run_id=run.id,
        source_record_id="review-conflict",
        observed_at=datetime.now(UTC),
        identifiers_json=[
            {"type": "hostname", "value": "existing"},
            {"type": "mac_address", "value": "00:11:22:33:44:55"},
        ],
        attributes_json={"canonical_name": "review"},
        payload_hash="b" * 64,
    )
    db_session.add(conflict)
    await db_session.flush()
    review = await reconciliation.reconcile_observation(db_session, conflict)
    assert review[0].score == 75
    assert review[0].status == ReconciliationStatus.PENDING
    assert review[0].conflicts_json[0]["identifier_type"] == "mac_address"
    with pytest.raises(reconciliation.ReconciliationError, match="conflicting"):
        await reconciliation.merge_candidate(
            db_session,
            review[0],
            status=ReconciliationStatus.APPROVED,
            actor_user_id=uuid.uuid4(),
            now=datetime.now(UTC),
        )


async def test_scoped_analytics_handles_more_than_500_findings(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = await _site(db_session, organization, "BIG")
    db_session.add_all(
        [
            Finding(
                organization_id=organization.id,
                site_id=site.id,
                scanner_name="scale-test",
                canonical_finding_key=f"phase44-{index:04d}",
                finding_type=FindingType.VULNERABILITY,
                title=f"Finding {index}",
                severity=Severity.HIGH if index % 2 else Severity.MEDIUM,
                status=FindingStatus.NEW,
            )
            for index in range(550)
        ]
    )
    await db_session.commit()
    first = await client.get("/api/v1/analytics/dashboard", headers=admin_headers)
    assert first.status_code == 200, first.text
    assert first.json()["findings"]["total"] == 550
    assert first.json()["findings"]["open"] == 550
    assert first.headers["cache-control"] == "private, max-age=60"
    assert first.headers["vary"] == "Authorization"
    second = await client.get("/api/v1/analytics/dashboard", headers=admin_headers)
    assert second.json()["cache"] == "hit"


async def test_report_template_password_portability_and_pdf_encryption(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = await _site(db_session, organization, "RPT")
    password = "phase44-pdf-password"
    created = await client.post(
        "/api/v1/report-templates",
        headers=admin_headers,
        json={
            "site_id": str(site.id),
            "name": "Executive weekly",
            "report_types": ["executive_pdf", "findings_csv"],
            "sections": ["summary", "findings"],
            "filters": {},
            "redaction": {"fields": ["network_identifiers"]},
            "branding": {"display_name": "Security program", "primary_color": "#2255aa"},
            "export_password": password,
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["has_export_password"] is True
    assert password not in created.text
    template = await db_session.get(ReportTemplate, uuid.UUID(created.json()["id"]))
    assert template is not None and password not in str(template.encrypted_export_password)
    queued = await client.post(
        f"/api/v1/report-templates/{template.id}/runs",
        headers={**admin_headers, "Idempotency-Key": "phase44-report-snapshot"},
    )
    assert queued.status_code == 202, queued.text
    run = await db_session.scalar(
        select(ReportTemplateRun).where(ReportTemplateRun.template_id == template.id)
    )
    assert run is not None
    assert run.parameters_json["name"] == "Executive weekly"
    assert run.parameters_json["report_types"] == ["executive_pdf", "findings_csv"]
    assert password not in str(run.parameters_json)
    assert password not in str(run.encrypted_export_password)

    changed = await client.patch(
        f"/api/v1/report-templates/{template.id}",
        headers=admin_headers,
        json={"name": "Executive monthly", "report_types": ["findings_csv"]},
    )
    assert changed.status_code == 200, changed.text
    assert run.parameters_json["name"] == "Executive weekly"
    assert run.parameters_json["report_types"] == ["executive_pdf", "findings_csv"]

    exported = await client.get("/api/v1/portability/export", headers=admin_headers)
    assert exported.status_code == 200, exported.text
    bundle = exported.json()
    assert bundle["schema_version"] == "8"
    assert bundle["report_templates"][0]["has_export_password"] is True
    assert password not in exported.text
    assert "encrypted_export_password" not in exported.text

    document = pdf.executive_pdf(
        {
            "organization": {"name": "Test"},
            "summary": {"severity_counts": {}, "finding_count": 0, "asset_count": 0},
            "scan_job": {},
            "findings": [],
            "_pdf_user_password": password,
        }
    )
    assert document.startswith(b"%PDF")
    assert b"/Encrypt" in document
    assert password.encode() not in document


async def test_cross_organization_denial_openapi_and_truthful_capability(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    foreign = Organization(name="Foreign", slug=f"foreign-p44-{uuid.uuid4().hex[:6]}")
    db_session.add(foreign)
    await db_session.flush()
    site = Site(
        organization_id=foreign.id,
        name="Foreign",
        code=f"FOREIGN-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.flush()
    connector = InventoryConnector(
        organization_id=foreign.id,
        site_id=site.id,
        name="Foreign connector",
        connector_type=PassiveConnectorType.DNS,
        config_json={},
    )
    db_session.add(connector)
    await db_session.commit()
    hidden = await client.post(
        f"/api/v1/inventory/connectors/{connector.id}/test", headers=admin_headers
    )
    assert hidden.status_code == 404

    viewer = await client.get("/api/v1/system/capabilities")
    phase44 = next(
        item for item in viewer.json()["capabilities"] if item["key"] == "passive_inventory"
    )
    assert phase44 == {
        "key": "passive_inventory",
        "name": "Passive inventory connectors, analytics, and report builder",
        "status": "available",
        "production_ready": False,
    }
    openapi = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/inventory/connectors",
        "/api/v1/inventory/reconciliation/{candidate_id}/decision",
        "/api/v1/analytics/dashboard",
        "/api/v1/analytics/history",
        "/api/v1/report-templates",
        "/api/v1/report-templates/{template_id}/comparison",
    ):
        assert path in openapi["paths"]
