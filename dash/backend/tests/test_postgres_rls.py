"""PostgreSQL-only release gate for runtime-role tenant isolation."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest
from app.core.config import Settings, get_settings
from app.db.session import set_maintenance_context, set_tenant_context
from app.models.asset import Asset, AssetIdentifier
from app.models.enums import (
    AssetStatus,
    AssetType,
    BackgroundTaskStatus,
    ConnectorRunStatus,
    IdentifierType,
    PassiveConnectorType,
)
from app.models.passive_inventory import AssetObservation, ConnectorRun, InventoryConnector
from app.models.site import Site
from app.services import background_tasks, passive_inventory, reconciliation
from app.services.bootstrap import run_bootstrap
from app.services.passive_inventory import NormalizedObservation
from sqlalchemy import func, literal, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

POSTGRES_URL = os.getenv("VULNA_POSTGRES_RLS_TEST_URL")

pytestmark = [
    pytest.mark.release_gate,
    pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL RLS test URL is not configured"),
]


class _PostgresInventoryAdapter:
    async def collect(
        self,
        connector: InventoryConnector,
        secret: str | None,
        *,
        cursor: dict[str, object],
        source_data: bytes | None,
    ) -> tuple[list[NormalizedObservation], dict[str, object]]:
        del connector, secret, cursor, source_data
        return (
            [
                NormalizedObservation(
                    source_record_id="postgres-failure-observation",
                    observed_at=datetime.now(UTC),
                    identifiers=[{"type": "hostname", "value": "failure.example.test"}],
                    attributes={"canonical_name": "failure.example.test"},
                )
            ],
            {},
        )


async def test_postgres_single_host_bootstrap_enters_default_tenant(tmp_path: Path) -> None:
    assert POSTGRES_URL is not None
    unique = uuid.uuid4().hex
    async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(async_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        default_org_name="RLS Bootstrap Organization",
        default_org_slug=f"rls-bootstrap-{unique}",
        default_site_name="RLS Bootstrap Site",
        default_site_code=f"RLS-{unique[:8]}",
        bootstrap_local_scout=True,
        bootstrap_dir=str(tmp_path),
        ca_key_path=str(tmp_path / "ca-key.pem"),
        ca_cert_path=str(tmp_path / "ca-cert.pem"),
    )
    try:
        async with factory() as session:
            await run_bootstrap(session, settings)
            assert session.info["vulna_organization_id"] is not None
            site = await session.scalar(select(Site).where(Site.code == settings.default_site_code))
            assert site is not None
            assert site.organization_id == session.info["vulna_organization_id"]
            await session.rollback()
    finally:
        await engine.dispose()


async def test_postgres_reconciliation_deduplicates_assets_with_json_columns() -> None:
    assert POSTGRES_URL is not None
    organization_id = uuid.uuid4()
    site_id = uuid.uuid4()
    owner = await asyncpg.connect(POSTGRES_URL)
    try:
        await owner.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES ($1, 'Reconciliation PostgreSQL', $2, 'UTC', '{}', '{}')
            """,
            organization_id,
            f"reconciliation-postgres-{organization_id.hex}",
        )
        await owner.execute(
            """
            INSERT INTO sites (id, organization_id, name, code, timezone, tags)
            VALUES ($1, $2, 'Reconciliation Site', $3, 'UTC', '[]')
            """,
            site_id,
            organization_id,
            f"REC-{site_id.hex[:8]}",
        )

        async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        engine = create_async_engine(async_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                await set_tenant_context(session, organization_id)
                connector = InventoryConnector(
                    organization_id=organization_id,
                    site_id=site_id,
                    name="PostgreSQL reconciliation",
                    connector_type=PassiveConnectorType.CSV,
                    config_json={},
                )
                session.add(connector)
                await session.flush()
                run = ConnectorRun(
                    organization_id=organization_id,
                    site_id=site_id,
                    connector_id=connector.id,
                    status=ConnectorRunStatus.RUNNING,
                )
                asset = Asset(
                    organization_id=organization_id,
                    site_id=site_id,
                    canonical_name="existing.example.test",
                    asset_type=AssetType.SERVER,
                    status=AssetStatus.ACTIVE,
                    metadata_json={"source": "postgres-regression"},
                )
                session.add_all([run, asset])
                await session.flush()
                session.add_all(
                    [
                        AssetIdentifier(
                            asset_id=asset.id,
                            identifier_type=IdentifierType.HOSTNAME,
                            identifier_value="existing.example.test",
                            confidence=75,
                        ),
                        AssetIdentifier(
                            asset_id=asset.id,
                            identifier_type=IdentifierType.IP_ADDRESS,
                            identifier_value="192.0.2.25",
                            confidence=90,
                        ),
                    ]
                )
                observation = AssetObservation(
                    organization_id=organization_id,
                    site_id=site_id,
                    connector_id=connector.id,
                    run_id=run.id,
                    source_record_id="postgres-json-distinct",
                    observed_at=datetime.now(UTC),
                    identifiers_json=[
                        {"type": "hostname", "value": "existing.example.test"},
                        {"type": "ip_address", "value": "192.0.2.25"},
                    ],
                    attributes_json={"canonical_name": "existing.example.test"},
                    payload_hash="c" * 64,
                )
                session.add(observation)
                await session.flush()

                candidates = await reconciliation.reconcile_observation(session, observation)

                assert len(candidates) == 1
                assert candidates[0].candidate_asset_id == asset.id
                await session.rollback()
        finally:
            await engine.dispose()
    finally:
        await owner.execute("DELETE FROM organizations WHERE id = $1", organization_id)
        await owner.close()


async def test_postgres_connector_failure_survives_statement_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    organization_id = uuid.uuid4()
    site_id = uuid.uuid4()
    owner = await asyncpg.connect(POSTGRES_URL)
    try:
        await owner.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES ($1, 'Connector Failure PostgreSQL', $2, 'UTC', '{}', '{}')
            """,
            organization_id,
            f"connector-failure-postgres-{organization_id.hex}",
        )
        await owner.execute(
            """
            INSERT INTO sites (id, organization_id, name, code, timezone, tags)
            VALUES ($1, $2, 'Connector Failure Site', $3, 'UTC', '[]')
            """,
            site_id,
            organization_id,
            f"FAIL-{site_id.hex[:8]}",
        )

        async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        engine = create_async_engine(async_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                await set_tenant_context(session, organization_id)
                connector = InventoryConnector(
                    organization_id=organization_id,
                    site_id=site_id,
                    name="PostgreSQL failing connector",
                    connector_type=PassiveConnectorType.AWS,
                    config_json={},
                    enabled=True,
                    successful_test_at=datetime.now(UTC),
                )
                session.add(connector)
                await session.flush()
                run = ConnectorRun(
                    organization_id=organization_id,
                    site_id=site_id,
                    connector_id=connector.id,
                    status=ConnectorRunStatus.QUEUED,
                )
                session.add(run)
                await session.flush()
                task, created = await background_tasks.enqueue_task(
                    session,
                    task_type="inventory.collect",
                    idempotency_key=f"postgres-connector-failure:{run.id}",
                    payload={"run_id": str(run.id)},
                    organization_id=organization_id,
                )
                assert created is True
                task.status = BackgroundTaskStatus.RUNNING
                task.attempts = 1
                await session.commit()

                async def abort_reconciliation(
                    failing_session: AsyncSession,
                    observation: AssetObservation,
                    *,
                    now: datetime | None = None,
                ) -> list[object]:
                    del observation, now
                    await failing_session.execute(text("SELECT 1 / 0"))
                    return []

                monkeypatch.setitem(
                    passive_inventory.ADAPTERS,
                    PassiveConnectorType.AWS,
                    _PostgresInventoryAdapter(),
                )
                monkeypatch.setattr(
                    reconciliation,
                    "reconcile_observation",
                    abort_reconciliation,
                )
                await set_tenant_context(session, organization_id)
                with pytest.raises(background_tasks.PersistedTaskFailure):
                    await passive_inventory.execute_connector_task(
                        session,
                        task,
                        get_settings(),
                    )
                await session.commit()
                session.expire_all()

                stored_run = await session.get(ConnectorRun, run.id)
                assert stored_run is not None
                assert stored_run.status == ConnectorRunStatus.FAILED
                assert stored_run.finished_at is not None
                assert stored_run.error is not None and "DivisionByZeroError" in stored_run.error
                assert (
                    await session.scalar(
                        select(func.count())
                        .select_from(AssetObservation)
                        .where(AssetObservation.run_id == run.id)
                    )
                    == 0
                )
        finally:
            await engine.dispose()
    finally:
        await owner.execute("DELETE FROM organizations WHERE id = $1", organization_id)
        await owner.close()


async def test_postgres_runtime_role_fails_closed_and_isolates_tenants() -> None:
    assert POSTGRES_URL is not None
    organization_one = uuid.uuid4()
    organization_two = uuid.uuid4()
    site_one = uuid.uuid4()
    site_two = uuid.uuid4()

    owner = await asyncpg.connect(POSTGRES_URL)
    try:
        await owner.execute(
            """
            INSERT INTO organizations
                (id, name, slug, default_timezone, settings_json, retention_policy_json)
            VALUES ($1, 'RLS Org One', $2, 'UTC', '{}', '{}'),
                   ($3, 'RLS Org Two', $4, 'UTC', '{}', '{}')
            """,
            organization_one,
            f"rls-one-{organization_one.hex}",
            organization_two,
            f"rls-two-{organization_two.hex}",
        )
        await owner.execute(
            """
            INSERT INTO sites (id, organization_id, name, code, timezone, tags)
            VALUES ($1, $2, 'Site One', 'ONE', 'UTC', '[]'),
                   ($3, $4, 'Site Two', 'TWO', 'UTC', '[]')
            """,
            site_one,
            organization_one,
            site_two,
            organization_two,
        )

        async_url = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        engine = create_async_engine(async_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                # The restricted runtime role is entered automatically. Without
                # an organization setting, protected tables expose no rows.
                assert await session.scalar(select(func.count()).select_from(Site)) == 0
                await set_tenant_context(session, organization_one)
                assert await session.scalar(select(func.count()).select_from(Site)) == 1
                assert await session.get(Site, site_two) is None
                await session.commit()
                # SET LOCAL is restored from session.info after every commit.
                assert await session.scalar(select(func.count()).select_from(Site)) == 1

            async with factory() as session:
                await set_tenant_context(session, organization_one)
                session.add(
                    Site(
                        id=uuid.uuid4(),
                        organization_id=organization_two,
                        name="Cross-tenant write",
                        code="DENY",
                        timezone="UTC",
                    )
                )
                with pytest.raises(DBAPIError):
                    await session.flush()

            async with factory() as session:
                # Worker sessions may discover a global maintenance task before
                # switching roles, so exercise the in-transaction transition.
                assert await session.scalar(select(literal(1))) == 1
                await set_maintenance_context(session)
                assert await session.scalar(select(func.count()).select_from(Site)) == 2
        finally:
            await engine.dispose()

        role = await owner.fetchrow(
            """
            SELECT rolsuper, rolbypassrls, rolcanlogin
              FROM pg_roles
             WHERE rolname = 'vulna_runtime'
            """
        )
        assert role is not None
        assert tuple(role) == (False, False, False)
        assert (
            await owner.fetchval(
                "SELECT COUNT(*) FROM pg_policies WHERE policyname = 'vulna_tenant_isolation'"
            )
            >= 40
        )
    finally:
        await owner.execute(
            "DELETE FROM organizations WHERE id = ANY($1::uuid[])",
            [organization_one, organization_two],
        )
        await owner.close()
