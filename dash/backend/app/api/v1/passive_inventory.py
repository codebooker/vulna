"""Passive inventory connector, observation, lifecycle, and reconciliation APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentUser,
    require_permission,
    require_step_up_permission,
)
from app.auth.site_scope import require_site_access, site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import InventoryAssetState, ReconciliationStatus
from app.models.passive_inventory import (
    AssetInventoryState,
    AssetObservation,
    ConnectorRun,
    InventoryConnector,
    InventoryLifecycleEvent,
    ReconciliationCandidate,
)
from app.schemas.background_task import BackgroundTaskRead
from app.schemas.passive_inventory import (
    AssetInventoryStateRead,
    AssetInventoryStateUpdate,
    AssetObservationRead,
    ConnectorRunRead,
    InventoryConnectorCreate,
    InventoryConnectorRead,
    InventoryConnectorTestRead,
    InventoryConnectorUpdate,
    ReconciliationCandidateRead,
    ReconciliationDecision,
)
from app.services import passive_inventory, reconciliation
from app.services.audit import record_audit

router = APIRouter(prefix="/inventory", tags=["passive inventory"])


async def _owned_connector(
    session: AsyncSession,
    connector_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> InventoryConnector:
    connector = await session.scalar(
        select(InventoryConnector).where(
            InventoryConnector.id == connector_id,
            InventoryConnector.organization_id == organization_id,
        )
    )
    if connector is None:
        raise HTTPException(status_code=404, detail="Inventory connector not found")
    return connector


@router.get(
    "/connectors",
    response_model=list[InventoryConnectorRead],
    dependencies=[Depends(require_permission("connectors.read"))],
)
async def list_connectors(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[InventoryConnectorRead]:
    rows = (
        (
            await session.execute(
                select(InventoryConnector)
                .where(
                    InventoryConnector.organization_id == actor.organization_id,
                    site_scope_clause(
                        actor, InventoryConnector.site_id, permission_key="connectors.read"
                    ),
                )
                .order_by(InventoryConnector.name)
            )
        )
        .scalars()
        .all()
    )
    return [InventoryConnectorRead.from_model(row) for row in rows]


@router.post(
    "/connectors",
    response_model=InventoryConnectorRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    payload: InventoryConnectorCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("connectors.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> InventoryConnectorRead:
    actor = identity.user
    await require_site_access(
        session,
        actor,
        payload.site_id,
        not_found_detail="Site not found",
        permission_key="connectors.manage",
    )
    duplicate = await session.scalar(
        select(InventoryConnector.id).where(
            InventoryConnector.organization_id == actor.organization_id,
            InventoryConnector.name == payload.name.strip(),
        )
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="Inventory connector name already exists")
    try:
        config = passive_inventory.validate_public_config(payload.config)
        base_url = passive_inventory.validate_base_url(
            str(payload.base_url) if payload.base_url else None
        )
        encrypted = (
            passive_inventory.encrypt_connector_secret(settings, payload.secret)
            if payload.secret
            else None
        )
    except passive_inventory.InventoryConnectorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    connector = InventoryConnector(
        organization_id=actor.organization_id,
        site_id=payload.site_id,
        name=payload.name.strip(),
        connector_type=payload.connector_type,
        base_url=base_url,
        config_json=config,
        encrypted_secret=encrypted,
        enabled=False,
        interval_minutes=payload.interval_minutes,
        created_by_user_id=actor.id,
    )
    session.add(connector)
    await session.flush()
    record_audit(
        session,
        action="inventory_connector.created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="inventory_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "connector_type": connector.connector_type.value,
            "site_id": str(connector.site_id),
            "has_secret": bool(encrypted),
        },
    )
    return InventoryConnectorRead.from_model(connector)


@router.patch("/connectors/{connector_id}", response_model=InventoryConnectorRead)
async def update_connector(
    connector_id: uuid.UUID,
    payload: InventoryConnectorUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("connectors.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> InventoryConnectorRead:
    actor = identity.user
    connector = await _owned_connector(session, connector_id, actor.organization_id)
    await require_site_access(
        session,
        actor,
        connector.site_id,
        not_found_detail="Inventory connector not found",
        permission_key="connectors.manage",
    )
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        name = str(changes["name"]).strip()
        duplicate = await session.scalar(
            select(InventoryConnector.id).where(
                InventoryConnector.organization_id == actor.organization_id,
                InventoryConnector.name == name,
                InventoryConnector.id != connector.id,
            )
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="Inventory connector name already exists")
        connector.name = name
    try:
        if "base_url" in changes:
            connector.base_url = passive_inventory.validate_base_url(
                str(changes["base_url"]) if changes["base_url"] else None
            )
            connector.successful_test_at = None
            connector.enabled = False
        if "config" in changes:
            connector.config_json = passive_inventory.validate_public_config(changes["config"])
            connector.successful_test_at = None
            connector.enabled = False
        if "secret" in changes:
            connector.encrypted_secret = passive_inventory.encrypt_connector_secret(
                settings, str(changes["secret"])
            )
            connector.successful_test_at = None
            connector.enabled = False
        elif changes.get("clear_secret"):
            connector.encrypted_secret = None
            connector.successful_test_at = None
            connector.enabled = False
    except passive_inventory.InventoryConnectorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if changes.get("enabled") is True and connector.successful_test_at is None:
        raise HTTPException(status_code=409, detail="Test the connector before enabling it")
    for field in ("enabled", "interval_minutes"):
        if field in changes:
            setattr(connector, field, changes[field])
    if connector.enabled and connector.interval_minutes and connector.next_run_at is None:
        connector.next_run_at = datetime.now(UTC) + timedelta(minutes=connector.interval_minutes)
    record_audit(
        session,
        action="inventory_connector.updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="inventory_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "changed_fields": sorted(payload.model_fields_set),
            "has_secret": bool(connector.encrypted_secret),
        },
    )
    return InventoryConnectorRead.from_model(connector)


@router.post("/connectors/{connector_id}/test", response_model=InventoryConnectorTestRead)
async def test_connector(
    connector_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("connectors.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> InventoryConnectorTestRead:
    actor = identity.user
    connector = await _owned_connector(session, connector_id, actor.organization_id)
    await require_site_access(
        session,
        actor,
        connector.site_id,
        not_found_detail="Inventory connector not found",
        permission_key="connectors.manage",
    )
    tested_at = datetime.now(UTC)
    try:
        metadata = await passive_inventory.test_connector(connector, settings)
    except (passive_inventory.InventoryConnectorError, OSError, ValueError) as exc:
        connector.successful_test_at = None
        connector.enabled = False
        connector.last_test_error = f"{type(exc).__name__}: {exc}"[:1024]
        result = InventoryConnectorTestRead(
            succeeded=False, tested_at=tested_at, error=connector.last_test_error
        )
    else:
        connector.successful_test_at = tested_at
        connector.last_test_error = None
        result = InventoryConnectorTestRead(succeeded=True, tested_at=tested_at, metadata=metadata)
    record_audit(
        session,
        action="inventory_connector.tested",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="inventory_connector",
        target_id=connector.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"succeeded": result.succeeded},
    )
    return result


@router.post(
    "/connectors/{connector_id}/runs",
    response_model=BackgroundTaskRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def queue_connector_run(
    connector_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("connectors.run"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", min_length=1, max_length=255)
    ] = None,
) -> BackgroundTaskRead:
    actor = identity.user
    connector = await _owned_connector(session, connector_id, actor.organization_id)
    await require_site_access(
        session,
        actor,
        connector.site_id,
        not_found_detail="Inventory connector not found",
        permission_key="connectors.run",
    )
    if not connector.enabled or connector.successful_test_at is None:
        raise HTTPException(status_code=409, detail="Connector must be tested and enabled")
    run, task, created = await passive_inventory.enqueue_run(
        session,
        connector,
        created_by_user_id=actor.id,
        client_idempotency_key=idempotency_key,
    )
    record_audit(
        session,
        action="inventory_connector.run_queued",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="connector_run",
        target_id=run.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"connector_id": str(connector.id), "idempotent_replay": not created},
    )
    return BackgroundTaskRead.model_validate(task)


@router.get(
    "/runs",
    response_model=list[ConnectorRunRead],
    dependencies=[Depends(require_permission("connectors.read"))],
)
async def list_runs(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ConnectorRunRead]:
    rows = (
        (
            await session.execute(
                select(ConnectorRun)
                .where(
                    ConnectorRun.organization_id == actor.organization_id,
                    site_scope_clause(
                        actor, ConnectorRun.site_id, permission_key="connectors.read"
                    ),
                )
                .order_by(ConnectorRun.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [ConnectorRunRead.model_validate(row) for row in rows]


@router.get(
    "/observations",
    response_model=list[AssetObservationRead],
    dependencies=[Depends(require_permission("reconciliation.read"))],
)
async def list_observations(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[AssetObservationRead]:
    rows = (
        (
            await session.execute(
                select(AssetObservation)
                .where(
                    AssetObservation.organization_id == actor.organization_id,
                    site_scope_clause(
                        actor, AssetObservation.site_id, permission_key="reconciliation.read"
                    ),
                )
                .order_by(AssetObservation.observed_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [AssetObservationRead.model_validate(row) for row in rows]


@router.get(
    "/reconciliation",
    response_model=list[ReconciliationCandidateRead],
    dependencies=[Depends(require_permission("reconciliation.read"))],
)
async def list_reconciliation(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    candidate_status: Annotated[ReconciliationStatus | None, Query(alias="status")] = None,
) -> list[ReconciliationCandidateRead]:
    filters = [
        ReconciliationCandidate.organization_id == actor.organization_id,
        site_scope_clause(
            actor, ReconciliationCandidate.site_id, permission_key="reconciliation.read"
        ),
    ]
    if candidate_status is not None:
        filters.append(ReconciliationCandidate.status == candidate_status)
    rows = (
        (
            await session.execute(
                select(ReconciliationCandidate)
                .where(*filters)
                .order_by(ReconciliationCandidate.score.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return [ReconciliationCandidateRead.model_validate(row) for row in rows]


@router.post(
    "/reconciliation/{candidate_id}/decision",
    response_model=ReconciliationCandidateRead,
)
async def decide_reconciliation(
    candidate_id: uuid.UUID,
    payload: ReconciliationDecision,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("reconciliation.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ReconciliationCandidateRead:
    actor = identity.user
    candidate = await session.scalar(
        select(ReconciliationCandidate).where(
            ReconciliationCandidate.id == candidate_id,
            ReconciliationCandidate.organization_id == actor.organization_id,
            site_scope_clause(
                actor,
                ReconciliationCandidate.site_id,
                permission_key="reconciliation.manage",
            ),
        )
    )
    if candidate is None:
        raise HTTPException(status_code=404, detail="Reconciliation candidate not found")
    now = datetime.now(UTC)
    try:
        if payload.action == "approve":
            await reconciliation.merge_candidate(
                session,
                candidate,
                status=ReconciliationStatus.APPROVED,
                actor_user_id=actor.id,
                now=now,
            )
        elif payload.action == "reject":
            await reconciliation.reject_candidate(
                session, candidate, actor_user_id=actor.id, now=now
            )
        else:
            await reconciliation.split_candidate(
                session, candidate, actor_user_id=actor.id, now=now
            )
    except reconciliation.ReconciliationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit(
        session,
        action=f"inventory_reconciliation.{payload.action}",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="reconciliation_candidate",
        target_id=candidate.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "observation_id": str(candidate.observation_id),
            "candidate_asset_id": str(candidate.candidate_asset_id),
            "score": candidate.score,
        },
    )
    return ReconciliationCandidateRead.model_validate(candidate)


@router.get(
    "/states",
    response_model=list[AssetInventoryStateRead],
    dependencies=[Depends(require_permission("assets.read"))],
)
async def list_inventory_states(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[AssetInventoryStateRead]:
    rows = (
        (
            await session.execute(
                select(AssetInventoryState)
                .where(
                    AssetInventoryState.organization_id == actor.organization_id,
                    site_scope_clause(
                        actor, AssetInventoryState.site_id, permission_key="assets.read"
                    ),
                )
                .order_by(AssetInventoryState.updated_at.desc())
                .limit(500)
            )
        )
        .scalars()
        .all()
    )
    return [AssetInventoryStateRead.model_validate(row) for row in rows]


@router.patch("/states/{asset_id}", response_model=AssetInventoryStateRead)
async def update_inventory_state(
    asset_id: uuid.UUID,
    payload: AssetInventoryStateUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("assets.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AssetInventoryStateRead:
    actor = identity.user
    row = await session.scalar(
        select(AssetInventoryState).where(
            AssetInventoryState.asset_id == asset_id,
            AssetInventoryState.organization_id == actor.organization_id,
            site_scope_clause(actor, AssetInventoryState.site_id, permission_key="assets.manage"),
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Inventory state not found")
    previous_state = row.state
    changes = payload.model_dump(exclude_unset=True)
    if "expected" in changes:
        row.expected = bool(changes["expected"])
        if row.expected and row.last_observed_at is None:
            row.state = InventoryAssetState.EXPECTED
        elif not row.expected and row.state == InventoryAssetState.EXPECTED:
            row.state = InventoryAssetState.DISCOVERED
    if "stale_after_days" in changes:
        row.stale_after_days = int(changes["stale_after_days"])
    if previous_state != row.state:
        session.add(
            InventoryLifecycleEvent(
                organization_id=row.organization_id,
                site_id=row.site_id,
                asset_id=row.asset_id,
                previous_state=previous_state,
                new_state=row.state,
                reason="administrator changed expected inventory policy",
                metadata_json={},
            )
        )
    record_audit(
        session,
        action="inventory_state.updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="asset",
        target_id=row.asset_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(payload.model_fields_set)},
    )
    return AssetInventoryStateRead.model_validate(row)
