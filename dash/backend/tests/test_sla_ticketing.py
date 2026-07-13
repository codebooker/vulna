"""Phase 43 SLA, guidance, ticket contract, isolation, and failure coverage."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.api.v1 import ticketing as ticketing_api
from app.core.config import get_settings
from app.models.background_task import BackgroundTask
from app.models.enums import (
    BackgroundTaskStatus,
    FindingStatus,
    FindingType,
    Severity,
    TicketConnectorType,
    TicketSyncStatus,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.site import Site
from app.models.sla import FindingSlaCalculation, SlaHistory
from app.models.ticketing import TicketConnector, TicketSync, TicketSyncEvent
from app.services import sla, ticketing
from app.services.ticketing import TicketResult
from app.tasks import runner
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.release_gate


class FakeAdapter:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []
        self.fail = False
        self.closed = False

    async def test(self, connector: TicketConnector, secret: str) -> dict[str, Any]:
        assert secret == "connector-secret-never-returned"
        return {"account": "fake", "project": connector.project_key}

    async def upsert(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str | None,
        idempotency_key: str,
    ) -> TicketResult:
        del connector, secret, idempotency_key
        self.payloads.append(payload)
        if self.fail:
            raise RuntimeError("simulated ticket outage")
        return TicketResult(external_id=external_id or "T-42", external_url=None, metadata={})

    async def close(
        self,
        connector: TicketConnector,
        secret: str,
        payload: dict[str, Any],
        *,
        external_id: str,
        idempotency_key: str,
    ) -> TicketResult:
        del connector, secret, payload, idempotency_key
        self.closed = True
        return TicketResult(external_id=external_id, external_url=None, metadata={"closed": True})


async def _finding(
    session: AsyncSession,
    organization: Organization,
    *,
    title: str = "Critical internet issue",
    severity: Severity = Severity.CRITICAL,
    known_exploited: bool = True,
) -> tuple[Site, Finding]:
    site = Site(
        organization_id=organization.id,
        name=f"Phase 43 {uuid.uuid4().hex[:6]}",
        code=f"P43-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    session.add(site)
    await session.flush()
    finding = Finding(
        organization_id=organization.id,
        site_id=site.id,
        scanner_name="phase43-test",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.VULNERABILITY,
        title=title,
        description="Selected description, never raw evidence",
        severity=severity,
        known_exploited=known_exploited,
        cve_ids_json=["CVE-2026-4300"],
        cwe_ids_json=[],
        evidence_json={"password": "must-not-leave-vulna"},
        references_json=[],
        remediation="Apply the vendor update",
        status=FindingStatus.NEW,
        first_seen_at=datetime.now(UTC),
    )
    session.add(finding)
    await session.commit()
    return site, finding


async def test_first_match_immutable_deadline_exception_guidance_and_metrics(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    _, finding = await _finding(db_session, organization)
    lower_priority = await client.post(
        "/api/v1/sla/policies",
        headers=admin_headers,
        json={
            "name": "All critical",
            "priority": 20,
            "match": {"severities": ["critical"]},
            "due_days": {"critical": 5},
        },
    )
    assert lower_priority.status_code == 201, lower_priority.text
    first_match = await client.post(
        "/api/v1/sla/policies",
        headers=admin_headers,
        json={
            "name": "Known exploited",
            "priority": 10,
            "match": {"known_exploited": True},
            "due_days": {"critical": 2},
            "pause_on_risk_acceptance": True,
        },
    )
    assert first_match.status_code == 201, first_match.text
    conflict = await client.post(
        "/api/v1/sla/policies",
        headers=admin_headers,
        json={"name": "Duplicate priority", "priority": 10},
    )
    assert conflict.status_code == 409
    denied = await client.post(
        "/api/v1/sla/policies",
        headers=viewer_headers,
        json={"name": "Viewer cannot manage", "priority": 99},
    )
    assert denied.status_code == 403

    calculated = await client.post(
        f"/api/v1/sla/findings/{finding.id}/calculate", headers=admin_headers
    )
    assert calculated.status_code == 200, calculated.text
    calculation = calculated.json()
    assert calculation["policy_id"] == first_match.json()["id"]
    assert calculation["calculation_json"]["days"] == 2
    original_due = datetime.fromisoformat(calculation["due_at"])

    replay = await client.post(
        f"/api/v1/sla/findings/{finding.id}/calculate", headers=admin_headers
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == calculation["id"]
    direct_change = await client.patch(
        f"/api/v1/findings/{finding.id}",
        headers=admin_headers,
        json={"due_at": (original_due + timedelta(days=1)).isoformat()},
    )
    assert direct_change.status_code == 409

    exception = await client.post(
        f"/api/v1/sla/findings/{finding.id}/exceptions",
        headers=admin_headers,
        json={
            "requested_due_at": (original_due + timedelta(days=7)).isoformat(),
            "reason": "A vendor maintenance window is already approved.",
        },
    )
    assert exception.status_code == 201, exception.text
    approved = await client.patch(
        f"/api/v1/sla/exceptions/{exception.json()['id']}",
        headers=admin_headers,
        json={"approve": True, "review_notes": "Approved by change control"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["resulting_calculation_id"] != calculation["id"]

    guidance = await client.post(
        f"/api/v1/sla/findings/{finding.id}/guidance",
        headers=admin_headers,
        json={
            "classification": "patch",
            "summary": "Install the supported vendor patch.",
            "steps": [{"title": "Stage", "instruction": "Deploy to a staging host."}],
            "validation_steps": [
                {"title": "Verify", "instruction": "Run a signed verification scan."}
            ],
            "references": ["CVE-2026-4300"],
            "source": "Vendor advisory",
        },
    )
    assert guidance.status_code == 201, guidance.text
    assert guidance.json()["classification"] == "patch"
    metrics = await client.get("/api/v1/sla/metrics", headers=admin_headers)
    assert metrics.status_code == 200, metrics.text
    assert metrics.json()["total_with_sla"] == 1
    assert metrics.json()["open"] == 1

    await db_session.refresh(finding)
    assert finding.current_sla_calculation_id == uuid.UUID(
        approved.json()["resulting_calculation_id"]
    )
    due_before_pause = finding.due_at
    assert due_before_pause is not None
    paused_at = datetime.now(UTC)
    assert await sla.pause_for_risk_acceptance(db_session, finding, now=paused_at) is True
    assert (
        await sla.resume_after_risk_acceptance(
            db_session, finding, now=paused_at + timedelta(hours=3)
        )
        is True
    )
    assert finding.due_at == due_before_pause.replace(tzinfo=UTC) + timedelta(hours=3)

    _, fallback = await _finding(
        db_session,
        organization,
        title="Low finding without a matching policy",
        severity=Severity.LOW,
        known_exploited=False,
    )
    fallback_calculation = await sla.calculate_deadline(db_session, fallback)
    assert fallback_calculation.source.value == "severity_fallback"
    assert await sla.pause_for_risk_acceptance(db_session, fallback, now=paused_at) is False
    assert (
        await db_session.scalar(
            select(func.count()).select_from(FindingSlaCalculation).where(
                FindingSlaCalculation.finding_id == finding.id
            )
        )
        == 3
    )
    assert (
        await db_session.scalar(
            select(func.count()).select_from(SlaHistory).where(SlaHistory.finding_id == finding.id)
        )
        >= 3
    )


async def test_ticket_secret_idempotency_worker_failure_and_verified_close(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    sessionmaker: async_sessionmaker[AsyncSession],
    organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, finding = await _finding(db_session, organization, title="Ticketed issue")
    finding_id = finding.id
    fake = FakeAdapter()
    monkeypatch.setitem(ticketing.ADAPTERS, TicketConnectorType.GITHUB, fake)
    monkeypatch.setattr(ticketing_api, "validate_destination", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "get_sessionmaker", lambda: sessionmaker)
    secret = "connector-secret-never-returned"
    created = await client.post(
        "/api/v1/ticketing/connectors",
        headers=admin_headers,
        json={
            "name": "Engineering",
            "connector_type": "github",
            "base_url": "https://github.example.test/api/v3",
            "project_key": "security/issues",
            "config": {"labels": ["security"], "allow_private": False},
            "secret": secret,
        },
    )
    assert created.status_code == 201, created.text
    connector_id = uuid.UUID(created.json()["id"])
    assert created.json()["has_secret"] is True
    assert secret not in created.text
    assert "encrypted_secret" not in created.json()
    connector = await db_session.get(TicketConnector, connector_id)
    assert connector is not None and secret not in connector.encrypted_secret

    tested = await client.post(
        f"/api/v1/ticketing/connectors/{connector_id}/test", headers=admin_headers
    )
    assert tested.status_code == 200 and tested.json()["succeeded"] is True
    enabled = await client.patch(
        f"/api/v1/ticketing/connectors/{connector_id}",
        headers=admin_headers,
        json={"enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    db_session.expire_all()

    queued = await client.post(
        f"/api/v1/ticketing/findings/{finding_id}/sync",
        headers={**admin_headers, "Idempotency-Key": "phase43-upsert"},
        json={"connector_id": str(connector_id), "action": "upsert"},
    )
    replay = await client.post(
        f"/api/v1/ticketing/findings/{finding_id}/sync",
        headers={**admin_headers, "Idempotency-Key": "phase43-upsert"},
        json={"connector_id": str(connector_id), "action": "upsert"},
    )
    assert queued.status_code == 202, queued.text
    assert replay.status_code == 202 and replay.json()["id"] == queued.json()["id"]
    assert await runner.run_worker_once(get_settings(), "phase43-success") is True
    db_session.expire_all()
    task = await db_session.get(BackgroundTask, uuid.UUID(queued.json()["id"]))
    assert task is not None and task.status == BackgroundTaskStatus.COMPLETED
    assert task.result_json["status"] == "succeeded"
    assert fake.payloads and "evidence" not in fake.payloads[0]
    assert "must-not-leave-vulna" not in str(fake.payloads[0])

    sync = await db_session.scalar(
        select(TicketSync).where(
            TicketSync.connector_id == connector_id, TicketSync.finding_id == finding_id
        )
    )
    assert sync is not None and sync.external_ticket_id == "T-42"
    sync_id = sync.id
    assert sync.status == TicketSyncStatus.SUCCEEDED

    fake.fail = True
    failed_task = await client.post(
        f"/api/v1/ticketing/findings/{finding_id}/sync",
        headers={**admin_headers, "Idempotency-Key": "phase43-failure"},
        json={"connector_id": str(connector_id), "action": "upsert"},
    )
    assert await runner.run_worker_once(get_settings(), "phase43-failure") is True
    db_session.expire_all()
    task = await db_session.get(BackgroundTask, uuid.UUID(failed_task.json()["id"]))
    assert task is not None and task.status == BackgroundTaskStatus.RETRY
    assert task.attempts == 1 and task.max_attempts == 5
    assert await db_session.get(Finding, finding_id) is not None
    await db_session.refresh(sync)
    assert sync.status == TicketSyncStatus.FAILED

    fake.fail = False
    premature = await client.post(
        f"/api/v1/ticketing/findings/{finding_id}/sync",
        headers={**admin_headers, "Idempotency-Key": "phase43-premature-close"},
        json={"connector_id": str(connector_id), "action": "close"},
    )
    assert premature.status_code == 202
    assert await runner.run_worker_once(get_settings(), "phase43-premature-close") is True
    db_session.expire_all()
    premature_task = await db_session.get(
        BackgroundTask, uuid.UUID(premature.json()["id"])
    )
    assert premature_task is not None
    assert premature_task.status == BackgroundTaskStatus.RETRY
    assert fake.closed is False

    finding = await db_session.get(Finding, finding_id)
    assert finding is not None
    finding.status = FindingStatus.RESOLVED
    finding.resolved_at = datetime.now(UTC)
    finding.last_verified_at = datetime.now(UTC)
    await db_session.commit()
    close_task = await client.post(
        f"/api/v1/ticketing/findings/{finding_id}/sync",
        headers={**admin_headers, "Idempotency-Key": "phase43-close"},
        json={"connector_id": str(connector_id), "action": "close"},
    )
    assert await runner.run_worker_once(get_settings(), "phase43-close") is True
    db_session.expire_all()
    task = await db_session.get(BackgroundTask, uuid.UUID(close_task.json()["id"]))
    assert task is not None and task.status == BackgroundTaskStatus.COMPLETED
    assert task.result_json["status"] == "succeeded" and fake.closed is True
    assert (
        await db_session.scalar(
                select(func.count()).select_from(TicketSyncEvent).where(
                    TicketSyncEvent.sync_id == sync_id
                )
        )
        == 4
    )


async def test_ticket_connector_cannot_cross_organizations(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = Organization(name="Foreign", slug=f"foreign-{uuid.uuid4().hex[:6]}")
    db_session.add(foreign)
    await db_session.flush()
    foreign_connector = TicketConnector(
        organization_id=foreign.id,
        name="Foreign",
        connector_type=TicketConnectorType.GITHUB,
        base_url="https://example.test",
        project_key="foreign/project",
        config_json={},
        encrypted_secret=ticketing.encrypt_connector_secret(get_settings(), "foreign-secret"),
    )
    db_session.add(foreign_connector)
    await db_session.commit()
    monkeypatch.setattr(ticketing_api, "validate_destination", lambda *_args, **_kwargs: None)
    response = await client.post(
        f"/api/v1/ticketing/connectors/{foreign_connector.id}/test", headers=admin_headers
    )
    assert response.status_code == 404


async def test_phase43_interfaces_and_capability_are_truthful(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/sla/policies",
        "/api/v1/sla/metrics",
        "/api/v1/sla/findings/{finding_id}/calculate",
        "/api/v1/ticketing/connectors",
        "/api/v1/ticketing/findings/{finding_id}/sync",
    ):
        assert path in schema["paths"]
    matrix = (await client.get("/api/v1/system/capabilities")).json()
    ticketing_capability = next(
        item for item in matrix["capabilities"] if item["key"] == "ticketing"
    )
    assert ticketing_capability == {
        "key": "ticketing",
        "name": "Ticketing connectors",
        "status": "available",
        "production_ready": False,
    }
