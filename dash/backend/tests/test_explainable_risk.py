"""Phase 41 explainable scoring, remediation grouping, and decision coverage."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.enums import (
    AssetCriticality,
    AssetType,
    FindingDecisionStatus,
    FindingStatus,
    FindingType,
    Severity,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.risk import (
    FindingDecision,
    FindingScoreSnapshot,
    RemediationSuggestion,
    RemediationUnit,
    RemediationUnitFinding,
)
from app.models.site import Site
from app.services import risk
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.release_gate


async def _finding(
    session: AsyncSession,
    organization: Organization,
    *,
    title: str = "OpenSSL vulnerable package",
    cve: str | None = "CVE-2026-4242",
    remediation: str | None = "Upgrade OpenSSL to the supported release",
) -> tuple[Site, Asset, Finding]:
    site = Site(
        organization_id=organization.id,
        name=f"Site {uuid.uuid4().hex[:6]}",
        code=f"S-{uuid.uuid4().hex[:8]}",
        timezone="UTC",
    )
    session.add(site)
    await session.flush()
    asset = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name=f"host-{uuid.uuid4().hex[:6]}",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.MISSION_CRITICAL,
        internet_exposed=True,
    )
    session.add(asset)
    await session.flush()
    finding = Finding(
        organization_id=organization.id,
        site_id=site.id,
        asset_id=asset.id,
        scanner_name="phase41-test",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.VULNERABILITY,
        title=title,
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        cve_ids_json=[cve] if cve else [],
        confidence=100,
        known_exploited=True,
        epss_score=1.0,
        evidence_json={"package": "openssl"},
        remediation=remediation,
        status=FindingStatus.NEW,
    )
    session.add(finding)
    await session.commit()
    return site, asset, finding


async def test_scoring_formula_is_versioned_explainable_and_immutable(
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    _, _, finding = await _finding(db_session, organization)
    first = await risk.score_finding(db_session, finding)
    await db_session.commit()

    expected = round(
        (
            sum(factor["contribution"] for factor in first.factors_json)
            / sum(abs(value) for value in risk.DEFAULT_WEIGHTS.values())
            + 1
        )
        * 50,
        2,
    )
    assert first.score == expected
    assert first.positive_maximum == sum(abs(value) for value in risk.DEFAULT_WEIGHTS.values())
    assert {factor["factor"] for factor in first.factors_json} == risk.FACTOR_KEYS
    assert all(-1 <= factor["normalized_value"] <= 1 for factor in first.factors_json)
    assert len(first.input_hash) == 64
    assert finding.current_score_snapshot_id == first.id

    same = await risk.score_finding(db_session, finding)
    assert same.id == first.id
    forced = await risk.score_finding(db_session, finding, force=True)
    assert forced.id != first.id
    assert forced.input_hash == first.input_hash
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(FindingScoreSnapshot)
            .where(FindingScoreSnapshot.finding_id == finding.id)
        )
        == 2
    )


async def test_internal_critical_finding_is_not_scored_informational(
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site = Site(
        organization_id=organization.id,
        name=f"Site {uuid.uuid4().hex[:6]}",
        code=f"S-{uuid.uuid4().hex[:8]}",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.flush()
    asset = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="internal-service",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.UNKNOWN,
        internet_exposed=False,
    )
    db_session.add(asset)
    await db_session.flush()
    finding = Finding(
        organization_id=organization.id,
        site_id=site.id,
        asset_id=asset.id,
        scanner_name="testssl",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.MISCONFIGURATION,
        title="Critical internal TLS issue",
        severity=Severity.CRITICAL,
        confidence=50,
        known_exploited=False,
        status=FindingStatus.NEW,
    )
    db_session.add(finding)
    await db_session.flush()

    snapshot = await risk.score_finding(db_session, finding)

    assert snapshot.score == 50.0
    assert risk.priority_from_score(snapshot.score)[0] == "plan"
    assert finding.risk_input_hash is not None


async def test_profile_versions_rescore_findings_and_reject_incomplete_catalogue(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    _, _, finding = await _finding(db_session, organization)
    invalid = await client.post(
        "/api/v1/risk-profiles",
        json={"name": "Incomplete", "weights": {"severity": 1}},
        headers=admin_headers,
    )
    assert invalid.status_code == 422

    weights = {**risk.DEFAULT_WEIGHTS, "severity": 50.0}
    created = await client.post(
        "/api/v1/risk-profiles",
        json={
            "name": "Internet production",
            "description": "Prioritize exposed production assets",
            "weights": weights,
            "make_default": True,
        },
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 1
    assert created.json()["is_default"] is True

    finding_id = finding.id
    organization_id = organization.id
    db_session.expire_all()
    updated = await db_session.get(Finding, finding_id)
    assert updated is not None
    assert updated.risk_profile_version == 1
    assert updated.current_score_snapshot_id is not None
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.organization_id == organization_id,
                AuditEvent.action == "risk_profile.version_created",
            )
        )
        == 1
    )


async def test_exact_grouping_and_fuzzy_review_never_auto_apply(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site, _, first = await _finding(db_session, organization)
    second = Finding(
        organization_id=organization.id,
        site_id=site.id,
        asset_id=first.asset_id,
        scanner_name="phase41-test",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.VULNERABILITY,
        title="Another OpenSSL issue",
        severity=Severity.HIGH,
        cve_ids_json=["CVE-2026-4242"],
        remediation="Upgrade OpenSSL to the supported release",
        status=FindingStatus.NEW,
    )
    fuzzy = Finding(
        organization_id=organization.id,
        site_id=site.id,
        asset_id=first.asset_id,
        scanner_name="phase41-test",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.MISCONFIGURATION,
        title="CVE-2026-4242 OpenSSL supported release configuration",
        severity=Severity.MEDIUM,
        remediation=None,
        status=FindingStatus.NEW,
    )
    db_session.add_all([second, fuzzy])
    await db_session.commit()

    grouped = await client.post(
        "/api/v1/remediation-units/auto-group",
        json={"finding_ids": [str(first.id), str(second.id), str(fuzzy.id)]},
        headers=admin_headers,
    )
    assert grouped.status_code == 200, grouped.text
    assert grouped.json()["units_created"] >= 2

    cve_unit = await db_session.scalar(
        select(RemediationUnit).where(
            RemediationUnit.organization_id == organization.id,
            RemediationUnit.exact_key == "CVE-2026-4242",
        )
    )
    assert cve_unit is not None
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(RemediationUnitFinding)
            .where(RemediationUnitFinding.remediation_unit_id == cve_unit.id)
        )
        == 2
    )

    suggested = await client.post(
        f"/api/v1/remediation-units/{cve_unit.id}/suggestions",
        json={"finding_ids": [str(fuzzy.id)], "threshold": 0.1},
        headers=admin_headers,
    )
    assert suggested.status_code == 200, suggested.text
    assert len(suggested.json()) == 1
    suggestion_id = suggested.json()[0]["id"]
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(RemediationUnitFinding)
            .where(
                RemediationUnitFinding.remediation_unit_id == cve_unit.id,
                RemediationUnitFinding.finding_id == fuzzy.id,
            )
        )
        == 0
    )
    reviewed = await client.post(
        f"/api/v1/remediation-units/suggestions/{suggestion_id}/review",
        json={"accept": True},
        headers=admin_headers,
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["status"] == "accepted"
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(RemediationUnitFinding)
            .where(
                RemediationUnitFinding.remediation_unit_id == cve_unit.id,
                RemediationUnitFinding.finding_id == fuzzy.id,
            )
        )
        == 1
    )


async def test_phase41_openapi_contract(client: AsyncClient) -> None:
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert {
        "/api/v1/risk-profiles",
        "/api/v1/finding-scores/{finding_id}",
        "/api/v1/remediation-units",
        "/api/v1/findings/{finding_id}/decisions",
    } <= set(paths)

    operation_ids = [
        operation["operationId"]
        for path in paths.values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]
    assert len(operation_ids) == len(set(operation_ids))


async def test_evidence_backed_decisions_expire_restore_and_isolate(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    _, _, finding = await _finding(db_session, organization)
    no_evidence = await client.post(
        f"/api/v1/findings/{finding.id}/decisions",
        json={
            "decision_type": "false_positive",
            "reason": "Scanner signature was disproved",
            "evidence": [],
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers=admin_headers,
    )
    assert no_evidence.status_code == 422

    denied = await client.post(
        f"/api/v1/findings/{finding.id}/decisions",
        json={
            "decision_type": "suppression",
            "reason": "Temporary maintenance window",
            "evidence": [{"type": "change", "reference": "CHG-42"}],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
        headers=viewer_headers,
    )
    assert denied.status_code == 403

    created = await client.post(
        f"/api/v1/findings/{finding.id}/decisions",
        json={
            "decision_type": "suppression",
            "reason": "Temporary maintenance window",
            "evidence": [{"type": "change", "reference": "CHG-42"}],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    decision_id = created.json()["id"]
    finding_id = finding.id
    db_session.expire_all()
    assert (await db_session.get(Finding, finding_id)).status == FindingStatus.SUPPRESSED  # type: ignore[union-attr]

    decision = await db_session.get(FindingDecision, uuid.UUID(decision_id))
    assert decision is not None
    decision_uuid = decision.id
    decision.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    expired = await client.post("/api/v1/findings/decisions/expire", headers=admin_headers)
    assert expired.status_code == 200, expired.text
    assert expired.json() == {"expired": 1}
    db_session.expire_all()
    assert (await db_session.get(Finding, finding_id)).status == FindingStatus.NEW  # type: ignore[union-attr]
    assert (
        await db_session.get(FindingDecision, decision_uuid)
    ).status == FindingDecisionStatus.EXPIRED  # type: ignore[union-attr]

    other_org = Organization(name="Other", slug=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other_org)
    await db_session.commit()
    other_site, _, other_finding = await _finding(db_session, other_org)
    assert other_site.organization_id == other_org.id
    hidden = await client.get(
        f"/api/v1/findings/{other_finding.id}/decisions", headers=admin_headers
    )
    assert hidden.status_code == 404

    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(RemediationSuggestion)
            .where(RemediationSuggestion.status == "pending")
        )
        == 0
    )
