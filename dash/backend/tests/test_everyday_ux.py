"""Everyday-UX: priority model, evidence sanitizing, dashboard, search, bulk (Phase 22)."""

from __future__ import annotations

import uuid

from app.models.enums import (
    FindingStatus,
    FindingType,
    Severity,
    ValidationStatus,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from app.services import priority as prio
from app.services.evidence import sanitize_evidence
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# --------------------------------------------------------------------------- #
# Priority model (security-critical: never overstate uncertain matches)
# --------------------------------------------------------------------------- #


def _classify(severity, confidence, kev=False, epss=None, val=ValidationStatus.UNVALIDATED):
    return prio.classify(
        severity=severity,
        confidence=confidence,
        known_exploited=kev,
        epss_score=epss,
        validation_status=val,
    )


def test_info_is_informational() -> None:
    assert _classify(Severity.INFO, 90)[0] == prio.INFORMATIONAL


def test_low_confidence_never_fix_now() -> None:
    # A critical, KEV finding with LOW detection confidence must not be fix-now.
    p, rationale = _classify(Severity.CRITICAL, 20, kev=True, epss=0.9)
    assert p == prio.WATCH
    assert "uncertain" in rationale.lower()


def test_confirmed_exploitable_is_fix_now() -> None:
    p, _ = _classify(Severity.MEDIUM, 80, val=ValidationStatus.CONFIRMED_EXPLOITABLE)
    assert p == prio.FIX_NOW


def test_kev_confident_high_is_fix_now() -> None:
    assert _classify(Severity.HIGH, 80, kev=True)[0] == prio.FIX_NOW


def test_critical_confident_is_fix_now() -> None:
    assert _classify(Severity.CRITICAL, 80)[0] == prio.FIX_NOW


def test_high_confident_no_epss_is_plan() -> None:
    assert _classify(Severity.HIGH, 80)[0] == prio.PLAN


def test_medium_is_watch() -> None:
    assert _classify(Severity.MEDIUM, 80)[0] == prio.WATCH


def test_confidence_label() -> None:
    assert prio.confidence_label(90) == "high"
    assert prio.confidence_label(50) == "medium"
    assert prio.confidence_label(10) == "low"


# --------------------------------------------------------------------------- #
# Evidence sanitizing
# --------------------------------------------------------------------------- #


def test_sanitize_strips_control_and_truncates() -> None:
    ev = {"out": "line1\x1b[31mred\x00\x07 end" + "A" * 5000, "n": 3, "nested": {"k": "v\x08x"}}
    clean = sanitize_evidence(ev)
    assert "\x1b" not in clean["out"] and "\x00" not in clean["out"]
    assert len(clean["out"]) <= 4000
    assert clean["n"] == 3
    assert clean["nested"]["k"] == "vx"


def test_sanitize_non_dict() -> None:
    assert sanitize_evidence(None) == {}
    assert sanitize_evidence("nope") == {}  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Finding presentation + dashboard + search + bulk (API)
# --------------------------------------------------------------------------- #


async def _site(db_session: AsyncSession, org_id: uuid.UUID, code: str) -> uuid.UUID:
    site = Site(organization_id=org_id, name="HQ", code=code)
    db_session.add(site)
    await db_session.flush()
    return site.id


async def _finding(
    db_session: AsyncSession, org_id: uuid.UUID, site_id: uuid.UUID, **over: object
) -> Finding:
    f = Finding(
        organization_id=org_id,
        site_id=site_id,
        scanner_name="nuclei",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.VULNERABILITY,
        title=over.pop("title", "Test finding"),  # type: ignore[arg-type]
        severity=over.pop("severity", Severity.HIGH),  # type: ignore[arg-type]
        confidence=over.pop("confidence", 80),  # type: ignore[arg-type]
        status=over.pop("status", FindingStatus.NEW),  # type: ignore[arg-type]
        evidence_json=over.pop("evidence_json", {}),  # type: ignore[arg-type]
    )
    for k, v in over.items():
        setattr(f, k, v)
    db_session.add(f)
    await db_session.flush()
    return f


async def test_finding_read_has_priority_and_sanitized_evidence(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession, admin: User
) -> None:
    site_id = await _site(db_session, admin.organization_id, "S1")
    f = await _finding(
        db_session,
        admin.organization_id,
        site_id,
        severity=Severity.CRITICAL,
        confidence=20,  # uncertain
        evidence_json={"raw": "boom\x1b[0m\x00"},
    )
    await db_session.commit()

    r = await client.get(f"/api/v1/findings/{f.id}", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    # Uncertain critical must NOT be presented as fix-now.
    assert body["priority"] == "watch"
    assert body["confidence_label"] == "low"
    assert "\x1b" not in body["evidence_json"]["raw"]


async def test_dashboard_summary(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession, admin: User
) -> None:
    site_id = await _site(db_session, admin.organization_id, "S2")
    await _finding(
        db_session,
        admin.organization_id,
        site_id,
        severity=Severity.CRITICAL,
        confidence=90,
        known_exploited=True,
    )
    await db_session.commit()

    r = await client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["needs_attention"]["fix_now"] >= 1
    assert body["next_action"]["kind"] == "review_fix_now"
    assert body["next_action"]["priority"] == "fix_now"
    assert "health" in body and "changed_recently" in body and "unassessed" in body
    assert body["finding_metrics"]["by_severity"]["critical"]["total"] >= 1
    assert body["finding_metrics"]["active_total"] >= 1
    assert body["operational_metrics"]["asset_total"] >= 0
    assert isinstance(body["operational_metrics"]["recent_jobs"], list)
    # The highest-priority issue is discoverable from the summary.
    assert body["needs_attention"]["top"][0]["priority"] == "fix_now"


async def test_global_search(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession, admin: User
) -> None:
    site_id = await _site(db_session, admin.organization_id, "S3")
    await _finding(db_session, admin.organization_id, site_id, title="OpenSSL heartbleed")
    await db_session.commit()

    r = await client.get("/api/v1/search?q=heartbleed", headers=admin_headers)
    assert r.status_code == 200
    assert any("heartbleed" in f["label"].lower() for f in r.json()["findings"])


async def test_bulk_action_authz_and_skip(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession, admin: User
) -> None:
    site_id = await _site(db_session, admin.organization_id, "S4")
    f1 = await _finding(db_session, admin.organization_id, site_id, title="A")
    f2 = await _finding(db_session, admin.organization_id, site_id, title="B")

    # A finding in a different organization must be skipped, never touched.
    other_org = Organization(name="Other", slug="other-" + uuid.uuid4().hex[:8])
    db_session.add(other_org)
    await db_session.flush()
    other_site = await _site(db_session, other_org.id, "OS")
    foreign = await _finding(db_session, other_org.id, other_site, title="Foreign")
    await db_session.commit()

    r = await client.post(
        "/api/v1/findings/bulk",
        json={"finding_ids": [str(f1.id), str(f2.id), str(foreign.id)], "action": "false_positive"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["updated"]) == 2
    assert body["skipped"] == 1

    # The foreign finding was not modified.
    await db_session.refresh(foreign)
    assert foreign.status == FindingStatus.NEW
