"""Version-based CVE correlation: discovered product/version -> findings."""

from __future__ import annotations

from datetime import UTC, datetime

from app.intelligence.matching import products_from_cpe_matches
from app.intelligence.nvd import CveData
from app.models.cve import CveProductIndex, CveRecord
from app.models.enums import ServiceState, ServiceTransport, Severity
from app.services.cve_correlation import (
    _best_cvss,
    _severity_from_score,
    correlate_hosts,
    lookup_cves_by_product,
)
from app.services.intelligence import ingest_nvd
from app.services.nmap_parser import ParsedHost, ParsedService
from sqlalchemy.ext.asyncio import AsyncSession

# A CVE affecting apache http_server 2.4.0 <= v < 2.4.50 (shaped like NVD's data).
RANGE_MATCH = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0",
    "versionEndExcluding": "2.4.50",
}


def _service(product: str | None, version: str | None, cpe: str | None = None) -> ParsedService:
    return ParsedService(
        transport=ServiceTransport.TCP,
        port=443,
        state=ServiceState.OPEN,
        service_name="http",
        product=product,
        version=version,
        cpe=cpe,
    )


async def _add_cve(
    session: AsyncSession,
    cve_id: str,
    cpe_matches: list[dict[str, object]],
    products: list[str],
    *,
    base_score: float | None = 9.8,
) -> None:
    session.add(
        CveRecord(
            cve_id=cve_id,
            cpe_matches_json=cpe_matches,
            cvss_v3_json={"baseScore": base_score} if base_score is not None else None,
            description=f"desc for {cve_id}",
        )
    )
    for product in products:
        session.add(CveProductIndex(product=product, cve_id=cve_id))
    await session.flush()


def test_products_from_cpe_matches() -> None:
    matches = [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
        {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"},  # dup product
        {"criteria": "cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*"},  # hardware -> excluded
        {"criteria": "not-a-cpe"},
        "junk",
    ]
    assert products_from_cpe_matches(matches) == {"http_server", "linux_kernel"}


def test_severity_from_score() -> None:
    assert _severity_from_score(9.8) is Severity.CRITICAL
    assert _severity_from_score(7.5) is Severity.HIGH
    assert _severity_from_score(5.0) is Severity.MEDIUM
    assert _severity_from_score(2.0) is Severity.LOW
    assert _severity_from_score(0.0) is Severity.INFO
    assert _severity_from_score(None) is Severity.INFO


def test_best_cvss_prefers_v3_then_v4_then_v2() -> None:
    only_v2 = CveRecord(cve_id="x", cvss_v2_json={"baseScore": 5.0, "vectorString": "AV:N"})
    score, vector = _best_cvss(only_v2)
    assert score == 5.0 and vector == "AV:N"

    v3_wins = CveRecord(
        cve_id="y",
        cvss_v2_json={"baseScore": 5.0},
        cvss_v3_json={"baseScore": 9.1},
    )
    assert _best_cvss(v3_wins)[0] == 9.1


async def test_lookup_cves_by_product(db_session: AsyncSession) -> None:
    await _add_cve(db_session, "CVE-2021-41773", [RANGE_MATCH], ["http_server"])
    hits = await lookup_cves_by_product(db_session, "HTTP_SERVER")  # case-insensitive
    assert [c.cve_id for c in hits] == ["CVE-2021-41773"]
    assert await lookup_cves_by_product(db_session, "nginx") == []


async def test_correlate_emits_finding_for_version_in_range(db_session: AsyncSession) -> None:
    await _add_cve(db_session, "CVE-2021-41773", [RANGE_MATCH], ["http_server"])
    hosts = [ParsedHost(ip="10.0.0.1", services=[_service("http_server", "2.4.49")])]

    findings = await correlate_hosts(db_session, hosts)

    assert len(findings) == 1
    f = findings[0]
    assert f.cve_ids == ["CVE-2021-41773"]
    assert f.severity is Severity.CRITICAL
    assert f.target_ip == "10.0.0.1" and f.port == 443
    assert f.scanner == "cve-correlation"
    assert f.confidence == 60  # medium: version confirmed in range
    assert f.evidence["matched_version"] == "2.4.49"


async def test_correlate_skips_version_out_of_range(db_session: AsyncSession) -> None:
    await _add_cve(db_session, "CVE-2021-41773", [RANGE_MATCH], ["http_server"])
    hosts = [ParsedHost(ip="10.0.0.1", services=[_service("http_server", "2.4.62")])]
    assert await correlate_hosts(db_session, hosts) == []


async def test_correlate_skips_low_confidence_product_only(db_session: AsyncSession) -> None:
    # A whole-product CPE with no version constraint is only a low-confidence
    # match, which must not be surfaced as a confirmed finding.
    product_only = {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
    await _add_cve(db_session, "CVE-9999-0001", [product_only], ["http_server"])
    hosts = [ParsedHost(ip="10.0.0.1", services=[_service("http_server", None)])]
    assert await correlate_hosts(db_session, hosts) == []


async def test_correlate_skips_rejected_cve(db_session: AsyncSession) -> None:
    db_session.add(
        CveRecord(cve_id="CVE-0000-0000", cpe_matches_json=[RANGE_MATCH], rejected=True)
    )
    db_session.add(CveProductIndex(product="http_server", cve_id="CVE-0000-0000"))
    await db_session.flush()
    hosts = [ParsedHost(ip="10.0.0.1", services=[_service("http_server", "2.4.49")])]
    assert await correlate_hosts(db_session, hosts) == []


async def test_ingest_nvd_maintains_product_index(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    cve = CveData(
        cve_id="CVE-2021-41773",
        published_at=now,
        modified_at=now,
        description="path traversal",
        cpe_matches=[RANGE_MATCH],
        cwe_ids=[],
        references=[],
    )
    await ingest_nvd(db_session, [cve], now=now)
    hits = await lookup_cves_by_product(db_session, "http_server")
    assert [c.cve_id for c in hits] == ["CVE-2021-41773"]

    # A later sync that drops the product removes its stale index row.
    cve.modified_at = datetime.now(UTC)
    cve.cpe_matches = [
        {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"}
    ]
    await ingest_nvd(db_session, [cve], now=now)
    assert await lookup_cves_by_product(db_session, "http_server") == []
    assert [c.cve_id for c in await lookup_cves_by_product(db_session, "nginx")] == [
        "CVE-2021-41773"
    ]


def test_cpe_product_parses_22_and_23_formats() -> None:
    from app.intelligence.matching import cpe_product

    assert cpe_product("cpe:/a:apache:http_server:2.4.49") == "http_server"  # nmap 2.2
    assert cpe_product("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") == "http_server"
    assert cpe_product("cpe:/o:linux:linux_kernel:5.4") == "linux_kernel"
    assert cpe_product("cpe:/h:cisco:router:1.0") is None  # hardware
    assert cpe_product(None) is None
    assert cpe_product("not-a-cpe") is None


async def test_correlate_uses_cpe_product_over_nmap_product(db_session: AsyncSession) -> None:
    # Nmap reports the human product "Apache httpd"; the CVE is indexed under the
    # CPE product "http_server". Correlation must key on the CPE product.
    await _add_cve(db_session, "CVE-2021-41773", [RANGE_MATCH], ["http_server"])
    svc = _service("Apache httpd", "2.4.49", cpe="cpe:/a:apache:http_server:2.4.49")
    hosts = [ParsedHost(ip="10.0.0.1", services=[svc])]

    findings = await correlate_hosts(db_session, hosts)
    assert [f.cve_ids[0] for f in findings] == ["CVE-2021-41773"]
