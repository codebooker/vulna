"""Correlate discovered services to known CVEs (build plan Section 14.3).

Discovery gives us a service's product and version (banner/``-sV`` based). This
turns that into candidate vulnerabilities: look up the CVEs indexed under the
product, ask :func:`match_confidence` whether the discovered version falls in a
CVE's affected range, and emit a finding for the confident matches.

Only *medium* and *high* confidence matches (the discovered version actually sits
in the CVE's affected range) become findings. A product-only match with no
version confirmation is *low* confidence, which — per Section 14.3 — must not be
surfaced as a confirmed vulnerability, so it is deliberately not turned into a
finding here.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.matching import match_confidence
from app.intelligence.nvd import cvss_base_score, cvss_vector
from app.models.cve import CveProductIndex, CveRecord
from app.models.enums import FindingType, MatchConfidence, Severity
from app.services.findings import ParsedFinding
from app.services.nmap_parser import ParsedHost, ParsedService

# How confident the correlation is that the CVE applies, as the numeric score the
# Finding model stores. Only medium/high are emitted (see module docstring).
_CONFIDENCE_SCORE: dict[MatchConfidence, int] = {
    MatchConfidence.HIGH: 90,
    MatchConfidence.MEDIUM: 60,
    MatchConfidence.LOW: 30,
}

_EMITTED = (MatchConfidence.MEDIUM, MatchConfidence.HIGH)


async def lookup_cves_by_product(session: AsyncSession, product: str) -> list[CveRecord]:
    """Return the non-rejected CVE records indexed under ``product``."""
    cve_ids = (
        await session.execute(
            select(CveProductIndex.cve_id).where(CveProductIndex.product == product.lower())
        )
    ).scalars().all()
    if not cve_ids:
        return []
    records = (
        await session.execute(
            select(CveRecord).where(
                CveRecord.cve_id.in_(cve_ids), CveRecord.rejected.is_(False)
            )
        )
    ).scalars().all()
    return list(records)


def _severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _best_cvss(cve: CveRecord) -> tuple[float | None, str | None]:
    """The base score and vector from the most authoritative CVSS metric present
    (CVSS v3 preferred, then v4, then v2)."""
    for cvss in (cve.cvss_v3_json, cve.cvss_v4_json, cve.cvss_v2_json):
        score = cvss_base_score(cvss)
        if score is not None:
            return score, cvss_vector(cvss)
    return None, None


def _finding_from_cve(
    cve: CveRecord, host: ParsedHost, svc: ParsedService, confidence: MatchConfidence
) -> ParsedFinding:
    score, vector = _best_cvss(cve)
    version = svc.version or ""
    product = svc.product or ""
    title = f"{cve.cve_id} affects {product} {version}".strip()
    return ParsedFinding(
        scanner="cve-correlation",
        weakness_key=cve.cve_id,
        finding_type=FindingType.VULNERABILITY,
        title=title,
        severity=_severity_from_score(score),
        target_ip=host.ip,
        port=svc.port,
        transport=svc.transport,
        description=cve.description,
        cvss_score=score,
        cvss_vector=vector,
        cve_ids=[cve.cve_id],
        cwe_ids=list(cve.cwe_ids_json),
        references=list(cve.references_json),
        confidence=_CONFIDENCE_SCORE[confidence],
        evidence={
            "matched_product": product,
            "matched_version": version,
            "match_confidence": confidence.value,
            "source": "version-based CVE correlation",
        },
    )


async def correlate_hosts(
    session: AsyncSession, hosts: list[ParsedHost]
) -> list[ParsedFinding]:
    """Emit findings for the confident CVE matches of every discovered service.

    CVE lookups are cached per product across the host set, so a subnet of like
    hosts costs one query per distinct product rather than one per service.
    """
    findings: list[ParsedFinding] = []
    cache: dict[str, list[CveRecord]] = {}
    for host in hosts:
        if not host.ip:
            continue
        for svc in host.services:
            if not svc.product:
                continue
            key = svc.product.lower()
            if key not in cache:
                cache[key] = await lookup_cves_by_product(session, key)
            for cve in cache[key]:
                confidence = match_confidence(
                    cve.cpe_matches_json,
                    product=svc.product,
                    version=svc.version,
                    service_cpe=svc.cpe,
                )
                if confidence in _EMITTED:
                    findings.append(_finding_from_cve(cve, host, svc, confidence))
    return findings
