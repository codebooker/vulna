"""CVE-to-service matching (build plan Section 14.3).

Matching is deliberately conservative. Our service data comes from banner-based
product/version detection, so a product+version match is reported as *medium*
confidence and a product-family-only match as *low*; only an exact CPE match on
the service is treated as *high*. Low-confidence matches must never be presented
as confirmed vulnerabilities (Section 14.3), which the caller enforces by
recording the confidence on the finding.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.models.enums import MatchConfidence


@dataclass
class Cpe:
    """The parts of a CPE 2.3 URI we care about."""

    part: str
    vendor: str
    product: str
    version: str


def parse_cpe(criteria: str) -> Cpe | None:
    """Parse a ``cpe:2.3:a:vendor:product:version:...`` string."""
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    fields = criteria.split(":")
    if len(fields) < 6:
        return None
    return Cpe(
        part=fields[2],
        vendor=fields[3].lower(),
        product=fields[4].lower(),
        version=fields[5].lower(),
    )


def cpe_product(cpe: str | None) -> str | None:
    """Extract the lower-cased product from a service CPE, accepting both the 2.3
    formatted URI (``cpe:2.3:a:vendor:product:version:...``) and the older 2.2 URI
    (``cpe:/a:vendor:product:version``) that Nmap emits. Only application/OS parts
    yield a product. This matters because Nmap's human ``product`` name (e.g.
    "Apache httpd") is not the CPE product ("http_server") CVEs are indexed under."""
    if not isinstance(cpe, str):
        return None
    if cpe.startswith("cpe:2.3:"):
        parsed = parse_cpe(cpe)
        return parsed.product if parsed else None
    if cpe.startswith("cpe:/"):
        fields = cpe.split(":")
        # ["cpe", "/a", vendor, product, version?, ...]
        if len(fields) >= 4 and fields[1] in ("/a", "/o"):
            product = fields[3].lower()
            return product or None
    return None


def products_from_cpe_matches(cpe_matches: list[dict[str, Any]]) -> set[str]:
    """Distinct application/OS product names (lower-cased) referenced by a CVE's
    CPE matches — the keys under which the CVE is indexed for correlation. Wildcard
    products (``*``/``-``) carry no product identity and are skipped."""
    products: set[str] = set()
    for m in cpe_matches:
        if not isinstance(m, dict):
            continue
        cpe = parse_cpe(m.get("criteria", ""))
        if cpe is not None and cpe.part in ("a", "o") and cpe.product not in ("*", "-", ""):
            products.add(cpe.product)
    return products


def _version_tuple(version: str) -> tuple[Any, ...]:
    """Split a version into comparable components (numeric where possible)."""
    parts: list[Any] = []
    token = ""
    is_digit = False
    for ch in version:
        if ch.isdigit():
            if token and not is_digit:
                parts.append(token)
                token = ""
            is_digit = True
            token += ch
        elif ch.isalnum():
            if token and is_digit:
                parts.append(int(token))
                token = ""
            is_digit = False
            token += ch
        else:  # separator
            if token:
                parts.append(int(token) if is_digit else token)
                token = ""
            is_digit = False
    if token:
        parts.append(int(token) if is_digit else token)
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    """Compare two version strings. Numeric components compare numerically;
    a purely lexical fallback is used when component types differ."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    for x, y in zip(ta, tb, strict=False):
        if type(x) is type(y):
            if x < y:
                return -1
            if x > y:
                return 1
        else:  # mixed int/str component: fall back to string compare
            sx, sy = str(x), str(y)
            if sx < sy:
                return -1
            if sx > sy:
                return 1
    if len(ta) < len(tb):
        return -1
    if len(ta) > len(tb):
        return 1
    return 0


def _version_in_range(version: str, m: dict[str, Any]) -> bool:
    """Whether ``version`` satisfies a cpeMatch's version-range constraints."""
    checks: tuple[tuple[str, Callable[[str], bool]], ...] = (
        ("versionStartIncluding", lambda c: _cmp(version, c) >= 0),
        ("versionStartExcluding", lambda c: _cmp(version, c) > 0),
        ("versionEndIncluding", lambda c: _cmp(version, c) <= 0),
        ("versionEndExcluding", lambda c: _cmp(version, c) < 0),
    )
    saw_bound = False
    for key, ok in checks:
        bound = m.get(key)
        if isinstance(bound, str) and bound:
            saw_bound = True
            if not ok(bound):
                return False
    return saw_bound


def match_confidence(
    cpe_matches: list[dict[str, Any]],
    *,
    product: str | None,
    version: str | None,
    service_cpe: str | None = None,
) -> MatchConfidence | None:
    """Return the best match confidence between a CVE's CPE matches and a
    service's product/version/CPE, or ``None`` if nothing matches.

    ``high``   — the service's own CPE product matches and the version fits.
    ``medium`` — product name matches and the version fits a specific/ranged CPE.
    ``low``    — product name matches but no version could be confirmed.
    """
    if not product:
        return None
    product_l = product.lower()
    service_cpe_parsed = parse_cpe(service_cpe) if service_cpe else None
    best: MatchConfidence | None = None
    rank = {MatchConfidence.LOW: 1, MatchConfidence.MEDIUM: 2, MatchConfidence.HIGH: 3}

    for m in cpe_matches:
        if not m.get("vulnerable", True):
            continue
        cpe = parse_cpe(m.get("criteria", ""))
        if cpe is None or cpe.part not in ("a", "o"):
            continue
        if cpe.product != product_l:
            continue

        confidence: MatchConfidence | None = None
        has_range = any(
            isinstance(m.get(k), str) and m.get(k)
            for k in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            )
        )
        specific_version = cpe.version not in ("*", "-", "")

        if version:
            version_l = version.lower()
            exact = specific_version and _cmp(version_l, cpe.version) == 0
            in_range = has_range and _version_in_range(version_l, m)
            if exact or in_range:
                confidence = MatchConfidence.MEDIUM
            # An exact CPE recorded on the service itself raises confidence.
            if (
                confidence is MatchConfidence.MEDIUM
                and service_cpe_parsed is not None
                and service_cpe_parsed.product == cpe.product
            ):
                confidence = MatchConfidence.HIGH
        if confidence is None and not specific_version and not has_range:
            # CPE matches the whole product with no version constraint.
            confidence = MatchConfidence.LOW

        if confidence is not None and (best is None or rank[confidence] > rank[best]):
            best = confidence

    return best
