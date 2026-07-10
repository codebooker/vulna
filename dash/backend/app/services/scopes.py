"""Network-scope validation logic.

These are pure functions (no database access) so the security-critical CIDR
rules can be unit-tested in isolation (build plan Section 27.1, "CIDR
authorization"). The rules implemented here:

* CIDRs are normalized to canonical network form.
* ``0.0.0.0/0`` and ``::/0`` (and any prefix-length-0 range) are rejected.
* Public / globally-routable ranges are rejected unless explicitly allowed.
* Overlapping scopes within the same site are detected.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeValidationError(ValueError):
    """Raised when a proposed network scope violates a safety rule."""


def normalize_cidr(cidr: str) -> IPNetwork:
    """Parse and normalize a CIDR string to a canonical network object.

    Host bits are masked off (``strict=False``) so ``10.20.0.5/24`` normalizes
    to ``10.20.0.0/24``. Raises :class:`ScopeValidationError` on malformed input.
    """
    candidate = cidr.strip()
    if not candidate:
        raise ScopeValidationError("CIDR must not be empty")
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        raise ScopeValidationError(f"Invalid CIDR '{cidr}': {exc}") from exc


def validate_cidr(cidr: str, *, allow_public: bool = False) -> str:
    """Validate a CIDR against the scope safety rules and return its canonical form.

    Raises :class:`ScopeValidationError` if the range is a default route or is
    public while ``allow_public`` is ``False``.
    """
    network = normalize_cidr(cidr)

    # Reject default routes outright — they can never be an approved scope.
    if network.prefixlen == 0:
        raise ScopeValidationError(
            "Refusing to approve a default route (0.0.0.0/0 or ::/0); "
            "specify a bounded range"
        )

    if not allow_public and not network.is_private:
        raise ScopeValidationError(
            f"'{network}' is a public/globally-routable range. Public ranges are "
            "denied by default; enable 'allow public addresses' to override."
        )

    return str(network)


def find_overlaps(cidr: str, existing: Iterable[str]) -> list[str]:
    """Return the canonical existing CIDRs that overlap ``cidr``.

    Malformed existing entries are ignored (they should never have been stored),
    keeping the overlap check robust.
    """
    network = normalize_cidr(cidr)
    overlaps: list[str] = []
    for other in existing:
        try:
            other_network = normalize_cidr(other)
        except ScopeValidationError:
            continue
        if network.version != other_network.version:
            continue
        if network.overlaps(other_network):
            overlaps.append(str(other_network))
    return overlaps
