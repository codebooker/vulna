"""VulnaRelay control plane and central egress enforcement (Phase 16, opt-in).

VulnaRelay is a thin-site tunnel mode: the site runs a minimal authenticated
tunnel with **no scanners**, and a central scanner reaches the site through it.
It is **off by default** and must be turned on in settings; the smart VulnaScout
probe (which enforces its scope and kill switch locally) remains the default.

Because a relay has no local cryptographic boundary, scope is enforced at the
**central egress**. :func:`egress_decision` is that authority: scan traffic may
leave toward a relay's approved CIDRs only while the relay is enrolled and its
tunnel is up. Tearing the tunnel or engaging the kill switch immediately blocks
all scanning for that relay. The relay never receives job-signing keys or scanner
credentials.

The egress decision is pure and unit-testable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy.orm.attributes import flag_modified

from app.models.enums import RelayStatus
from app.models.organization import Organization
from app.services.scopes import ScopeValidationError, validate_cidr

RELAY_ENABLED_FLAG = "relay_mode_enabled"


# --------------------------------------------------------------------------- #
# Feature flag: OFF by default; enabled in dashboard settings
# --------------------------------------------------------------------------- #


def relay_enabled(org: Organization) -> bool:
    return bool((org.settings_json or {}).get(RELAY_ENABLED_FLAG, False))


def set_relay_enabled(org: Organization, enabled: bool) -> bool:
    settings = dict(org.settings_json or {})
    settings[RELAY_ENABLED_FLAG] = bool(enabled)
    org.settings_json = settings
    flag_modified(org, "settings_json")
    return relay_enabled(org)


# --------------------------------------------------------------------------- #
# Central egress enforcement (the security core)
# --------------------------------------------------------------------------- #


@dataclass
class EgressDecision:
    allowed: bool
    reason: str


_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _target_network(target: str) -> _Net:
    t = target.strip()
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError as exc:  # a bare IP is fine too
        raise ScopeValidationError(f"Invalid target '{target}': {exc}") from exc


def _within(target: _Net, cidrs: list[str]) -> bool:
    """True if ``target`` is fully contained in any of ``cidrs`` (same IP version)."""
    t_lo, t_hi = int(target.network_address), int(target.broadcast_address)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            continue
        if target.version != net.version:
            continue
        if int(net.network_address) <= t_lo and t_hi <= int(net.broadcast_address):
            return True
    return False


def _overlaps_any(target: _Net, cidrs: list[str]) -> bool:
    """True if ``target`` overlaps any of ``cidrs`` at all (same IP version).

    Deny rules use overlap, not containment: a denied host inside a larger target
    block must still block the whole block, otherwise a broad target (e.g. a /16
    that contains one denied host) would slip past the deny list.
    """
    t_lo, t_hi = int(target.network_address), int(target.broadcast_address)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            continue
        if target.version != net.version:
            continue
        if int(net.network_address) <= t_hi and t_lo <= int(net.broadcast_address):
            return True
    return False


def egress_decision(
    target: str,
    approved_cidrs: list[str],
    denied_cidrs: list[str],
    *,
    status: RelayStatus,
    tunnel_up: bool,
) -> EgressDecision:
    """Decide whether scan traffic may egress to ``target`` through a relay.

    Fails closed: an unenrolled/killed relay, a down tunnel, or an out-of-scope or
    explicitly denied target all block the traffic, each with a clear reason.
    """
    if status == RelayStatus.KILLED:
        return EgressDecision(False, "The relay kill switch is engaged; scanning is blocked.")
    if status != RelayStatus.ENROLLED:
        return EgressDecision(False, f"The relay is not enrolled (status: {status.value}).")
    if not tunnel_up:
        return EgressDecision(False, "The relay tunnel is down; scanning is blocked.")

    try:
        net = _target_network(target)
    except ScopeValidationError as exc:
        return EgressDecision(False, str(exc))

    if _overlaps_any(net, denied_cidrs):
        return EgressDecision(False, f"Target {target} overlaps an explicitly denied range.")
    if not _within(net, approved_cidrs):
        return EgressDecision(
            False,
            f"Target {target} is outside the relay's approved scope; the central "
            "egress blocks out-of-scope destinations.",
        )
    return EgressDecision(True, "Target is within the relay's approved scope.")


def validate_egress_cidrs(cidrs: list[str], *, allow_public: bool = False) -> list[str]:
    """Validate and canonicalize a relay's approved egress CIDRs (scope rules apply)."""
    out: list[str] = []
    for c in cidrs:
        out.append(validate_cidr(c, allow_public=allow_public))
    return out


# --------------------------------------------------------------------------- #
# Relay install command (thin appliance, no scanners)
# --------------------------------------------------------------------------- #


def build_relay_install(server_url: str, token: str, name: str) -> dict[str, str]:
    """Copy-paste command to bring up a thin relay (tunnel only, no scanners).

    The token is passed via the environment, not on the command line, so it does
    not linger in process listings.
    """
    base = server_url.rstrip("/") if server_url else "https://vulna.example"
    one_liner = (
        f"VULNA_SERVER={base} VULNA_RELAY_TOKEN={token} "
        f"VULNA_RELAY_NAME={name!r} sh install-relay.sh"
    )
    return {
        "name": name,
        "command": one_liner,
        "note": (
            "Installs the relay image (WireGuard tunnel endpoint, no scanners). The "
            "relay never receives job-signing keys or scanner credentials."
        ),
    }
