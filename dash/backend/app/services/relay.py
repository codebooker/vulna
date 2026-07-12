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

import base64
import ipaddress
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import Settings
from app.models.enums import RelayStatus
from app.models.organization import Organization
from app.models.relay import Relay
from app.services.scopes import ScopeValidationError, validate_cidr

RELAY_ENABLED_FLAG = "relay_mode_enabled"


# --------------------------------------------------------------------------- #
# Feature flag: relays are available by default, like Scouts. Admins can still
# turn the whole subsystem off as an org-wide kill switch, and each relay has its
# own kill switch, but there is no opt-in step before a relay can be enrolled.
# --------------------------------------------------------------------------- #


def relay_enabled(org: Organization) -> bool:
    return bool((org.settings_json or {}).get(RELAY_ENABLED_FLAG, True))


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


def overlapping_cidrs(left: list[str], right: list[str]) -> tuple[str, str] | None:
    """Return the first overlapping pair, if any.

    WireGuard AllowedIPs are one routing table: two relay peers cannot safely claim
    overlapping destination ranges because traffic would be routed to only one of
    them. Reject the ambiguity at configuration time.
    """
    for a in left:
        net_a = ipaddress.ip_network(a, strict=False)
        for b in right:
            net_b = ipaddress.ip_network(b, strict=False)
            if net_a.version == net_b.version and net_a.overlaps(net_b):
                return a, b
    return None


async def allocate_tunnel_address(session: AsyncSession, settings: Settings) -> str:
    """Allocate the first free client address from the configured WireGuard subnet.

    The first usable address belongs to the central egress. Relay addresses begin at
    the second usable address and are persisted under a unique constraint, so an
    address is never silently shared by two peers.
    """
    network = ipaddress.ip_network(settings.relay_tunnel_cidr, strict=False)
    used = set((await session.execute(select(Relay.tunnel_address))).scalars())
    hosts = network.hosts()
    next(hosts, None)  # central egress address
    for address in hosts:
        candidate = f"{address}/{network.max_prefixlen}"
        if candidate not in used:
            return candidate
    raise ValueError(f"Relay tunnel subnet {network} has no free client addresses")


def relay_server_address(settings: Settings) -> str:
    network = ipaddress.ip_network(settings.relay_tunnel_cidr, strict=False)
    address = next(network.hosts(), None)
    if address is None:
        raise ValueError(f"Relay tunnel subnet {network} has no usable server address")
    return f"{address}/{network.prefixlen}"


def relay_endpoint(settings: Settings) -> str:
    if settings.relay_endpoint:
        return settings.relay_endpoint
    parsed = urlparse(settings.public_base_url or "")
    host = parsed.hostname
    if not host:
        raise ValueError("VULNA_RELAY_ENDPOINT or VULNA_PUBLIC_BASE_URL must be configured")
    rendered = f"[{host}]" if ":" in host else host
    return f"{rendered}:{settings.relay_listen_port}"


def relay_control_url(settings: Settings) -> str:
    if settings.relay_control_url:
        return settings.relay_control_url.rstrip("/")
    parsed = urlparse(settings.public_base_url or "")
    if not parsed.hostname:
        raise ValueError("VULNA_RELAY_CONTROL_URL or VULNA_PUBLIC_BASE_URL must be configured")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme or 'https'}://{host}:8443"


def relay_server_public_key(settings: Settings) -> str:
    try:
        with open(settings.relay_server_public_key_path, encoding="utf-8") as key_file:
            value = key_file.read().strip()
    except OSError as exc:
        raise ValueError("Relay egress has not published its WireGuard public key yet") from exc
    if not value:
        raise ValueError("Relay egress WireGuard public key is empty")
    return value


# --------------------------------------------------------------------------- #
# Relay install command (thin appliance, no scanners)
# --------------------------------------------------------------------------- #


def build_relay_install(settings: Settings, token: str, name: str) -> dict[str, str]:
    """Copy-paste command to bring up a thin relay (tunnel only, no scanners).

    The token is passed via the environment, not on the command line, so it does
    not linger in process listings.
    """
    base = relay_control_url(settings)
    version = settings.release_version or settings.version
    tag = version if version.startswith("v") else f"v{version}"
    installer = f"https://github.com/codebooker/vulna/releases/download/{tag}/install-relay.sh"
    ca_env = ""
    ca_path = Path(settings.bootstrap_dir) / "orchestrator-ca.crt"
    try:
        ca_b64 = base64.b64encode(ca_path.read_bytes()).decode("ascii")
    except OSError:
        ca_b64 = ""
    if ca_b64:
        ca_env = f"VULNA_SERVER_CA_B64={shlex.quote(ca_b64)} "
    one_liner = (
        f"curl -fsSLo /tmp/install-relay.sh {shlex.quote(installer)} && "
        f"VULNA_SERVER={shlex.quote(base)} VULNA_RELAY_TOKEN={shlex.quote(token)} "
        f"VULNA_RELAY_NAME={shlex.quote(name)} {ca_env}VULNA_VERSION={shlex.quote(tag)} "
        "sh /tmp/install-relay.sh"
    )
    return {
        "name": name,
        "command": one_liner,
        "note": (
            "Run as root. Installs the signed scanner-free WireGuard relay agent. The "
            "relay never receives job-signing keys or scanner credentials."
        ),
    }
