"""Networking / URL / TLS / reverse-proxy assistant logic (Phase 23).

Pure, unit-testable helpers for the five supported access modes, trusted-proxy
enforcement, certificate inspection (never private keys), issue detection with
plain-language explanations, and reverse-proxy snippet generation. Nothing here
disables certificate validation, and private key material is never accepted,
returned, or logged.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

# Supported application access modes.
ACCESS_MODES = ("localhost", "lan", "public_dns", "existing_proxy", "manual_cert")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


# --------------------------------------------------------------------------- #
# Trusted proxy
# --------------------------------------------------------------------------- #


def parse_trusted_proxies(spec: str) -> list[IPNetwork]:
    """Parse a comma-separated list of IPs/CIDRs into networks (bad entries dropped)."""
    nets: list[IPNetwork] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def is_trusted_peer(peer_ip: str | None, trusted: list[IPNetwork]) -> bool:
    """Return True only if the immediate peer address is within a trusted network.

    Forwarding headers (X-Forwarded-*, the probe fingerprint) are honored only when
    this is true, so an untrusted peer cannot spoof source address or TLS state.
    """
    if not peer_ip:
        return False
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(ip in net for net in trusted)


def client_ip_from_request(
    peer_ip: str | None, forwarded_for: str | None, trusted: list[IPNetwork]
) -> str | None:
    """Resolve the real client IP: the left-most X-Forwarded-For entry only when the
    peer is a trusted proxy, otherwise the peer address itself."""
    if forwarded_for and is_trusted_peer(peer_ip, trusted):
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return peer_ip


# --------------------------------------------------------------------------- #
# Hostname / URL validation
# --------------------------------------------------------------------------- #


def valid_hostname(host: str) -> bool:
    """Accept a syntactically valid DNS hostname or an IP address literal."""
    host = host.strip()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


def is_private_host(host: str) -> bool:
    """True if the host is an IP in a private/loopback range (best-effort)."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host in ("localhost",) or host.endswith(".local")


# --------------------------------------------------------------------------- #
# Certificate inspection (public parts only — never private keys)
# --------------------------------------------------------------------------- #


def inspect_certificate(pem: str, now: datetime | None = None) -> dict[str, Any]:
    """Return the public, non-sensitive details of a PEM certificate.

    Raises ValueError on unparseable input. Never accepts or returns key material.
    """
    now = now or datetime.now(UTC)
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface a friendly message
        raise ValueError(f"Could not parse certificate: {exc}") from exc

    dns_names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = list(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    cn = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        cn = cn_attrs[0].value

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_left = int((not_after - now).total_seconds() // 86400)
    return {
        "common_name": cn,
        "dns_names": dns_names,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": now > not_after or now < not_before,
        "days_left": days_left,
    }


def cert_matches_hostname(hostname: str, names: list[str]) -> bool:
    """Wildcard-aware match of a hostname against a certificate's DNS names/CN."""
    host = hostname.strip().lower().rstrip(".")
    for raw in names:
        name = raw.strip().lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            # Wildcard matches exactly one left-most label.
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


# --------------------------------------------------------------------------- #
# Issue detection with plain-language explanations
# --------------------------------------------------------------------------- #


def detect_issues(
    *,
    mode: str,
    hostname: str,
    scheme: str,
    cert_info: dict[str, Any] | None = None,
    clock_skew_seconds: float | None = None,
) -> list[dict[str, str]]:
    """Return a list of detected problems, each with a plain-language explanation
    and a corrective action. Empty list means nothing detected."""
    issues: list[dict[str, str]] = []

    if not valid_hostname(hostname):
        issues.append(
            {
                "code": "invalid_hostname",
                "problem": f"'{hostname}' is not a valid hostname or IP.",
                "action": "Enter a valid DNS name (e.g. vulna.example.com) or IP address.",
            }
        )

    if mode == "public_dns" and is_private_host(hostname):
        issues.append(
            {
                "code": "split_dns_or_private",
                "problem": f"'{hostname}' looks private/local but public access was selected.",
                "action": "Use a publicly resolvable DNS name, or choose the LAN access mode. "
                "If you use split DNS/NAT loopback, ensure the name resolves correctly "
                "from where you browse.",
            }
        )

    if mode in ("public_dns", "manual_cert") and scheme == "http":
        issues.append(
            {
                "code": "mixed_or_insecure",
                "problem": "The site was reached over HTTP while TLS was expected.",
                "action": "Reach the site over HTTPS. Mixed HTTP/HTTPS content will be blocked "
                "by the browser; ensure all links use https.",
            }
        )

    if clock_skew_seconds is not None and abs(clock_skew_seconds) > 300:
        issues.append(
            {
                "code": "clock_skew",
                "problem": "The system clock is off by more than 5 minutes.",
                "action": "Enable NTP (e.g. `timedatectl set-ntp true`). TLS certificate "
                "validation fails with an inaccurate clock.",
            }
        )

    if cert_info is not None:
        if cert_info.get("expired"):
            issues.append(
                {
                    "code": "cert_expired",
                    "problem": f"The certificate for {hostname} is expired or not yet valid.",
                    "action": "Renew or replace the certificate; check the not_before/not_after "
                    "dates and the system clock.",
                }
            )
        elif isinstance(cert_info.get("days_left"), int) and cert_info["days_left"] < 14:
            issues.append(
                {
                    "code": "cert_expiring",
                    "problem": f"The certificate expires in {cert_info['days_left']} day(s).",
                    "action": "Renew the certificate soon to avoid an outage.",
                }
            )
        names = list(cert_info.get("dns_names") or [])
        if cert_info.get("common_name"):
            names.append(cert_info["common_name"])
        if names and not cert_matches_hostname(hostname, names):
            issues.append(
                {
                    "code": "cert_name_mismatch",
                    "problem": f"The certificate does not cover '{hostname}'. It is valid for: "
                    f"{', '.join(sorted(set(names)))}.",
                    "action": "Use a certificate whose subject/SAN includes this hostname, or "
                    "browse to a name the certificate covers.",
                }
            )
    return issues


# --------------------------------------------------------------------------- #
# Access-mode settings and reverse-proxy snippet
# --------------------------------------------------------------------------- #


def access_mode_settings(
    mode: str, hostname: str = "localhost", acme_email: str | None = None
) -> dict[str, Any]:
    """Return the environment/settings for an access mode, plus any warnings."""
    warnings: list[str] = []
    domain = hostname
    caddy_tls = "internal"

    if mode == "localhost":
        domain = "localhost"
    elif mode == "lan":
        caddy_tls = "internal"
        warnings.append(
            "LAN mode uses a self-signed internal CA; browsers warn until you trust it."
        )
    elif mode == "public_dns":
        caddy_tls = acme_email or "internal"
        warnings.append(
            "Public access exposes the login to the internet. Before enabling it, ensure a "
            "strong admin password, keep updates and backups current, and consider rate limiting."
        )
    elif mode == "existing_proxy":
        warnings.append(
            "Behind your own proxy, configure the trusted-proxy list (VULNA_TRUSTED_PROXIES) to "
            "your proxy's address so forwarded headers are honored only from it."
        )
    elif mode == "manual_cert":
        warnings.append(
            "Provide the certificate and key to the proxy out-of-band; "
            "never paste keys into Vulna."
        )

    return {
        "mode": mode,
        "vulna_domain": domain,
        "caddy_tls": caddy_tls,
        "cors_origins": _origins_for(domain, mode),
        "warnings": warnings,
    }


def _origins_for(domain: str, mode: str) -> str:
    scheme = "http" if mode == "localhost" else "https"
    return f"{scheme}://{domain}"


def reverse_proxy_snippet(hostname: str, api_upstream: str = "127.0.0.1:8000") -> str:
    """Generate an nginx snippet for the 'existing reverse proxy' mode.

    It forwards the verified TLS state and preserves the Scout mutual-TLS boundary
    note. It never trusts forwarded headers blindly — the app additionally enforces
    its trusted-proxy list.
    """
    return f"""# nginx reverse-proxy snippet for VulnaDash ({hostname}).
# Terminate the browser-facing TLS here. This is SEPARATE from VulnaScout mutual
# TLS (that is terminated by the bundled Caddy against the internal CA and must
# not be proxied through here). Set VULNA_TRUSTED_PROXIES to this proxy's address.
server {{
    listen 443 ssl;
    server_name {hostname};

    # ssl_certificate     /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;   # keep the key on the proxy only

    location / {{
        proxy_pass http://{api_upstream};
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # do NOT append client-supplied values
        proxy_set_header X-Forwarded-Proto $scheme;
        # Do NOT forward X-Vulna-Client-Cert-Fingerprint from the browser path.
    }}
}}
"""
