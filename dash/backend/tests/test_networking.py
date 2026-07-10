"""Networking assistant + trusted-proxy hardening (Phase 23)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable

from app.services import networking as net
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import AsyncClient

from tests.conftest import probe_cert_headers

TRUSTED = net.parse_trusted_proxies("127.0.0.1/32,10.0.0.0/8,192.168.0.0/16")
EnrolledProbe = dict[str, str]


# --------------------------------------------------------------------------- #
# Trusted proxy (security-critical)
# --------------------------------------------------------------------------- #


def test_is_trusted_peer() -> None:
    assert net.is_trusted_peer("127.0.0.1", TRUSTED)
    assert net.is_trusted_peer("10.9.8.7", TRUSTED)
    assert not net.is_trusted_peer("8.8.8.8", TRUSTED)
    assert not net.is_trusted_peer("not-an-ip", TRUSTED)
    assert not net.is_trusted_peer(None, TRUSTED)


def test_forwarded_for_only_from_trusted_peer() -> None:
    # Trusted proxy: honor the forwarded client IP.
    assert net.client_ip_from_request("10.0.0.1", "203.0.113.9, 10.0.0.1", TRUSTED) == "203.0.113.9"
    # Untrusted peer: ignore the header, use the peer (no spoofing).
    assert net.client_ip_from_request("8.8.8.8", "203.0.113.9", TRUSTED) == "8.8.8.8"
    # No header: peer.
    assert net.client_ip_from_request("10.0.0.1", None, TRUSTED) == "10.0.0.1"


# --------------------------------------------------------------------------- #
# Hostname / certificate helpers
# --------------------------------------------------------------------------- #


def test_valid_hostname() -> None:
    assert net.valid_hostname("vulna.example.com")
    assert net.valid_hostname("192.168.1.10")
    assert net.valid_hostname("localhost")
    assert not net.valid_hostname("bad host")
    assert not net.valid_hostname("")


def test_cert_matches_hostname_wildcard() -> None:
    assert net.cert_matches_hostname("a.example.com", ["*.example.com"])
    assert net.cert_matches_hostname("vulna.example.com", ["vulna.example.com"])
    assert not net.cert_matches_hostname("a.b.example.com", ["*.example.com"])
    assert not net.cert_matches_hostname("example.com", ["*.example.com"])
    assert not net.cert_matches_hostname("evil.com", ["vulna.example.com"])


def _self_signed(hostname: str, days: int = 365) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_inspect_certificate_public_only() -> None:
    info = net.inspect_certificate(_self_signed("vulna.example.com"))
    assert "vulna.example.com" in info["dns_names"]
    assert info["expired"] is False
    assert info["days_left"] > 300
    # No private key material anywhere in the output.
    assert "PRIVATE" not in str(info)


def test_detect_issues() -> None:
    # public mode against a private host → split-DNS/private warning.
    issues = net.detect_issues(mode="public_dns", hostname="192.168.1.5", scheme="https")
    assert any(i["code"] == "split_dns_or_private" for i in issues)
    # cert name mismatch.
    cert_info = net.inspect_certificate(_self_signed("other.example.com"))
    issues = net.detect_issues(
        mode="manual_cert", hostname="vulna.example.com", scheme="https", cert_info=cert_info
    )
    assert any(i["code"] == "cert_name_mismatch" for i in issues)
    # clock skew.
    issues = net.detect_issues(
        mode="lan", hostname="host.local", scheme="https", clock_skew_seconds=1000
    )
    assert any(i["code"] == "clock_skew" for i in issues)


def test_snippet_has_trusted_proxy_note_no_keys() -> None:
    snip = net.reverse_proxy_snippet("vulna.example.com")
    assert "VULNA_TRUSTED_PROXIES" in snip
    assert "keep the key on the proxy" in snip


# --------------------------------------------------------------------------- #
# API + probe-auth spoofing defense
# --------------------------------------------------------------------------- #


async def test_untrusted_peer_cannot_spoof_probe_identity(
    client: AsyncClient,
    untrusted_client: AsyncClient,
    enroll_probe: Callable[..., Awaitable[EnrolledProbe]],
) -> None:
    probe = await enroll_probe()
    headers = probe_cert_headers(probe["fingerprint"])

    # From a trusted peer (loopback), the fingerprint header authenticates.
    hb_url = f"/api/v1/probes/{probe['probe_id']}/heartbeat"
    ok = await client.post(hb_url, json={}, headers=headers)
    assert ok.status_code == 200

    # From an untrusted peer, the same header is ignored → 401 (no spoofing).
    spoof = await untrusted_client.post(hb_url, json={}, headers=headers)
    assert spoof.status_code == 401


async def test_networking_status_and_validate(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    s = await client.get("/api/v1/networking/status", headers=admin_headers)
    assert s.status_code == 200
    assert "manual_cert" in s.json()["access_modes"]

    v = await client.post(
        "/api/v1/networking/validate",
        json={"mode": "public_dns", "hostname": "10.0.0.5", "scheme": "http"},
        headers=admin_headers,
    )
    assert v.status_code == 200
    codes = {i["code"] for i in v.json()["issues"]}
    assert "split_dns_or_private" in codes and "mixed_or_insecure" in codes


async def test_validate_rejects_private_key(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/networking/validate",
        json={
            "mode": "manual_cert",
            "hostname": "vulna.example.com",
            "certificate_pem": "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----",
        },
        headers=admin_headers,
    )
    assert r.status_code == 422  # never accept key material


async def test_url_change_plan(client: AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.post(
        "/api/v1/networking/url-change",
        json={"new_url": "https://vulna.example.com"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["apply"]["VULNA_DOMAIN"] == "vulna.example.com"
    assert "Scout" in body["scout_impact"]

    bad = await client.post(
        "/api/v1/networking/url-change", json={"new_url": "not a url"}, headers=admin_headers
    )
    assert bad.status_code == 422


async def test_test_browser_reports_trust(
    client: AsyncClient, untrusted_client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    trusted = await client.get("/api/v1/networking/test-browser", headers=admin_headers)
    assert trusted.json()["peer_is_trusted_proxy"] is True
    untrusted = await untrusted_client.get("/api/v1/networking/test-browser", headers=admin_headers)
    assert untrusted.json()["peer_is_trusted_proxy"] is False
