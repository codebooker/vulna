"""Parse testssl.sh JSON output into normalized findings.

testssl.sh ``--json`` emits a flat list of check results. Only results at LOW
severity or above become findings; OK/INFO/WARN/DEBUG are ignored. Output is
untrusted; malformed entries are skipped and the input size is bounded by the
caller.

Each check is mapped through a catalog to a human-readable title, a finding type,
and practical remediation, so a raw ``"VULNERABLE"`` / ``"offered"`` string
becomes an actionable finding (e.g. "Heartbleed" with a fix). Unknown checks fall
back to a humanized id and category-based remediation, so nothing is left bare.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.models.enums import FindingType, ServiceTransport, Severity
from app.services.findings import ParsedFinding

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_PROTOCOL = FindingType.WEAK_PROTOCOL
_CIPHER = FindingType.WEAK_PROTOCOL
_VULN = FindingType.VULNERABILITY
_CERT = FindingType.MISCONFIGURATION


class TestsslParseError(ValueError):
    """Raised when testssl.sh JSON is malformed."""

    __test__ = False  # not a pytest test class despite the "Test" prefix


@dataclass(frozen=True)
class _Check:
    title: str
    finding_type: FindingType
    remediation: str


# Well-known testssl checks -> readable title + finding type + remediation.
def _c(title: str, finding_type: FindingType, remediation: str) -> _Check:
    return _Check(title, finding_type, remediation)


_CATALOG: dict[str, _Check] = {
    # Legacy protocols
    "SSLv2": _c("SSLv2 supported", _PROTOCOL, "Disable SSLv2; serve only TLS 1.2 and 1.3."),
    "SSLv3": _c("SSLv3 supported", _PROTOCOL, "Disable SSLv3; serve only TLS 1.2 and 1.3."),
    "TLS1": _c("TLS 1.0 supported", _PROTOCOL, "Disable TLS 1.0; offer only TLS 1.2 and TLS 1.3."),
    "TLS1_1": _c("TLS 1.1 supported", _PROTOCOL, "Disable TLS 1.1; serve only TLS 1.2 and 1.3."),
    # Named vulnerabilities
    "heartbleed": _c(
        "Heartbleed",
        _VULN,
        "Upgrade OpenSSL to 1.0.1g or later, then rotate the server's private key "
        "and reissue its certificate — both may have been exposed.",
    ),
    "CCS": _c("OpenSSL CCS injection", _VULN, "Update OpenSSL to fix CVE-2014-0224."),
    "ticketbleed": _c(
        "Ticketbleed", _VULN, "Update the F5 BIG-IP firmware to a fixed version (CVE-2016-9244)."
    ),
    "ROBOT": _c(
        "ROBOT (RSA decryption oracle)",
        _VULN,
        "Disable RSA key-exchange cipher suites, or patch the TLS stack against ROBOT.",
    ),
    "secure_renego": _c(
        "Insecure TLS renegotiation",
        _VULN,
        "Enable only RFC 5746 secure renegotiation and disable client-initiated renegotiation.",
    ),
    "secure_client_renego": _c(
        "Client-initiated renegotiation allowed",
        _VULN,
        "Disable client-initiated TLS renegotiation to prevent denial-of-service.",
    ),
    "CRIME_TLS": _c("CRIME (TLS compression)", _VULN, "Disable TLS-level compression."),
    "POODLE_SSL": _c("POODLE (SSLv3)", _VULN, "Disable SSLv3 on the server."),
    "fallback_SCSV": _c(
        "Missing TLS_FALLBACK_SCSV",
        _CIPHER,
        "Enable TLS_FALLBACK_SCSV to prevent protocol-downgrade attacks.",
    ),
    "SWEET32": _c(
        "SWEET32 (64-bit block cipher)", _VULN, "Disable 64-bit block ciphers (3DES/DES-CBC3)."
    ),
    "FREAK": _c("FREAK (export RSA)", _VULN, "Disable all export-grade RSA cipher suites."),
    "DROWN": _c(
        "DROWN (SSLv2)",
        _VULN,
        "Disable SSLv2 on every service and never share the certificate/key with an "
        "SSLv2-enabled host.",
    ),
    "LOGJAM": _c(
        "Logjam (weak DH)",
        _VULN,
        "Use unique 2048-bit-or-larger DH parameters and disable export DHE cipher suites.",
    ),
    "BEAST": _c(
        "BEAST (TLS 1.0 CBC)", _CIPHER, "Prefer TLS 1.2+ and prioritize AEAD (GCM) cipher suites."
    ),
    "LUCKY13": _c("Lucky13", _VULN, "Update the TLS library; prefer AEAD ciphers over CBC."),
    "RC4": _c("RC4 cipher suites offered", _CIPHER, "Disable all RC4 cipher suites."),
    "PFS": _c("No forward secrecy", _CIPHER, "Enable forward-secret (ECDHE/DHE) cipher suites."),
    # Certificate issues
    "cert_chain_of_trust": _c(
        "Certificate chain not trusted",
        _CERT,
        "Install the complete certificate chain from a publicly-trusted CA.",
    ),
    "cert_trust": _c(
        "Certificate not trusted / hostname mismatch",
        _CERT,
        "Reissue the certificate from a trusted CA with a SAN matching the served hostname.",
    ),
    "cert_expirationStatus": _c(
        "Certificate expiry", _CERT, "Renew the certificate before the current one expires."
    ),
    "cert_notAfter": _c(
        "Certificate validity (notAfter)",
        _CERT,
        "Renew and install a certificate before the current one expires.",
    ),
    "cert_subjectAltName": _c(
        "Certificate Subject Alternative Name",
        _CERT,
        "Reissue the certificate with a SAN that covers the hostname (modern browsers ignore CN).",
    ),
    "cert_signatureAlgorithm": _c(
        "Weak certificate signature algorithm",
        _CERT,
        "Reissue the certificate with a SHA-256-or-stronger signature.",
    ),
    "cert_keySize": _c(
        "Weak certificate key size",
        _CERT,
        "Reissue with a 2048-bit-or-larger RSA key (or a 256-bit-or-larger ECDSA key).",
    ),
    "OCSP_stapling": _c(
        "OCSP stapling not enabled",
        _CERT,
        "Enable OCSP stapling so clients can check revocation efficiently.",
    ),
}


def _fallback(check_id: str) -> tuple[FindingType, str]:
    """Category (by id prefix) for a check not in the catalog."""
    cid = check_id.lower()
    if cid.startswith("cert") or cid.startswith("ocsp") or "crl" in cid:
        return _CERT, "Review the certificate configuration and reissue/renew as needed."
    if cid.startswith("cipher") or "rc4" in cid or "3des" in cid or "cbc" in cid:
        return _CIPHER, "Remove weak cipher suites; prefer forward-secret AEAD (GCM) ciphers."
    if cid.startswith("ssl") or cid.startswith("tls"):
        return _PROTOCOL, "Disable legacy SSL/TLS versions; serve only TLS 1.2 and 1.3."
    return _PROTOCOL, "Harden the server's TLS configuration to address this issue."


def _humanize(check_id: str) -> str:
    """Readable title for a check with no catalog entry."""
    text = check_id.replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else check_id


def _target_ip(entry: dict[str, Any]) -> str | None:
    raw = entry.get("ip") or entry.get("fqdn/ip") or ""
    if not isinstance(raw, str) or not raw:
        return None
    # testssl reports "fqdn/ip"; take the address portion.
    return raw.split("/")[-1] or None


def parse_testssl_json(data: bytes) -> list[ParsedFinding]:
    """Parse testssl.sh JSON bytes into findings."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as exc:
        raise TestsslParseError(f"Invalid testssl JSON: {exc}") from exc

    # The flat --json format is a list; some builds wrap it in {"scanResult": [...]}
    if isinstance(parsed, dict):
        parsed = parsed.get("scanResult") or parsed.get("results") or []
    if not isinstance(parsed, list):
        raise TestsslParseError("Unexpected testssl JSON structure")

    findings: list[ParsedFinding] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        severity = _SEVERITY.get(str(entry.get("severity", "")).upper())
        if severity is None:
            continue
        check_id = str(entry.get("id") or "unknown")
        finding_text = str(entry.get("finding") or "")
        port: int | None = None
        try:
            port = int(entry["port"]) if entry.get("port") else None
        except (TypeError, ValueError):
            port = None
        cve = entry.get("cve")
        cve_ids = cve.split() if isinstance(cve, str) and cve else []
        cwe = entry.get("cwe")
        cwe_ids = cwe.split() if isinstance(cwe, str) and cwe else []

        check = _CATALOG.get(check_id)
        if check is not None:
            title, finding_type, remediation = check.title, check.finding_type, check.remediation
        else:
            finding_type, remediation = _fallback(check_id)
            title = _humanize(check_id)

        # Describe what was observed, pairing the readable check with testssl's raw
        # result so the observation is specific (e.g. "Heartbleed — VULNERABLE").
        description = f"{title} — {finding_text}" if finding_text else title
        evidence: dict[str, object] = {
            "check_id": check_id,
            "finding": finding_text,
            "severity": str(entry.get("severity", "")),
        }
        if cve_ids:
            evidence["cve"] = " ".join(cve_ids)
        if cwe_ids:
            evidence["cwe"] = " ".join(cwe_ids)

        findings.append(
            ParsedFinding(
                scanner="testssl",
                weakness_key=check_id,
                finding_type=finding_type,
                title=title,
                severity=severity,
                target_ip=_target_ip(entry),
                port=port,
                transport=ServiceTransport.TCP,
                description=description,
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                remediation=remediation,
                evidence=evidence,
                scanner_finding_id=check_id,
            )
        )
    return findings
