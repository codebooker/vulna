"""Unit tests for the Nuclei and testssl.sh finding parsers."""

from __future__ import annotations

import pytest
from app.models.enums import FindingType, Severity
from app.services.nuclei_parser import parse_nuclei_jsonl
from app.services.testssl_parser import TestsslParseError, parse_testssl_json

NUCLEI_JSONL = (
    b'{"template-id":"tls-version","type":"ssl","host":"10.20.0.5:443",'
    b'"matched-at":"10.20.0.5:443","ip":"10.20.0.5","info":{"name":"TLS 1.0 detected",'
    b'"severity":"low","description":"Legacy TLS","reference":["https://ex/1"],'
    b'"classification":{"cve-id":["CVE-2011-3389"],"cwe-id":["CWE-327"],'
    b'"cvss-score":4.3,"cvss-metrics":"CVSS:3.1/AV:N"}}}\n'
    b'{"template-id":"missing-header","type":"http","host":"http://10.20.0.5:8080/",'
    b'"matched-at":"http://10.20.0.5:8080/","matcher-name":"x-frame",'
    b'"info":{"name":"Missing header","severity":"info"}}\n'
    b"this is not json and should be skipped\n"
)


def test_parse_nuclei_jsonl() -> None:
    findings = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(findings) == 2  # the garbage line is skipped

    tls = findings[0]
    assert tls.scanner == "nuclei"
    assert tls.severity == Severity.LOW
    assert tls.target_ip == "10.20.0.5"
    assert tls.port == 443
    assert tls.cve_ids == ["CVE-2011-3389"]
    assert tls.cwe_ids == ["CWE-327"]
    assert tls.cvss_score == 4.3
    assert tls.references == ["https://ex/1"]

    hdr = findings[1]
    assert hdr.finding_type == FindingType.WEB_APPLICATION_ISSUE
    assert hdr.port == 8080
    assert hdr.weakness_key == "missing-header:x-frame"


def test_parse_nuclei_empty() -> None:
    assert parse_nuclei_jsonl(b"") == []


TESTSSL_JSON = (
    b'[{"id":"SSLv3","ip":"host/10.20.0.5","port":"443","severity":"HIGH",'
    b'"finding":"SSLv3 is offered"},'
    b'{"id":"cipherlist","fqdn/ip":"host/10.20.0.5","port":"443","severity":"OK",'
    b'"finding":"no weak ciphers"},'
    b'{"id":"cert_expiration","ip":"10.20.0.5","port":"443","severity":"MEDIUM",'
    b'"finding":"certificate expired","cve":"CVE-2020-1971"}]'
)


def test_parse_testssl_json() -> None:
    findings = parse_testssl_json(TESTSSL_JSON)
    assert len(findings) == 2  # the OK result is skipped

    sslv3 = findings[0]
    assert sslv3.scanner == "testssl"
    assert sslv3.severity == Severity.HIGH
    assert sslv3.target_ip == "10.20.0.5"
    assert sslv3.port == 443
    assert sslv3.weakness_key == "SSLv3"
    assert sslv3.finding_type == FindingType.WEAK_PROTOCOL
    # A readable title from the catalog instead of the raw "SSLv3 is offered".
    assert sslv3.title == "SSLv3 supported"
    assert "Disable SSLv3" in (sslv3.remediation or "")
    assert sslv3.evidence["check_id"] == "SSLv3"
    assert sslv3.evidence["finding"] == "SSLv3 is offered"

    cert = findings[1]
    assert cert.cve_ids == ["CVE-2020-1971"]
    # Legacy check ids normalize onto the canonical certificate-expiry family.
    assert cert.title == "Certificate expiry"
    assert cert.weakness_key == "cert_expirationStatus"
    assert cert.finding_type == FindingType.MISCONFIGURATION
    assert cert.remediation


def test_parse_testssl_named_vuln_has_cve_and_remediation() -> None:
    data = (
        b'[{"id":"heartbleed","ip":"10.0.0.5","port":"443","severity":"CRITICAL",'
        b'"finding":"VULNERABLE","cve":"CVE-2014-0160","cwe":"CWE-119"}]'
    )
    (f,) = parse_testssl_json(data)
    assert f.title == "Heartbleed"  # not the raw "VULNERABLE"
    assert f.finding_type == FindingType.VULNERABILITY
    assert f.cve_ids == ["CVE-2014-0160"]
    assert f.cwe_ids == ["CWE-119"]
    assert "OpenSSL" in (f.remediation or "")
    assert f.evidence["cve"] == "CVE-2014-0160"


def test_parse_testssl_wrapped_object() -> None:
    wrapped = (
        b'{"scanResult":[{"id":"x","ip":"1.2.3.4","port":"443",'
        b'"severity":"LOW","finding":"f"}]}'
    )
    assert len(parse_testssl_json(wrapped)) == 1


def test_parse_testssl_ignores_handshake_summaries_and_deduplicates_aliases() -> None:
    data = (
        b'[{"id":"protocol_negotiated","ip":"10.0.0.5","port":"443",'
        b'"severity":"LOW","finding":"TLSv1.2"},'
        b'{"id":"cipher_negotiated","ip":"10.0.0.5","port":"443",'
        b'"severity":"HIGH","finding":"ECDHE-RSA-AES256-GCM-SHA384"},'
        b'{"id":"cipherlist_STRONG","ip":"10.0.0.5","port":"443",'
        b'"severity":"MEDIUM","finding":"strong ciphers available"},'
        b'{"id":"BEAST","ip":"10.0.0.5","port":"443",'
        b'"severity":"LOW","finding":"CBC offered"},'
        b'{"id":"BEAST_CBC_TLS1","ip":"10.0.0.5","port":"443",'
        b'"severity":"MEDIUM","finding":"CBC offered with TLS 1.0"}]'
    )

    (finding,) = parse_testssl_json(data)

    assert finding.weakness_key == "BEAST"
    assert finding.title == "BEAST (TLS 1.0 CBC)"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["scanner_check_id"] == "BEAST_CBC_TLS1"


def test_parse_testssl_malformed_raises() -> None:
    with pytest.raises(TestsslParseError):
        parse_testssl_json(b"not json at all")
