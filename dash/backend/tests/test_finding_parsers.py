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

    cert = findings[1]
    assert cert.cve_ids == ["CVE-2020-1971"]


def test_parse_testssl_wrapped_object() -> None:
    wrapped = (
        b'{"scanResult":[{"id":"x","ip":"1.2.3.4","port":"443",'
        b'"severity":"LOW","finding":"f"}]}'
    )
    assert len(parse_testssl_json(wrapped)) == 1


def test_parse_testssl_malformed_raises() -> None:
    with pytest.raises(TestsslParseError):
        parse_testssl_json(b"not json at all")
