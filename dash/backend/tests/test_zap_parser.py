"""Unit tests for the ZAP traditional-json report parser."""

from __future__ import annotations

import json

import pytest
from app.models.enums import FindingType, Severity
from app.services.zap_parser import ZapParseError, parse_zap_json

ZAP_REPORT = json.dumps(
    {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://10.20.0.5",
                "@host": "10.20.0.5",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alertRef": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "2",
                        "desc": "<p>Reflected <b>XSS</b> found.</p>",
                        "solution": "<p>Encode output &amp; validate input.</p>",
                        "reference": "<p>https://owasp.org/xss https://cwe.mitre.org/79</p>",
                        "cweid": "79",
                        "instances": [
                            {
                                "uri": "http://10.20.0.5/q?x=1",
                                "method": "GET",
                                "param": "x",
                                "attack": "<script>alert(1)</script>",
                                "evidence": "<script>",
                            }
                        ],
                    },
                    {
                        "pluginid": "10038",
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "1",
                        "desc": "CSP missing",
                        "cweid": "693",
                        "instances": [],
                    },
                ],
            }
        ],
    }
).encode()


def test_parse_zap_maps_alerts_to_findings() -> None:
    findings = parse_zap_json(ZAP_REPORT)
    assert len(findings) == 2
    xss = findings[0]
    assert xss.scanner == "zap"
    assert xss.finding_type == FindingType.WEB_APPLICATION_ISSUE
    assert xss.severity == Severity.HIGH  # riskcode 3
    assert xss.weakness_key == "40012"
    assert xss.target_ip == "10.20.0.5"
    assert xss.port == 443
    assert xss.cwe_ids == ["CWE-79"]
    # HTML is stripped from description/solution.
    assert xss.description == "Reflected XSS found."
    assert xss.remediation is not None and "<b>" not in xss.remediation
    # References are extracted as URLs.
    assert "https://owasp.org/xss" in xss.references
    # Evidence captures the first instance.
    assert xss.evidence["param"] == "x"
    assert xss.evidence["uri"] == "http://10.20.0.5/q?x=1"

    csp = findings[1]
    assert csp.severity == Severity.LOW  # riskcode 1
    assert csp.evidence["instance_count"] == 0


def test_parse_zap_skips_malformed_structure() -> None:
    # Missing/emtpy sites and alerts are tolerated, not raised.
    assert parse_zap_json(b'{"site": []}') == []
    assert parse_zap_json(b'{"site": [{"@host": "h", "alerts": "nope"}]}') == []


def test_parse_zap_rejects_non_json() -> None:
    with pytest.raises(ZapParseError):
        parse_zap_json(b"<html>not json</html>")
