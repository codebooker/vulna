"""Allowlisted NSE script results -> findings (e.g. anonymous FTP)."""

from __future__ import annotations

from app.models.enums import FindingType, ServiceState, ServiceTransport, Severity
from app.services.nmap_parser import ParsedHost, ParsedService, parse_nmap_xml
from app.services.nse_findings import findings_from_hosts


def _ftp(scripts: dict[str, str]) -> ParsedService:
    return ParsedService(
        transport=ServiceTransport.TCP,
        port=21,
        state=ServiceState.OPEN,
        service_name="ftp",
        scripts=scripts,
    )


def test_ftp_anon_becomes_a_finding() -> None:
    hosts = [
        ParsedHost(
            ip="10.0.0.1",
            services=[_ftp({"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"})],
        )
    ]
    findings = findings_from_hosts(hosts)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Anonymous FTP access allowed"
    assert f.severity is Severity.MEDIUM
    assert f.finding_type is FindingType.MISCONFIGURATION
    assert f.scanner == "nmap-nse" and f.weakness_key == "ftp-anon"
    assert f.target_ip == "10.0.0.1" and f.port == 21
    assert "230" in f.evidence["output"]


def test_ftp_anon_when_denied_is_not_a_finding() -> None:
    hosts = [ParsedHost(ip="10.0.0.1", services=[_ftp({"ftp-anon": "Anonymous login denied"})])]
    assert findings_from_hosts(hosts) == []


def test_unknown_script_is_ignored() -> None:
    hosts = [ParsedHost(ip="10.0.0.1", services=[_ftp({"http-title": "Login"})])]
    assert findings_from_hosts(hosts) == []


def test_parser_extracts_script_output() -> None:
    xml = (
        b'<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        b'<ports><port protocol="tcp" portid="21"><state state="open"/>'
        b'<service name="ftp" product="vsftpd" version="3.0.3"/>'
        b'<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>'
        b"</port></ports></host></nmaprun>"
    )
    hosts = parse_nmap_xml(xml)
    svc = hosts[0].services[0]
    assert svc.scripts["ftp-anon"] == "Anonymous FTP login allowed (FTP code 230)"
    # And it flows through to a finding.
    assert len(findings_from_hosts(hosts)) == 1


def _svc(port: int, service_name: str, scripts: dict[str, str]) -> ParsedService:
    return ParsedService(
        transport=ServiceTransport.TCP,
        port=port,
        state=ServiceState.OPEN,
        service_name=service_name,
        scripts=scripts,
    )


def test_http_git_exposure_becomes_a_finding() -> None:
    # Real http-git output shape when a .git dir is served.
    out = "\n  10.0.0.1:80/.git/\n    Potential Git repository found (found 2/6 expected files)\n"
    hosts = [ParsedHost(ip="10.0.0.1", services=[_svc(80, "http", {"http-git": out})])]
    findings = findings_from_hosts(hosts)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Exposed Git repository"
    assert f.severity is Severity.HIGH
    assert f.finding_type is FindingType.WEB_APPLICATION_ISSUE
    assert f.weakness_key == "http-git"


def test_http_methods_flags_only_risky() -> None:
    # Real http-methods output: nmap itself classifies the risky ones.
    risky = "\n  Supported Methods: GET POST OPTIONS HEAD TRACE\n  Potentially risky methods: TRACE"
    hosts = [ParsedHost(ip="10.0.0.1", services=[_svc(80, "http", {"http-methods": risky})])]
    findings = findings_from_hosts(hosts)
    assert len(findings) == 1
    assert findings[0].title == "Risky HTTP methods enabled"
    assert findings[0].severity is Severity.LOW

    # Only safe methods -> nmap omits the "risky methods" line -> no finding.
    safe = "\n  Supported Methods: GET POST HEAD OPTIONS\n"
    hosts = [ParsedHost(ip="10.0.0.1", services=[_svc(80, "http", {"http-methods": safe})])]
    assert findings_from_hosts(hosts) == []
