"""Turn allowlisted NSE script results into findings.

The discovery scan runs a small allowlist of safe NSE scripts (see the Scout's
nmap adapter, ``safeScripts``). This maps their output to normalized findings —
e.g. nmap's ``ftp-anon`` reporting "Anonymous FTP login allowed" becomes an
anonymous-FTP exposure finding, the kind of thing a plain ``-sV`` scan silently
misses. Keep this table in sync with the Scout's script allowlist.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.models.enums import FindingType, Severity
from app.services.findings import ParsedFinding
from app.services.nmap_parser import ParsedHost


@dataclass(frozen=True)
class _ScriptFinding:
    title: str
    description: str
    finding_type: FindingType
    severity: Severity
    matches: Callable[[str], bool]


_SCRIPT_FINDINGS: dict[str, _ScriptFinding] = {
    "ftp-anon": _ScriptFinding(
        title="Anonymous FTP access allowed",
        description=(
            "The FTP service accepts anonymous logins, exposing its contents "
            "without authentication. Disable anonymous access unless it is "
            "explicitly required."
        ),
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        matches=lambda out: "anonymous ftp login allowed" in out.lower(),
    ),
    "http-git": _ScriptFinding(
        title="Exposed Git repository",
        description=(
            "A .git directory is served over HTTP, letting an attacker download "
            "the repository and reconstruct source code — and any secrets "
            "committed to it. Block web access to .git."
        ),
        finding_type=FindingType.WEB_APPLICATION_ISSUE,
        severity=Severity.HIGH,
        matches=lambda out: "git repository found" in out.lower(),
    ),
    "http-methods": _ScriptFinding(
        title="Risky HTTP methods enabled",
        description=(
            "The web server advertises potentially dangerous HTTP methods (e.g. "
            "TRACE, PUT, DELETE). Disable any method the application does not "
            "require; see the evidence for the specific methods."
        ),
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.LOW,
        matches=lambda out: "potentially risky methods:" in out.lower(),
    ),
}


def findings_from_hosts(hosts: list[ParsedHost]) -> list[ParsedFinding]:
    """Emit findings for allowlisted NSE script results across discovered hosts."""
    findings: list[ParsedFinding] = []
    for host in hosts:
        if not host.ip:
            continue
        for svc in host.services:
            for script_id, output in svc.scripts.items():
                spec = _SCRIPT_FINDINGS.get(script_id)
                if spec is None or not spec.matches(output):
                    continue
                findings.append(
                    ParsedFinding(
                        scanner="nmap-nse",
                        weakness_key=script_id,
                        finding_type=spec.finding_type,
                        title=spec.title,
                        severity=spec.severity,
                        target_ip=host.ip,
                        port=svc.port,
                        transport=svc.transport,
                        description=spec.description,
                        evidence={"script": script_id, "output": output},
                    )
                )
    return findings
