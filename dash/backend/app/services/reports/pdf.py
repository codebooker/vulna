"""PDF report rendering with fpdf2 (pure-Python, no system libraries).

Two report types are produced from a snapshot: an executive summary and a
technical report. Both assemble every section named in the build plan
(Section 16.1) so a report renders without missing sections. Text is coerced to
Latin-1 (the core-font encoding) with replacement, so arbitrary scanner output
never crashes rendering.
"""

from __future__ import annotations

from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

TEMPLATE_VERSION = "1"

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _txt(value: Any) -> str:
    """Coerce any value to a Latin-1-safe string for the core PDF fonts."""
    text = "" if value is None else str(value)
    return text.encode("latin-1", "replace").decode("latin-1")


class _Doc(FPDF):
    """An FPDF with a running header/footer and section helpers."""

    def __init__(self, title: str, subtitle: str) -> None:
        super().__init__()
        self._title = _txt(title)
        self._subtitle = _txt(subtitle)
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title(self._title)

    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, self._subtitle, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="R")
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")
        self.set_text_color(0, 0, 0)

    def h1(self, text: str) -> None:
        self.set_font("Helvetica", "B", 18)
        self.multi_cell(0, 9, _txt(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def h2(self, text: str) -> None:
        self.ln(2)
        self.set_font("Helvetica", "B", 13)
        self.set_fill_color(238, 240, 244)
        self.cell(0, 8, _txt(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(1)

    def kv(self, label: str, value: Any) -> None:
        self.set_font("Helvetica", "B", 10)
        self.cell(55, 6, _txt(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, _txt(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(self, text: str) -> None:
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 5.5, _txt(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bullet(self, text: str) -> None:
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 5.5, f"- {_txt(text)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _risk_rating(summary: dict[str, Any]) -> str:
    counts = summary.get("severity_counts", {})
    if counts.get("critical"):
        return "Critical"
    if counts.get("high"):
        return "High"
    if counts.get("medium"):
        return "Medium"
    if counts.get("low"):
        return "Low"
    return "Informational"


def _org_site(snapshot: dict[str, Any]) -> str:
    org = (snapshot.get("organization") or {}).get("name", "Unknown org")
    site = (snapshot.get("site") or {}).get("name")
    return f"{org} — {site}" if site else org


def executive_pdf(snapshot: dict[str, Any]) -> bytes:
    summary = snapshot.get("summary", {})
    counts = summary.get("severity_counts", {})
    scan = snapshot.get("scan_job", {})
    doc = _Doc("Executive Assessment Summary", _org_site(snapshot))
    doc.add_page()

    doc.h1("Executive Assessment Summary")
    doc.para(_org_site(snapshot))

    doc.h2("Assessment overview")
    doc.kv("Assessment mode", scan.get("mode"))
    dates = f"{scan.get('started_at') or '—'} to {scan.get('finished_at') or '—'}"
    doc.kv("Assessment dates", dates)
    doc.kv("Authorization ref", scan.get("id"))
    doc.kv("Scope", ", ".join(scan.get("targets", [])) or "—")
    doc.kv("Overall risk rating", _risk_rating(summary))

    doc.h2("Key findings")
    doc.kv("Critical findings", counts.get("critical", 0))
    doc.kv("High findings", counts.get("high", 0))
    doc.kv("Known-exploited (KEV)", summary.get("kev_count", 0))
    doc.kv("Confirmed exploitable", summary.get("exploitable_count", 0))
    doc.kv("Assets assessed", summary.get("asset_count", 0))

    doc.h2("Top remediation priorities")
    priorities = _top_priorities(snapshot)
    if priorities:
        for f in priorities:
            doc.bullet(f"[{f['severity'].upper()}] {f['title']}")
    else:
        doc.para("No findings require remediation at this time.")

    doc.h2("Asset coverage")
    doc.para(
        f"{summary.get('asset_count', 0)} assets and {summary.get('service_count', 0)} "
        f"services were included in this assessment."
    )

    doc.h2("Limitations")
    doc.para(
        "This assessment reflects the state observed during the scan window and the "
        "scanners in scope. Unauthenticated network assessment cannot observe every "
        "host-level condition; results should be read with the assessment mode in mind."
    )

    doc.h2("Conclusion")
    doc.para(_plain_conclusion(summary))

    return bytes(doc.output())


def technical_pdf(snapshot: dict[str, Any]) -> bytes:
    summary = snapshot.get("summary", {})
    counts = summary.get("severity_counts", {})
    scan = snapshot.get("scan_job", {})
    doc = _Doc("Technical Assessment Report", _org_site(snapshot))
    doc.add_page()

    doc.h1("Technical Assessment Report")
    doc.para(_org_site(snapshot))

    doc.h2("Assessment metadata")
    doc.kv("Scan job", scan.get("id"))
    doc.kv("Mode", scan.get("mode"))
    doc.kv("Status", scan.get("status"))
    doc.kv("Started", scan.get("started_at"))
    doc.kv("Finished", scan.get("finished_at"))
    doc.kv("Target scopes", ", ".join(scan.get("targets", [])) or "—")

    doc.h2("Stage timeline")
    workflow = scan.get("workflow", [])
    if workflow:
        for stage in workflow:
            doc.bullet(f"{stage.get('stage', '?')} — plugin {stage.get('plugin', '?')}")
    else:
        doc.para("No workflow stages recorded.")

    doc.h2("Asset inventory summary")
    doc.para(f"{summary.get('asset_count', 0)} assets, {summary.get('service_count', 0)} services.")

    doc.h2("Port and service inventory")
    _service_table(doc, snapshot.get("services", []))

    doc.h2("Findings by severity")
    for sev in _SEVERITY_ORDER:
        doc.kv(sev.capitalize(), counts.get(sev, 0))

    doc.h2("Detailed findings")
    findings = snapshot.get("findings", [])
    if findings:
        for f in findings:
            _finding_section(doc, f)
    else:
        doc.para("No findings were recorded for this assessment.")

    doc.h2("Coverage gaps and scanner notes")
    doc.para(
        "Findings are derived from the scanners configured for this assessment. "
        "Absence of a finding is not proof of absence of a vulnerability."
    )

    doc.h2("Appendix: change events")
    changes = snapshot.get("changes", [])
    if changes:
        for c in changes[:50]:
            doc.bullet(f"{c.get('timestamp', '')}: {c.get('summary', '')}")
    else:
        doc.para("No changes were recorded for this scan.")

    return bytes(doc.output())


def pentest_pdf(snapshot: dict[str, Any]) -> bytes:
    """Controlled-pentest report (build plan Section 16.1)."""
    sessions = snapshot.get("pentest_sessions", [])
    scan = snapshot.get("scan_job", {})
    doc = _Doc("Controlled Pentest Report", _org_site(snapshot))
    doc.add_page()

    doc.h1("Controlled Pentest Report")
    doc.para(_org_site(snapshot))

    doc.h2("Executive summary")
    validated = [s for s in sessions if s.get("status") in ("cleaned", "completed", "terminated")]
    doc.para(
        f"{len(sessions)} validation session(s) were authorized for this engagement; "
        f"{len(validated)} completed. All validation used allowlisted, non-destructive "
        "modules under explicit approval."
    )

    doc.h2("Rules of engagement")
    doc.para(
        "Testing was performed under the organization's rules of engagement: allowlisted "
        "modules only, per-session approval, bounded session duration, and required cleanup. "
        "Denial-of-service modules are categorically prohibited."
    )

    doc.h2("Testing window and scope")
    doc.kv("Window", f"{scan.get('started_at') or '—'} to {scan.get('finished_at') or '—'}")
    doc.kv("Scope", ", ".join(scan.get("targets", [])) or "—")

    doc.h2("Methodology")
    doc.para(
        "Discovery and vulnerability assessment produced a candidate list; each candidate "
        "validation was individually approved, executed with an allowlisted module under a "
        "session timeout, evidenced minimally, and followed by cleanup and a verification scan."
    )

    doc.h2("Validated weaknesses and proof of access")
    if sessions:
        for s in sessions:
            doc.ln(1)
            doc.set_font("Helvetica", "B", 11)
            title = s.get("finding_title") or s.get("finding_id")
            doc.multi_cell(
                0, 6, _txt(f"[{s.get('status', '').upper()}] {title}"),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            doc.kv("Module", s.get("module"))
            doc.kv("Approved at", s.get("approved_at") or "—")
            doc.kv("Session window", f"{s.get('started_at') or '—'} → {s.get('ended_at') or '—'}")
            doc.kv("Max duration", f"{s.get('max_session_seconds')}s")
            if s.get("outcome"):
                doc.para(s["outcome"])
    else:
        doc.para("No validation sessions were run in this engagement.")

    doc.h2("Cleanup confirmation")
    for s in sessions:
        state = "completed" if s.get("cleanup_completed") else (
            "not required" if not s.get("cleanup_required") else "PENDING"
        )
        doc.bullet(f"{s.get('module')}: cleanup {state}")
    if not sessions:
        doc.para("No cleanup was required.")

    doc.h2("Limitations")
    doc.para(
        "Validation is limited to allowlisted, non-destructive modules; absence of a validated "
        "exploit is not proof a weakness is unexploitable by other means."
    )

    doc.h2("Approval / sign-off")
    doc.para("Each session in this report was individually approved by an authorized approver.")

    return bytes(doc.output())


def full_spectrum_pdf(snapshot: dict[str, Any]) -> bytes:
    """Combined full-spectrum report: executive posture, findings by severity,
    validation summary, and remediation/exposure changes (build plan §13.3)."""
    summary = snapshot.get("summary", {})
    counts = summary.get("severity_counts", {})
    sessions = snapshot.get("pentest_sessions", [])
    doc = _Doc("Full-Spectrum Assessment Report", _org_site(snapshot))
    doc.add_page()

    doc.h1("Full-Spectrum Assessment Report")
    doc.para(_org_site(snapshot))

    doc.h2("Executive summary")
    doc.kv("Overall risk rating", _risk_rating(summary))
    doc.kv("Critical / High", f"{counts.get('critical', 0)} / {counts.get('high', 0)}")
    doc.kv("Known-exploited (KEV)", summary.get("kev_count", 0))
    assets_services = f"{summary.get('asset_count', 0)} / {summary.get('service_count', 0)}"
    doc.kv("Assets / services", assets_services)
    doc.para(_plain_conclusion(summary))

    doc.h2("Vulnerability results by severity")
    for sev in _SEVERITY_ORDER:
        doc.kv(sev.capitalize(), counts.get(sev, 0))

    doc.h2("Validation results")
    if sessions:
        for s in sessions:
            doc.bullet(
                f"[{s.get('status', '').upper()}] {s.get('finding_title') or s.get('finding_id')} "
                f"via {s.get('module')}"
            )
    else:
        doc.para("No controlled validation was performed in this engagement.")

    doc.h2("Asset and exposure changes")
    changes = snapshot.get("changes", [])
    if changes:
        for c in changes[:40]:
            doc.bullet(f"{c.get('timestamp', '')}: {c.get('summary', '')}")
    else:
        doc.para("No changes were recorded for this scan.")

    doc.h2("Remediation roadmap")
    for f in _top_priorities(snapshot):
        doc.bullet(f"[{f.get('severity', '').upper()}] {f.get('title')} — {f.get('status')}")
    if not _top_priorities(snapshot):
        doc.para("No high-priority remediation items outstanding.")

    doc.h2("Cleanup and verification summary")
    pending = [s for s in sessions if s.get("cleanup_required") and not s.get("cleanup_completed")]
    doc.para(
        f"{len(sessions)} validation session(s); "
        f"{len(pending)} with cleanup still pending. A verification scan follows all validation."
    )

    return bytes(doc.output())


def _service_table(doc: _Doc, services: list[dict[str, Any]]) -> None:
    if not services:
        doc.para("No services were discovered.")
        return
    doc.set_font("Helvetica", "B", 9)
    doc.cell(45, 6, "Asset", border=1)
    doc.cell(30, 6, "Port", border=1)
    doc.cell(0, 6, "Product / version", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    doc.set_font("Helvetica", "", 9)
    for s in services[:200]:
        product = " ".join(x for x in [s.get("product"), s.get("version")] if x) or "—"
        port = f"{s.get('port')}/{s.get('transport')}"
        doc.cell(45, 6, _txt(s.get("asset_name") or s.get("asset_id")), border=1)
        doc.cell(30, 6, _txt(port), border=1)
        doc.cell(0, 6, _txt(product), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _finding_section(doc: _Doc, f: dict[str, Any]) -> None:
    doc.ln(1)
    doc.set_font("Helvetica", "B", 11)
    doc.multi_cell(
        0, 6, _txt(f"[{f.get('severity', '').upper()}] {f.get('title', '')}"),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    doc.kv("Asset", f.get("asset_name") or f.get("asset_id") or "—")
    doc.kv("Type", f.get("finding_type"))
    score = f.get("cvss_score") if f.get("cvss_score") is not None else "—"
    doc.kv("CVSS", f"{score} {f.get('cvss_vector') or ''}")
    if f.get("cve_ids"):
        doc.kv("CVEs", ", ".join(f["cve_ids"]))
    doc.kv("Known exploited", "yes" if f.get("known_exploited") else "no")
    if f.get("epss_score") is not None:
        doc.kv("EPSS", f"{f.get('epss_score')} (pct {f.get('epss_percentile')})")
    doc.kv("Validation", f.get("validation_status"))
    doc.kv("Status", f.get("status"))
    if f.get("description"):
        doc.para(f["description"])
    if f.get("remediation"):
        doc.set_font("Helvetica", "B", 10)
        doc.cell(0, 6, "Remediation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        doc.para(f["remediation"])


def _top_priorities(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    findings = [
        f
        for f in snapshot.get("findings", [])
        if f.get("severity") in ("critical", "high") or f.get("known_exploited")
    ]
    findings.sort(
        key=lambda f: (
            0 if f.get("known_exploited") else 1,
            order.get(f.get("severity", "info"), 99),
        )
    )
    return findings[:10]


def _plain_conclusion(summary: dict[str, Any]) -> str:
    counts = summary.get("severity_counts", {})
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    kev = summary.get("kev_count", 0)
    if crit or high:
        text = (
            f"The assessment identified {crit} critical and {high} high-severity issues"
        )
        if kev:
            text += f", including {kev} with known exploitation in the wild"
        return text + ". Prioritize the remediation items above."
    return (
        "No critical or high-severity issues were identified in this assessment. "
        "Maintain current controls and reassess on the regular schedule."
    )
