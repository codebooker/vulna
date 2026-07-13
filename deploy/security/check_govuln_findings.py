#!/usr/bin/env python3
"""Classify govulncheck JSON findings by actual symbol reachability."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

Finding = tuple[str, str]


def classify_findings(text: str) -> tuple[set[Finding], set[str], set[Finding]]:
    """Return called dependencies, called stdlib findings, and uncalled modules.

    ``govulncheck -format json`` emits a stream of JSON objects. Imported or
    required modules can have a module/version-only trace; a reachable finding
    has at least one frame with the protocol's ``function`` field.
    """
    decoder, offset, length = json.JSONDecoder(), 0, len(text)
    dependencies: set[Finding] = set()
    standard_library: set[str] = set()
    uncalled: set[Finding] = set()
    while offset < length:
        while offset < length and text[offset] in " \t\r\n":
            offset += 1
        if offset >= length:
            break
        item, offset = decoder.raw_decode(text, offset)
        finding = item.get("finding")
        if not finding:
            continue
        trace = finding.get("trace") or []
        osv = finding.get("osv", "unknown")
        module = next((frame.get("module", "") for frame in trace if frame.get("module")), "")
        if not any(frame.get("function") for frame in trace):
            uncalled.add((osv, module))
            continue
        if module in ("stdlib", "toolchain"):
            standard_library.add(osv)
        else:
            dependencies.add((osv, module))
    return dependencies, standard_library, uncalled


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--subject", default="Go application")
    args = parser.parse_args()
    dependencies, standard_library, uncalled = classify_findings(
        args.report.read_text(encoding="utf-8")
    )
    if uncalled:
        print("NOTE: module/import-only findings are not called:", sorted(uncalled))
    if dependencies:
        raise SystemExit(f"FAIL: called dependency vulnerabilities: {sorted(dependencies)}")
    if standard_library:
        print(
            "NOTE: Go stdlib advisories in the current toolchain "
            "(patched by upgrading Go):",
            sorted(standard_library),
        )
    print(f"OK: no called dependency vulnerabilities in {args.subject}.")


if __name__ == "__main__":
    main()
