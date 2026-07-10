#!/usr/bin/env bash
# Generate Software Bills of Materials for the three components. Emits CycloneDX
# JSON where the native tool is available, and a plain dependency list otherwise.
# Output goes to sbom/ at the repo root. Run from anywhere.
#
#   deploy/sbom/generate-sbom.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/sbom"
mkdir -p "$OUT"

echo "== backend (Python) =="
if command -v cyclonedx-py >/dev/null 2>&1; then
	( cd "$ROOT/dash/backend" && cyclonedx-py environment -o "$OUT/backend.cdx.json" ) \
		&& echo "wrote sbom/backend.cdx.json"
else
	( cd "$ROOT/dash/backend" && pip freeze > "$OUT/backend-requirements.txt" ) \
		&& echo "cyclonedx-py not found; wrote sbom/backend-requirements.txt"
fi

echo "== frontend (npm) =="
if ( cd "$ROOT/dash/frontend" && npm sbom --sbom-format cyclonedx > "$OUT/frontend.cdx.json" ) 2>/dev/null; then
	echo "wrote sbom/frontend.cdx.json"
else
	( cd "$ROOT/dash/frontend" && npm ls --all --json > "$OUT/frontend-deps.json" ) 2>/dev/null \
		&& echo "npm sbom unavailable; wrote sbom/frontend-deps.json"
fi

echo "== probe (Go) =="
# The scout module is standard-library only, so its module graph is minimal.
( cd "$ROOT/scout" && go list -m all > "$OUT/probe-modules.txt" ) \
	&& echo "wrote sbom/probe-modules.txt"

echo "done: SBOMs in sbom/"
