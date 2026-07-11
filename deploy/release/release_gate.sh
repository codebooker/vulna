#!/usr/bin/env bash
# Release-blocking regression gate (Phase 32).
#
# Runs the security-critical, release-blocking regression suite. A release MUST
# NOT be promoted if this fails. The suite covers: setup/enrollment, target/scope
# enforcement, job signatures and signed local policy, job cancellation,
# backup/restore, relay egress + kill switch, and data authorization (RBAC and
# cross-organization isolation).
#
# Usage (from the repository root):
#   deploy/release/release_gate.sh
#
# It runs the backend suite marked `release_gate`. Point PYTEST at a venv's
# pytest if needed (e.g. PYTEST=dash/backend/.venv/bin/pytest).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="$ROOT/dash/backend"
PYTEST="${PYTEST:-pytest}"

echo "release-gate: running the security-critical release-blocking suite" >&2
cd "$BACKEND"

if "$PYTEST" -m release_gate -p no:cacheprovider -q; then
    echo "release-gate: PASS — the release-blocking regression suite is green." >&2
    exit 0
fi

echo "release-gate: FAIL — a release-blocking regression failed. Do not promote this release." >&2
exit 1
