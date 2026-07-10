#!/usr/bin/env bash
#
# backup.sh — back up VulnaDash state (PostgreSQL, reports, evidence, config).
#
# Phase 0 scaffold. The full implementation (encrypted, rotated, verified
# backups incl. the CA key) is delivered alongside Phase 15.
#
set -euo pipefail

echo "==> Vulna backup (Phase 0 scaffold)"
echo "Planned coverage:"
echo "  - PostgreSQL logical dump (pg_dump)"
echo "  - report and evidence volumes"
echo "  - configuration (.env, Caddyfile)"
echo "  - certificate authority material"
echo
echo "Backups must be encrypted and stored offsite. See docs (Phase 15)."
