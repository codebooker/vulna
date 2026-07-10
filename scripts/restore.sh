#!/usr/bin/env bash
#
# restore.sh — restore VulnaDash state from a backup produced by backup.sh.
#
# Phase 0 scaffold. Full restore + verification is delivered alongside Phase 15.
#
set -euo pipefail

echo "==> Vulna restore (Phase 0 scaffold)"
echo "Planned steps:"
echo "  - stop services"
echo "  - restore PostgreSQL from a logical dump"
echo "  - restore report/evidence volumes and configuration"
echo "  - verify integrity (checksums) and restart"
echo
echo "Always test restores regularly. A restore that has never been tested"
echo "is not a backup."
