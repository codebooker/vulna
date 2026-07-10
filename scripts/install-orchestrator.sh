#!/usr/bin/env bash
#
# install-orchestrator.sh — bootstrap the VulnaDash orchestrator via Docker Compose.
#
# Phase 0: performs preflight checks and prepares the .env file. Later phases
# extend this with key generation, first-run admin bootstrap, and migrations.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Vulna orchestrator installer (Phase 0)"

# --- Preflight -------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose plugin is required" >&2; exit 1; }

# --- Environment -----------------------------------------------------------
if [[ ! -f .env ]]; then
  echo "==> Creating .env from template"
  cp .env.example .env
  echo "    Edit .env and set POSTGRES_PASSWORD and the VULNA_* secrets before starting."
else
  echo "==> .env already exists; leaving it untouched"
fi

cat <<'EOF'

Next steps:
  1. Edit .env and set strong values for POSTGRES_PASSWORD, VULNA_MASTER_KEY,
     and VULNA_SECRET_KEY (e.g. `openssl rand -base64 32`).
  2. Start the stack:
       docker compose up -d
  3. Check health:
       curl -fsS http://localhost/health

Authorized use only. Review SECURITY.md and docs/authorized-use.md first.
EOF
