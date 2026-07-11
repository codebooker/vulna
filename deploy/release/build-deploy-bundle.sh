#!/usr/bin/env bash
# Build the deployment bundle shipped alongside the `vulna` CLI in a release.
#
# The hosted bootstrap (scripts/install.sh) downloads this bundle for `install`
# so the operator ends up with the Compose files + overlay + backup/restore
# scripts the CLI needs — not just a bare binary. It is added to the release
# `dist/` directory BEFORE deploy/release/sign.sh, so its checksum is signed.
#
#   deploy/release/build-deploy-bundle.sh <version> <out-dir>
#   deploy/release/build-deploy-bundle.sh v1.0.0 dist/
set -euo pipefail

VERSION="${1:?usage: build-deploy-bundle.sh <version> <out-dir>}"
OUT_DIR="${2:?usage: build-deploy-bundle.sh <version> <out-dir>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
BUNDLE="$OUT_DIR/vulna-deploy_${VERSION}.tar.gz"

# The files a fresh single-host deployment needs. deploy/ carries the backup and
# restore scripts that `vulna backup restore` / `vulna rollback` invoke.
tar -czf "$BUNDLE" -C "$ROOT" \
	docker-compose.yml \
	docker-compose.single-host.yml \
	.env.example \
	deploy/backup \
	deploy/single-host \
	deploy/Caddyfile

echo "wrote $BUNDLE"
