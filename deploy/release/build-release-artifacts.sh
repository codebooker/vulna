#!/usr/bin/env bash
# Build the Linux release binaries using the exact names consumed by the three
# verified bootstrap installers, then add the single-host deployment bundle.
# Signing remains a separate offline step; see docs/release-process.md.
set -euo pipefail

VERSION="${1:?usage: build-release-artifacts.sh <vX.Y.Z> <out-dir>}"
OUT_DIR="${2:?usage: build-release-artifacts.sh <vX.Y.Z> <out-dir>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BARE_VERSION="${VERSION#v}"
COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

case "$VERSION" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "release-build: version must be a v-prefixed semantic version" >&2; exit 2 ;;
esac

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
printf '%s\n' "$VERSION" >"$OUT_DIR/VERSION"

for arch in amd64 arm64; do
	echo "release-build: linux/$arch" >&2
	(
		cd "$ROOT/cli"
		pkg=github.com/codebooker/vulna/cli/internal/buildinfo
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
			-ldflags "-s -w -X ${pkg}.Version=${BARE_VERSION} -X ${pkg}.Commit=${COMMIT} -X ${pkg}.Date=${BUILD_DATE}" \
			-o "$OUT_DIR/vulna_${VERSION}_linux_${arch}" ./cmd/vulna
	)
	(
		cd "$ROOT/scout"
		pkg=github.com/codebooker/vulna/scout/internal/buildinfo
		ldflags="-s -w -X ${pkg}.Version=${BARE_VERSION} -X ${pkg}.Commit=${COMMIT} -X ${pkg}.Date=${BUILD_DATE}"
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$ldflags" \
			-o "$OUT_DIR/vulnascout_${VERSION}_linux_${arch}" ./cmd/vulnascout
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$ldflags" \
			-o "$OUT_DIR/vulnarelay_${VERSION}_linux_${arch}" ./cmd/vulnarelay
	)
done

"$ROOT/deploy/release/build-deploy-bundle.sh" "$VERSION" "$OUT_DIR"
echo "release-build: unsigned artifacts are ready in $OUT_DIR" >&2
