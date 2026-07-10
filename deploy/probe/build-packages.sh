#!/usr/bin/env bash
# Build VulnaScout probe packages for amd64 and arm64.
#
# Produces a static, CGO-free binary per architecture and a matching .deb via
# nfpm. Run from the repository root. Requires Go and nfpm
# (https://nfpm.goreleaser.com). VM images are then built by baking the
# resulting .deb into a base cloud image with the cloud-init in this directory.
#
#   VERSION=1.0.0 deploy/probe/build-packages.sh
set -euo pipefail

VERSION="${VERSION:-0.0.0-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
mkdir -p dist

for arch in amd64 arm64; do
	echo "== building vulnascout $VERSION ($arch) =="
	( cd scout && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w" -o "$ROOT/dist/vulnascout" ./cmd/vulnascout )

	if command -v nfpm >/dev/null 2>&1; then
		export VERSION
		export ARCH="$arch"
		nfpm package -f deploy/probe/nfpm.yaml -p deb -t "dist/vulnascout_${VERSION}_${arch}.deb"
		echo "wrote dist/vulnascout_${VERSION}_${arch}.deb"
	else
		echo "nfpm not installed; built dist/vulnascout ($arch) only" >&2
	fi
done

echo "done: artifacts in dist/"
