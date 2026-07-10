#!/bin/sh
# Debian/RPM post-install: create the vulna user + data dir, activate the
# installed release, and enable the service. Idempotent and re-run on upgrade —
# it never touches /var/lib/vulna, so identity and policy are preserved.
set -e

VERSION="${VERSION:-}"

if ! id vulna >/dev/null 2>&1; then
	useradd -r -s /usr/sbin/nologin vulna || true
fi
mkdir -p /var/lib/vulna
chown vulna:vulna /var/lib/vulna

# Activate the release that this package shipped (the newest under releases/).
if [ -z "$VERSION" ]; then
	# Newest installed release directory (version-sorted). find keeps shellcheck
	# happy and handles an empty releases dir gracefully.
	VERSION="$(find /opt/vulna/releases -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
		2>/dev/null | sort -V | tail -n1)"
fi
if [ -n "$VERSION" ]; then
	/opt/vulna/bin/vulna-update activate "$VERSION" || true
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable vulnascout.service || true
	systemctl restart vulnascout.service || true
fi

echo "VulnaScout installed. Enroll with: vulna-appliance enroll <server-url> <token>"
