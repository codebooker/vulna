#!/usr/bin/env bash
#
# install-probe.sh — install the VulnaScout agent as a systemd service.
#
# Phase 0: preflight and usage scaffold only. The full installer (binary
# download + signature verification, user/dirs, systemd unit, enrollment) is
# delivered in Phase 2 and Phase 13.
#
set -euo pipefail

echo "==> VulnaScout installer (Phase 0 scaffold)"
echo "This script will, in later phases:"
echo "  - verify the signed release manifest and checksums"
echo "  - create the vulna system user and /etc/vulna, /var/lib/vulna dirs"
echo "  - install the vulnascout binary and a hardened systemd unit"
echo "  - run 'vulnascout enroll' against your orchestrator"
echo
echo "For now, build and self-test the agent from source:"
echo "  cd scout && go build -o bin/vulnascout ./cmd/vulnascout"
echo "  ./bin/vulnascout self-test"
echo
echo "Authorized use only. A VulnaScout must only assess networks you are"
echo "explicitly permitted to test."
