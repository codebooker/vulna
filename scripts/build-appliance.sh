#!/usr/bin/env bash
#
# build-appliance.sh — build VulnaScout appliance images (OVA/QCOW2/VHDX/Pi).
#
# Phase 0 scaffold. Appliance image builds are delivered in Phase 13.
#
set -euo pipefail

echo "==> VulnaScout appliance builder (Phase 0 scaffold)"
echo "Planned outputs (Phase 13):"
echo "  - cloud-init seed for VM deployment"
echo "  - Debian/Ubuntu .deb packages (amd64, arm64)"
echo "  - container image"
echo "  - OVA / QCOW2 / VHDX / Raspberry Pi images"
echo
echo "For now, cross-compile the binary:"
echo "  cd scout && make -C .. probe-build-all"
