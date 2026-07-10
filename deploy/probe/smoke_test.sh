#!/usr/bin/env bash
# Packaging smoke test: proves an upgrade preserves the probe's identity/policy
# and a rollback restores the prior version. Runs anywhere bash + coreutils exist
# (CI, a laptop, a fresh VM) — no VulnaDash or real binary required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATE="$HERE/update.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export VULNA_ROOT="$WORK/opt"
export VULNA_DATA="$WORK/data"

pass=0
check() { # <description> <expected> <actual>
	if [ "$2" = "$3" ]; then
		echo "  ok: $1"
		pass=$((pass + 1))
	else
		echo "  FAIL: $1 (expected '$2', got '$3')" >&2
		exit 1
	fi
}

make_stub() { # <version> -> prints a fake binary that echoes its version
	local v="$1"
	local path="$WORK/vulnascout-$v"
	printf '#!/bin/sh\necho "%s"\n' "$v" > "$path"
	chmod +x "$path"
	echo "$path"
}

echo "== install + activate v1.0.0 =="
bash "$UPDATE" install 1.0.0 "$(make_stub 1.0.0)"
bash "$UPDATE" activate 1.0.0
check "active version is v1" "1.0.0" "$(bash "$UPDATE" current)"
check "live binary reports v1" "1.0.0" "$("$VULNA_ROOT/bin/vulnascout")"

echo "== simulate an enrolled identity + signed policy in the data dir =="
mkdir -p "$VULNA_DATA"
echo "probe-cert-and-key" > "$VULNA_DATA/client.pem"
echo "signed-policy-v4" > "$VULNA_DATA/policy.json"

echo "== upgrade to v2.0.0 =="
bash "$UPDATE" install 2.0.0 "$(make_stub 2.0.0)"
bash "$UPDATE" activate 2.0.0
check "active version is v2" "2.0.0" "$(bash "$UPDATE" current)"
check "live binary reports v2" "2.0.0" "$("$VULNA_ROOT/bin/vulnascout")"
# Acceptance: upgrade does not lose identity or policy.
check "identity survived upgrade" "probe-cert-and-key" "$(cat "$VULNA_DATA/client.pem")"
check "policy survived upgrade" "signed-policy-v4" "$(cat "$VULNA_DATA/policy.json")"

echo "== rollback =="
bash "$UPDATE" rollback
# Acceptance: rollback restores prior version.
check "rolled back to v1" "1.0.0" "$(bash "$UPDATE" current)"
check "live binary reports v1 again" "1.0.0" "$("$VULNA_ROOT/bin/vulnascout")"
check "identity survived rollback" "probe-cert-and-key" "$(cat "$VULNA_DATA/client.pem")"

echo "== roll forward again (previous now points at v2) =="
bash "$UPDATE" rollback
check "rolled forward to v2" "2.0.0" "$(bash "$UPDATE" current)"

echo ""
echo "ALL PACKAGING SMOKE CHECKS PASSED ($pass)"
