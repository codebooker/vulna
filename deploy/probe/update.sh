#!/usr/bin/env bash
# VulnaScout appliance update/rollback engine.
#
# Binaries are installed side-by-side under releases/<version>/ and made live via
# a single symlink, while identity, policy, and config live in a SEPARATE data
# directory that updates never touch. This guarantees an upgrade never loses a
# probe's enrolled identity or signed policy, and a rollback simply re-points the
# symlink at the previous release.
#
# Layout (override roots via env for testing):
#   VULNA_ROOT (default /opt/vulna)
#     releases/<version>/vulnascout   installed binaries, side by side
#     bin/vulnascout                  symlink -> the active release binary
#     state/current_version           active version
#     state/previous_version          prior version (rollback target)
#   VULNA_DATA (default /var/lib/vulna)   identity/policy/config — never touched
#
# Usage:
#   update.sh install  <version> <src-binary>   register a release
#   update.sh activate <version>                make a release live
#   update.sh rollback                          revert to the previous release
#   update.sh current                           print the active version
set -euo pipefail

VULNA_ROOT="${VULNA_ROOT:-/opt/vulna}"
VULNA_DATA="${VULNA_DATA:-/var/lib/vulna}"

RELEASES="$VULNA_ROOT/releases"
BIN_LINK="$VULNA_ROOT/bin/vulnascout"
STATE="$VULNA_ROOT/state"

die() { echo "update.sh: $*" >&2; exit 1; }

ensure_dirs() {
	mkdir -p "$RELEASES" "$VULNA_ROOT/bin" "$STATE" "$VULNA_DATA"
}

cmd_install() {
	local version="${1:?version required}" src="${2:?source binary required}"
	[ -f "$src" ] || die "source binary not found: $src"
	ensure_dirs
	mkdir -p "$RELEASES/$version"
	install -m 0755 "$src" "$RELEASES/$version/vulnascout"
	echo "installed release $version"
}

cmd_activate() {
	local version="${1:?version required}"
	[ -x "$RELEASES/$version/vulnascout" ] || die "release not installed: $version"
	ensure_dirs
	local current=""
	[ -f "$STATE/current_version" ] && current="$(cat "$STATE/current_version")"
	if [ -n "$current" ] && [ "$current" != "$version" ]; then
		echo "$current" > "$STATE/previous_version"
	fi
	ln -sfn "$RELEASES/$version/vulnascout" "$BIN_LINK"
	echo "$version" > "$STATE/current_version"
	echo "activated $version"
}

cmd_rollback() {
	[ -f "$STATE/previous_version" ] || die "no previous version to roll back to"
	local prev current
	prev="$(cat "$STATE/previous_version")"
	current="$(cat "$STATE/current_version")"
	[ -x "$RELEASES/$prev/vulnascout" ] || die "previous release missing: $prev"
	ln -sfn "$RELEASES/$prev/vulnascout" "$BIN_LINK"
	echo "$prev" > "$STATE/current_version"
	echo "$current" > "$STATE/previous_version"
	echo "rolled back to $prev"
}

cmd_current() {
	[ -f "$STATE/current_version" ] || die "no active version"
	cat "$STATE/current_version"
}

main() {
	local action="${1:-}"
	shift || true
	case "$action" in
		install) cmd_install "$@" ;;
		activate) cmd_activate "$@" ;;
		rollback) cmd_rollback ;;
		current) cmd_current ;;
		*) die "usage: install|activate|rollback|current" ;;
	esac
}

main "$@"
