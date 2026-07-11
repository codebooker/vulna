#!/usr/bin/env bash
# Smoke test for `vulna backup`: a created bundle verifies as USABLE, and a
# corrupted or wrong-passphrase bundle is marked UNUSABLE before any restore.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "smoke: building vulna CLI"
(cd "$ROOT/cli" && go build -o "$work/vulna" ./cmd/vulna)

# Stand in for a tar.gz produced by deploy/backup/backup.sh: a real gzip+tar
# carrying a database dump, a data/ payload, and the deployment .env under config/
# (verification inspects the archive contents, and "config" — the DB password +
# evidence master key — is a required class, so a complete backup must include it).
stage="$work/stage"
mkdir -p "$stage/data/keys" "$stage/config"
printf 'pretend postgres custom-format dump\n' >"$stage/db.dump"
printf 'pretend CA certificate\n' >"$stage/data/keys/ca_cert.pem"
printf 'VULNA_MASTER_KEY=smoke\nPOSTGRES_PASSWORD=smoke\n' >"$stage/config/env"
tar -czf "$work/base.tar.gz" -C "$stage" .

echo "smoke: (1) create an encrypted bundle and verify it is USABLE"
VULNA_BACKUP_PASSPHRASE="correct horse battery staple" \
	"$work/vulna" backup create \
	--archive "$work/base.tar.gz" --out "$work/backups" --encrypt \
	--schema-version abc123 --org-id org-1 --org-slug default >/dev/null

bundle="$(find "$work/backups" -maxdepth 1 -type d -name 'vulna-backup-*' | head -1)"
[ -n "$bundle" ] || {
	echo "smoke: FAIL — no bundle created" >&2
	exit 1
}

VULNA_BACKUP_PASSPHRASE="correct horse battery staple" \
	"$work/vulna" backup verify "$bundle" | grep -q "USABLE" || {
	echo "smoke: FAIL — a fresh bundle should be USABLE" >&2
	exit 1
}
echo "smoke:   ok — created bundle is usable"

echo "smoke: (2) wrong passphrase must be UNUSABLE"
if VULNA_BACKUP_PASSPHRASE="wrong" "$work/vulna" backup verify "$bundle" 2>/dev/null | grep -q "^backup: USABLE"; then
	echo "smoke: FAIL — wrong passphrase must not verify" >&2
	exit 1
fi
echo "smoke:   ok — wrong passphrase refused"

echo "smoke: (3) corrupted archive must be UNUSABLE"
enc="$(find "$bundle" -name '*.enc' | head -1)"
printf 'corruption' >>"$enc"
if VULNA_BACKUP_PASSPHRASE="correct horse battery staple" "$work/vulna" backup verify "$bundle" 2>/dev/null | grep -q "^backup: USABLE"; then
	echo "smoke: FAIL — corrupted bundle must be marked unusable" >&2
	exit 1
fi
echo "smoke:   ok — corrupted bundle refused"

echo "smoke: (4) recovery sheet contains no secrets"
"$work/vulna" backup recovery-sheet "$bundle" >"$work/sheet.txt"
if grep -qiE 'correct horse|-----BEGIN|password=' "$work/sheet.txt"; then
	echo "smoke: FAIL — recovery sheet leaked a secret" >&2
	exit 1
fi
echo "smoke:   ok — recovery sheet has no secrets"

echo "smoke: PASS"
