# Updates and rollback

Keeping Vulna current should be less risky than leaving it outdated. Updates are
**verified, operator-driven, and reversible**. The web **Updates** panel is
display-only; the running application never fetches or applies a release (so it is
not a remote code-execution channel). You apply updates with the `vulna` CLI,
which verifies a signed release manifest before doing anything.

## Channels

`stable` (default), `candidate`, and `development`. Automatic installation is
opt-in — there is no forced remote update path.

## Check, apply, roll back

```sh
vulna update check --channel stable    # verify the signed manifest; show what's new (no changes)
vulna update                           # pre-update checks + automatic backup, then the apply steps
vulna update status                    # current version and the recorded rollback point
vulna rollback                         # revert to the prior known-good version
```

`vulna update check` downloads the release manifest plus its `SHA256SUMS` and
Ed25519 signature and **rejects** anything unsigned, altered, expired, or on the
wrong channel. It shows the version, security relevance, database-migration impact,
Scout compatibility, and scanner/template changes.

`vulna update`:

1. Verifies the signed manifest.
2. Runs pre-update checks — free disk, backup status, database health, local
   modifications, and (blocking) an **incompatible active assessment**. No update
   begins while one runs.
3. Takes an **automatic pre-update backup** (unless you pass `--no-backup`, which
   assumes you have your own).
4. Records the applied and prior versions plus the backup path for rollback.
5. Prints the exact deploy steps (`docker compose pull/build && up`); migrations
   run automatically on API start.

If the new version does not become healthy, run `vulna rollback`.

## Rollback safety

Rollback reverts to the recorded prior version. For a **schema-changing** release
it requires the pre-update backup and tells you to restore it first, so a rollback
never leaves the database on an incompatible schema. Persistent data — config,
identity, scopes, findings, evidence, reports, audit history — lives on Docker
volumes and survives a version change.

## Separate update types

Application, VulnaScout, scanner binaries, scanner templates, and intelligence
feeds are updated independently. Scout updates use the appliance's side-by-side
update/rollback; feed refreshes are the normal VulnaWatch sync.
