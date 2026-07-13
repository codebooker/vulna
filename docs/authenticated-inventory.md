# Authenticated scanning and software inventory

Authenticated inventory is an explicit, read-only extension to the ordinary
assessment workflow. It is disabled per Scout until an administrator opts that
Scout in. The Authenticated inventory page manages vault metadata, deterministic
assignments, resolution previews, Scout opt-in, software history, end-of-life
state, and sanitized usage records.

## Credential lifecycle

Create either an SSH credential for Linux or a WinRM credential for Windows. A
secret is accepted only on creation or rotation. API reads return `has_secret`,
the current version number, username, and non-secret connection metadata; no API
can retrieve a stored value. SSH and WinRM values use distinct purpose-bound HKDF
contexts before authenticated encryption at rest. Rotation appends a new version
and retires the previous version without rewriting usage history.

SSH requires a pinned `SHA256:` host-key fingerprint. Password and private-key
authentication are supported. WinRM requires HTTPS plus a TLS server name or
pinned CA, and supports password authentication over NTLM or Basic. Certificate
and host-key verification cannot be disabled. Microsoft notes that Basic
authentication by itself provides no encryption, which is why Vulna requires
[WinRM over HTTPS](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).

## Assignment and resolution

One credential is resolved per requested protocol in this fixed order:

1. asset;
2. materialized asset group;
3. normalized asset tag;
4. network;
5. site;
6. scan preset.

The first level with a match wins. More than one match at that level is a hard
conflict and blocks job creation. Resolution preview shows the selected metadata
or conflict without decrypting a secret. Organization ownership and site grants
are checked before assignment, preview, test, job creation, inventory reads, and
EOL overrides.

## Scout delivery boundary

Enrollment generates an X25519 key pair on the Scout. Only the public key is sent
to VulnaDash; the raw private key is stored `0600` in Scout state and is removed by
`vulnascout reset`. An authenticated job must target exactly one IP already bound
to the chosen asset. VulnaDash decrypts the selected vault version only in memory,
then creates a ChaCha20-Poly1305 envelope using an ephemeral X25519 key and
HKDF-SHA256. Associated data and the encrypted payload bind it to the job id,
Scout id, and expiry.

The encrypted envelope is covered by the ordinary Ed25519 job signature. The Scout
first verifies signature, expiry, local policy, target scope, limits, plugin
allowlist, and its credentialed-scan opt-in. Only then does it decrypt the envelope.
Credentials remain in memory for the collector lifetime and are cleared afterward;
they are never written to Scout state, command arguments, environment variables,
temporary files, result output, evidence, or logs.

## Collectors and inventory history

The SSH collector runs exactly two fixed read-only commands: operating-system
identification and a `dpkg-query`/RPM package listing. The WinRM collector runs one
fixed read-only PowerShell inventory script. Jobs cannot supply commands. Both
collectors enforce a two-minute context and bounded output, accept one IP only, and
return normalized OS/package JSON.

VulnaDash validates the JSON shape and bounds before materializing inventory.
Added, observed, version-changed, and removed records append history rather than
overwriting provenance. Optional provider-neutral EOL records enrich packages;
authorized administrators can add expiring, audited manual overrides.

## Backup and portability

Encrypted database backups contain vault ciphertext, all secret versions,
assignments, usage, inventory history, EOL data, and Scout public keys. Portability
schema v6 introduced credential-only metadata (`has_secret` and version number), and current
schema v7 retains that one-way representation,
assignments, sanitized tests/usage, software inventory/history, and EOL overrides.
It never exports ciphertext, secret-version rows, Scout private keys, or encrypted
job envelopes. A working credential vault can move only through a verified,
encrypted backup/restore.
