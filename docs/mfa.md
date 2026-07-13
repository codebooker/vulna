# Multi-factor authentication and passkeys

Open **Security** under Administration to enroll an authenticator app (TOTP), a
passkey/security key (WebAuthn), or to replace recovery codes. Recovery codes are
shown once; keep them offline. Each code works once and Vulna stores only an Argon2
hash. TOTP seeds are encrypted with a purpose-specific key derived from the
application secret and are never returned after setup.

## Sign in and recovery

Password verification creates a server-side session, but a user with an enrolled
strong factor must complete TOTP or WebAuthn before ordinary APIs are available.
The access token remains in browser memory. A recovery code may replace the second
factor for one sign-in and is consumed immediately. TOTP codes from an already-used
time step are rejected.

Adding or removing a factor revokes the account's other sessions. Security events
are audited and use configured notification channels when available; notification
failure never blocks sign-in or persistence.

## Organization policy

Administrators can leave MFA optional or require it for all users or selected
roles. Newly required users without a factor receive a configurable grace period
(seven days by default). During the grace period they can work and see the deadline.
After expiry, they can sign in only far enough to enroll a factor. Experience
profiles never hide or disable enforcement.

High-risk scope, pentest, retention/hold, evidence/report, repair, Scout enrollment
and certificate, and MFA-policy operations require authentication within the
organization's privileged window (15 minutes by default). Re-enter the password or
complete MFA when the API returns `step_up_required`.

## WebAuthn deployment settings

WebAuthn requires HTTPS except for localhost. The supported same-origin deployment
usually infers the relying party from the public request. Set these values when a
reverse proxy changes the public origin:

```dotenv
VULNA_WEBAUTHN_ORIGIN=https://vulna.example.com
VULNA_WEBAUTHN_RP_ID=vulna.example.com
VULNA_WEBAUTHN_RP_NAME=Vulna
```

The origin must exactly match the browser-visible scheme and host. The RP ID must
be that host or a valid registrable parent. Vulna requires user verification and
stores only the credential public key, identifier, sign count, device/backup flags,
label, and transports; the authenticator private key never leaves the device.

## Failure throttling and backup

Password and MFA failures share database-backed account/IP exponential backoff.
Keys are SHA-256 hashes of normalized identifiers, so the throttle table does not
become another plaintext account/IP index. Error text does not distinguish unknown
accounts, bad passwords, or bad factors.

Encrypted full-database backups preserve factors, recovery-code use, WebAuthn sign
counters, policy/grace state, and session strength. Non-secret portability exports
exclude every authentication factor, challenge, policy, throttle, and session
record. See [backups](backups.md) and [portability](portability.md).
