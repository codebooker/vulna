# Sessions and signed-in devices

Vulna uses revocable server-side sessions rather than long-lived stateless browser
tokens. A password sign-in returns a 15-minute access token that the frontend
keeps only in memory and sets a random refresh token in an HttpOnly cookie. The
server stores only a purpose-bound HMAC hash of that refresh token.

## Review and revoke

Open **Sessions** under Administration to see device name, source IP, browser,
last activity, trust duration, and absolute expiry. Any user can revoke another
one of their sessions or choose **Sign out everywhere**. Revoking the current
session returns to sign-in immediately.

Administrators can also open a user in **Users** and revoke that account's active
sessions. Password resets, password changes, account status changes, role changes,
and site-access changes revoke every session for the affected user.

## Organization policy

Administrators configure the policy on the Sessions page. Defaults are:

- idle timeout: 12 hours;
- absolute lifetime: 30 days;
- recent password/privileged window: 15 minutes;
- maximum concurrent sessions: 10; and
- trusted-device duration: 30 days.

Policy edits are audited. New limits apply to newly issued sessions; administrators
can revoke existing sessions if a stricter limit must take effect immediately.

## Cookie and proxy requirements

The refresh cookie is HttpOnly, SameSite=Lax, and scoped to the authentication API.
Production deployments always add `Secure`, so the public URL must use HTTPS.
Development permits plain HTTP only for localhost. Cross-origin custom deployments
must preserve credentials at their reverse proxy; the supported deployment keeps
the frontend and API on the same origin.

Refresh tokens rotate on every use. If an already-used token appears again, Vulna
assumes theft, revokes the session family, and records an audit event. Idle expiry,
absolute expiry, account status, and authentication version are checked on every
access or refresh.

## Upgrades, backup, and portability

The session-model migration invalidates legacy stateless tokens, so an upgrade causes a
one-time forced sign-in. Encrypted full-database backups preserve session state,
including revocation and token-use records. Portability exports intentionally omit
all session metadata and refresh hashes.
