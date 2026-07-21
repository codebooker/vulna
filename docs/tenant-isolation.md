# PostgreSQL tenant isolation

Vulna applies organization filters in its services and API and also enables
PostgreSQL row-level security (RLS) on high-value tenant data. The two controls
are independent: a future query that accidentally omits an organization filter
still cannot read or modify another organization's protected rows.

Application ORM transactions automatically enter the non-login,
non-owner `vulna_runtime` database role. That role is neither superuser nor
`BYPASSRLS`. Until authentication binds the session to one organization,
protected tables expose no rows. The organization setting is transaction-local
and is restored after every commit from the session's immutable context.

The initial protected set covers sites and networks; asset, service, finding,
scan, and raw scan-artifact data; credentials and software inventory; reports;
remediation and ticket records; controlled-pentest authorization and sessions;
and related job-attempt/result records. Machine identity and authentication
bootstrap tables remain outside RLS so Vulna can resolve a JWT, API token, SCIM
token, or Scout certificate before it knows the tenant.

An explicit `vulna_maintenance` `BYPASSRLS` role is reserved for trusted
cross-organization maintenance such as aggregate internal metrics and scheduler
work. It is never selected from request input. Both roles are `NOLOGIN`; the
database migration owner retains credentials and uses `SET LOCAL ROLE` for the
runtime boundary, so no second database password is introduced.

The migration requires the database owner to be able to create roles. This is
automatic in the supported Compose deployment. On a managed PostgreSQL service,
pre-create `vulna_runtime` and `vulna_maintenance` with equivalent properties or
run the migration using the service's role-administration account.

CI starts PostgreSQL 17, applies every migration, and proves that:

- no tenant context returns zero protected rows;
- one tenant cannot read another tenant's rows;
- a cross-tenant insert is rejected by PostgreSQL;
- tenant context survives application commits; and
- only the explicit maintenance role can see the aggregate dataset.
