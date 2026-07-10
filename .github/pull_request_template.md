# Summary

<!-- What does this change do, and which build-plan phase does it belong to? -->

Phase: <!-- e.g. Phase 1 -->

## Changes

- Files added:
- Files changed:

## Testing

<!-- Commands run and their results. -->

- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] New/updated tests cover the change
- [ ] Negative authorization tests added (if new endpoints)

## Security impact

<!-- Required. Note any effect on the safety guarantees in SECURITY.md:
     scope enforcement, job/policy signing, plugin argument allowlists,
     credential handling, evidence encryption, audit logging. -->

- [ ] No arbitrary command execution introduced
- [ ] Local scope checks not weakened
- [ ] No hard-coded secrets
- [ ] Scanner output treated as untrusted / sanitized

## Known limitations

<!-- Anything intentionally out of scope or deferred. -->
