# Scanner process isolation

VulnaScout runs Nmap, Nuclei, testssl.sh, passive/approved-active ZAP, and
Metasploit as unprivileged child processes. Supported Linux deployments also
wrap every invocation in VulnaScout's hidden `scanner-sandbox` helper.

The helper creates a per-invocation home, temporary directory, config directory,
and cache inside a freshly created workspace. It then applies a Landlock
filesystem ruleset on an OS-thread-pinned launch path before starting the
scanner, guaranteeing that the child inherits the domain:

- system binaries, libraries, scanner templates, certificates, `/proc`, and
  `/sys` are read-only;
- the disposable scanner workspace and existing `/dev` nodes are writable;
- `/var/lib/vulna` is not visible to the scanner, so enrollment identity,
  private keys, signed policy, leases, and the offline queue cannot be read or
  modified by a compromised scanner;
- same-UID process inspection is disabled on both the Scout and scanner helper,
  `no_new_privs` is set, and core dumps are disabled;
- cancellation kills the complete scanner process group, including shell/Java
  descendants.

The single-host container adds an immutable root filesystem, a bounded 2 GiB
temporary filesystem, and CPU, memory, and process limits. The systemd units
apply equivalent cgroup resource ceilings. Network access is intentionally not
removed: scanners still need to reach the exact targets authorized by the
locally verified job policy.

## Requirements and failure behavior

The deployment images enable the helper automatically with
`VULNA_SCANNER_SANDBOX_HELPER`. Landlock requires Linux 5.13 or newer. When the
helper is enabled, failure to create or enforce its ruleset is fail-closed: the
scanner is not started and the stage reports an error. Developers running the
Scout directly on macOS or Windows may leave the helper unset; this is not a
supported production isolation mode.

Scanner temporary files must be created beneath the workspace supplied by the
adapter. The helper rejects missing, non-directory, root-temp, symlink-escaped,
or otherwise out-of-tree workspace paths.
