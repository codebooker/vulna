"""Helpers for the per-site "Add VulnaScout" flow (Phase 20).

Enrollment itself is unchanged — tokens are single-use, hashed centrally, and
expiring (Phase 2). This module only assembles the copy-paste installation
commands for a freshly minted token. Every convenience command routes through the
signed bootstrap (``scripts/install-scout.sh``), which verifies the release
signature before installing anything, and enrollment never authorizes a target.
"""

from __future__ import annotations

# The verified bootstrap script served alongside releases. It downloads a pinned,
# signed VulnaScout release, checks its checksum + Ed25519 signature, installs it,
# and enrolls with the one-time token — never piping unverified content to a shell.
BOOTSTRAP_SCRIPT = "install-scout.sh"


def build_install_commands(server_url: str, token: str, probe_name: str) -> dict[str, str]:
    """Return ready-to-copy install commands for the supported paths.

    The token is short-lived and single-use; the same value appears in each
    command so the operator can pick whichever install path fits their host. The
    scout auto-detects OS/architecture and installs the server CA itself.
    """
    base = server_url.rstrip("/")
    bootstrap_url = f"{base}/{BOOTSTRAP_SCRIPT}"

    # One-liner: fetch the verifying bootstrap, then let it verify+install+enroll.
    # Secrets are passed via environment, not argv, so they do not linger in
    # persistent process listings the way a long-lived argument would.
    universal = (
        f"curl -fsSLO {bootstrap_url} && "
        f"VULNA_SERVER={base} VULNA_ENROLL_TOKEN={token} sh {BOOTSTRAP_SCRIPT}"
    )

    container = (
        f"docker run --rm -e VULNA_ENROLL_TOKEN={token} "
        f"-v vulna-scout:/var/lib/vulna vulna/vulnascout "
        f"enroll --server {base}"
    )

    cloud_init = (
        "#cloud-config\n"
        "runcmd:\n"
        f"  - curl -fsSLO {bootstrap_url}\n"
        f"  - VULNA_SERVER={base} VULNA_ENROLL_TOKEN={token} sh {BOOTSTRAP_SCRIPT}\n"
    )

    return {
        "universal": universal,
        "debian": universal,  # the bootstrap installs the .deb on Debian/Ubuntu
        "container": container,
        "cloud_init": cloud_init,
    }
