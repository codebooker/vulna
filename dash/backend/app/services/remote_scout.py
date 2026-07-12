"""Helpers for the per-site "Add VulnaScout" flow (Phase 20).

Enrollment itself is unchanged — tokens are single-use, hashed centrally, and
expiring (Phase 2). This module only assembles the copy-paste installation
commands for a freshly minted token. Every convenience command routes through the
signed bootstrap (``scripts/install-scout.sh``), which verifies the release
signature before installing anything, and enrollment never authorizes a target.
"""

from __future__ import annotations

import base64
import shlex
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import Settings


def scout_control_url(public_url: str) -> str:
    """Return the probe mTLS URL, preserving the public host but using :8443."""
    parsed = urlparse(public_url)
    if not parsed.hostname:
        raise ValueError("VULNA_PUBLIC_BASE_URL must contain a hostname or IP address")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme or 'https'}://{host}:8443"


def build_install_commands(
    settings: Settings, server_url: str, token: str, probe_name: str
) -> dict[str, str]:
    """Return ready-to-copy install commands for the supported paths.

    The token is short-lived and single-use; the same value appears in each
    command so the operator can pick whichever install path fits their host. The
    scout auto-detects OS/architecture and installs the server CA itself.
    """
    base = scout_control_url(server_url.rstrip("/"))
    version = settings.release_version or settings.version
    tag = version if version.startswith("v") else f"v{version}"
    bootstrap_url = (
        f"https://github.com/codebooker/vulna/releases/download/{tag}/install-scout.sh"
    )
    ca_env = ""
    ca_path = Path(settings.bootstrap_dir) / "orchestrator-ca.crt"
    try:
        ca_b64 = base64.b64encode(ca_path.read_bytes()).decode("ascii")
    except OSError:
        ca_b64 = ""
    if ca_b64:
        ca_env = f"VULNA_SERVER_CA_B64={shlex.quote(ca_b64)} "

    # One-liner: fetch the verifying bootstrap, then let it verify+install+enroll.
    # Secrets are passed via environment, not argv, so they do not linger in
    # persistent process listings the way a long-lived argument would.
    universal = (
        f"curl -fsSLo /tmp/install-scout.sh {shlex.quote(bootstrap_url)} && "
        f"VULNA_SERVER={shlex.quote(base)} "
        f"VULNA_ENROLL_TOKEN={shlex.quote(token)} {ca_env}"
        f"VULNA_VERSION={shlex.quote(tag)} sh /tmp/install-scout.sh"
    )

    container = (
        "Container installation is not an official remote-Scout path yet; "
        "use the verified Linux installer above."
    )

    cloud_init = (
        "#cloud-config\n"
        "runcmd:\n"
        f"  - {universal}\n"
    )

    return {
        "universal": universal,
        "debian": universal,  # the bootstrap installs the .deb on Debian/Ubuntu
        "container": container,
        "cloud_init": cloud_init,
    }
