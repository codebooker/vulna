"""Resolve signed endpoint release locations for Scout and Relay installers."""

from __future__ import annotations

from dataclasses import dataclass

RELEASES_URL = "https://github.com/codebooker/vulna/releases"


@dataclass(frozen=True)
class EndpointRelease:
    """The bootstrap URL and version value passed to an endpoint installer."""

    base_url: str
    version: str

    def installer_url(self, filename: str) -> str:
        return f"{self.base_url}/{filename}"


def resolve_endpoint_release(
    configured_version: str | None, application_version: str
) -> EndpointRelease:
    """Resolve ``latest`` without fabricating a ``vlatest`` GitHub tag.

    Explicit versions stay pinned to their tag.  ``latest`` uses GitHub's
    latest-release redirect; the bootstrap then reads the signed release's
    ``VERSION`` asset before selecting its architecture-specific binary.
    """
    version = (configured_version or application_version).strip()
    if version.lower() == "latest":
        return EndpointRelease(f"{RELEASES_URL}/latest/download", "latest")
    tag = version if version.startswith("v") else f"v{version}"
    return EndpointRelease(f"{RELEASES_URL}/download/{tag}", tag)
