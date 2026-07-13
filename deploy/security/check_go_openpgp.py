#!/usr/bin/env python3
"""Fail if the unsafe x/crypto OpenPGP package enters a Vulna Go build graph."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOCKED_PREFIX = "golang.org/x/crypto/openpgp"
TARGETS = ("darwin", "linux", "windows")


def main() -> None:
    for module in ("cli", "scout"):
        for goos in TARGETS:
            env = {
                **os.environ,
                "CGO_ENABLED": "0",
                "GOARCH": "amd64",
                "GOOS": goos,
            }
            result = subprocess.run(
                ["go", "list", "-deps", "./..."],
                cwd=ROOT / module,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            blocked = sorted(
                package
                for line in result.stdout.splitlines()
                if (package := line.strip())
                and (package == BLOCKED_PREFIX or package.startswith(f"{BLOCKED_PREFIX}/"))
            )
            if blocked:
                joined = ", ".join(blocked)
                raise SystemExit(
                    f"GO-2026-5932: unsafe OpenPGP packages entered "
                    f"{module} for {goos}/amd64: {joined}"
                )
    print(
        "GO-2026-5932 guard: no x/crypto OpenPGP package is imported "
        "for supported Go targets."
    )


if __name__ == "__main__":
    main()
