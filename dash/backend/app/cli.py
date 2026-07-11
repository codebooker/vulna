"""Command-line interface for VulnaDash.

Exposed as the ``vulna`` console script. Phase 1 provides ``version`` and
``bootstrap-admin``; later phases add ``worker`` and ``scheduler`` subcommands
referenced by the production Compose file.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app import __version__
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import dispose_engine, get_engine, get_sessionmaker
from app.services.bootstrap import (
    BootstrapError,
    ensure_bootstrap_admin,
    ensure_default_organization,
)


async def _bootstrap_admin(create_tables: bool) -> int:
    settings = get_settings()
    if create_tables:
        import app.models  # noqa: F401

        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    factory = get_sessionmaker()
    async with factory() as session:
        org = await ensure_default_organization(session, settings)
        try:
            admin = await ensure_bootstrap_admin(session, settings)
        except BootstrapError as exc:
            print(f"error: {exc}", file=sys.stderr)
            await dispose_engine()
            return 2
        await session.commit()

    if admin is not None:
        print(f"Created administrator '{admin.email}' in organization '{org.slug}'.")
    else:
        print(
            "No administrator created: either one already exists or "
            "VULNA_ADMIN_EMAIL/VULNA_ADMIN_PASSWORD are not set."
        )
    await dispose_engine()
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="vulna", description="VulnaDash management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="Print the VulnaDash version")

    bootstrap = sub.add_parser(
        "bootstrap-admin",
        help="Seed the default organization and first administrator from the environment",
    )
    bootstrap.add_argument(
        "--create-tables",
        action="store_true",
        help="Create tables from the ORM metadata first (dev convenience; prod uses migrations)",
    )

    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "bootstrap-admin":
        return asyncio.run(_bootstrap_admin(create_tables=args.create_tables))

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
