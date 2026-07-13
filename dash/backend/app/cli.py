"""Command-line interface for VulnaDash.

Exposed as the ``vulna`` console script with bootstrap, worker, and scheduler
process entry points used by the production Compose deployment.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys
from collections.abc import Coroutine
from typing import Any

from app import __version__
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import dispose_engine, get_engine, get_sessionmaker
from app.services.background_tasks import default_process_id
from app.services.bootstrap import (
    BootstrapError,
    ensure_bootstrap_admin,
    ensure_default_organization,
)
from app.tasks.runner import run_scheduler_once, run_worker_once, scheduler_loop, worker_loop


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


async def _run_worker(*, once: bool, worker_id: str | None) -> int:
    settings = get_settings()
    identity = worker_id or default_process_id("worker")
    try:
        if once:
            await run_worker_once(settings, identity)
        else:
            await _until_terminated(worker_loop(settings, identity))
    finally:
        await dispose_engine()
    return 0


async def _run_scheduler(*, once: bool, scheduler_id: str | None) -> int:
    settings = get_settings()
    identity = scheduler_id or default_process_id("scheduler")
    try:
        if once:
            await run_scheduler_once(settings, identity)
        else:
            await _until_terminated(scheduler_loop(settings, identity))
    finally:
        await dispose_engine()
    return 0


async def _until_terminated(service: Coroutine[Any, Any, None]) -> None:
    """Cancel a service cooperatively on SIGTERM so leases are released/retried."""
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    with contextlib.suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGTERM, stopped.set)
    service_task = asyncio.create_task(service)
    signal_task = asyncio.create_task(stopped.wait())
    done, _ = await asyncio.wait(
        {service_task, signal_task}, return_when=asyncio.FIRST_COMPLETED
    )
    if signal_task in done and not service_task.done():
        service_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await service_task
    else:
        signal_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await signal_task
        await service_task


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

    worker = sub.add_parser("worker", help="Run the durable background-task worker")
    worker.add_argument("--once", action="store_true", help="Claim at most one task and exit")
    worker.add_argument("--worker-id", help="Stable worker identity (defaults to host and pid)")

    scheduler = sub.add_parser("scheduler", help="Run the durable task scheduler")
    scheduler.add_argument("--once", action="store_true", help="Run one leader-election tick")
    scheduler.add_argument(
        "--scheduler-id", help="Stable scheduler identity (defaults to host and pid)"
    )

    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "bootstrap-admin":
        return asyncio.run(_bootstrap_admin(create_tables=args.create_tables))
    if args.command == "worker":
        return asyncio.run(_run_worker(once=args.once, worker_id=args.worker_id))
    if args.command == "scheduler":
        return asyncio.run(_run_scheduler(once=args.once, scheduler_id=args.scheduler_id))

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
