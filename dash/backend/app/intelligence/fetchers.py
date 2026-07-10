"""HTTP fetching for intelligence feeds, with retry and backoff.

Sync jobs depend on the ``Fetcher`` protocol rather than a concrete client so
tests can inject fixture data without touching the network. ``fetch_with_retry``
adds bounded exponential backoff so a transient upstream failure or rate-limit
response is retried a few times before the sync is marked failed (build plan
Section 14.2: "respect upstream rate limits", "failed-sync retries").
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol

import httpx


class FetchError(Exception):
    """Raised when a feed could not be fetched (after any retries)."""


class Fetcher(Protocol):
    """Fetches the raw bytes at a URL. Implementations may be async clients or,
    in tests, canned responses."""

    async def fetch(self, url: str, *, params: Mapping[str, str] | None = None) -> bytes: ...


class HttpFetcher:
    """A ``Fetcher`` backed by httpx with a sane timeout and User-Agent."""

    def __init__(self, *, timeout: float = 30.0, user_agent: str = "VulnaWatch/1.0") -> None:
        self._timeout = timeout
        self._user_agent = user_agent

    async def fetch(self, url: str, *, params: Mapping[str, str] | None = None) -> bytes:
        headers = {"User-Agent": self._user_agent, "Accept": "application/json"}
        query = dict(params) if params else None
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, params=query, headers=headers)
                resp.raise_for_status()
                return resp.content
        except httpx.HTTPError as exc:  # network error or non-2xx
            raise FetchError(f"GET {url} failed: {exc}") from exc


async def fetch_with_retry(
    fetcher: Fetcher,
    url: str,
    *,
    params: Mapping[str, str] | None = None,
    retries: int = 3,
    backoff_base: float = 1.0,
    backoff_cap: float = 30.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> tuple[bytes, int]:
    """Fetch ``url``, retrying on :class:`FetchError` with exponential backoff.

    Returns ``(body, attempts)`` where ``attempts`` is how many requests were
    made (1 when the first succeeds). Raises the last :class:`FetchError` if all
    ``retries`` + 1 attempts fail. ``sleep`` is injectable so tests run instantly
    and can count backoff calls.
    """
    if retries < 0:
        raise ValueError("retries must be >= 0")
    last_exc: FetchError = FetchError(f"GET {url} was not attempted")
    for attempt in range(retries + 1):
        try:
            return await fetcher.fetch(url, params=params), attempt + 1
        except FetchError as exc:
            last_exc = exc
            if attempt == retries:
                break
            delay = min(backoff_base * (2**attempt), backoff_cap)
            await sleep(delay)
    raise last_exc
