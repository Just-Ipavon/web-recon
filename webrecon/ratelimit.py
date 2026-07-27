"""Concurrency and pacing controls.

Recon tooling that fires unbounded concurrent requests is indistinguishable
from a denial-of-service attempt. Every outbound call in this project passes
through a Throttle so both the in-flight count and the request rate stay
bounded.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType


class Throttle:
    """Caps in-flight work and enforces a minimum spacing between starts.

    Combines a semaphore (how many at once) with a token bucket (how many per
    second). Used as an async context manager::

        async with throttle:
            await do_request()
    """

    def __init__(self, concurrency: int = 20, rate_per_second: float = 0.0) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if rate_per_second < 0:
            raise ValueError("rate_per_second must be >= 0")
        self._sem = asyncio.Semaphore(concurrency)
        self._min_interval = 1.0 / rate_per_second if rate_per_second else 0.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def _wait_for_slot(self) -> None:
        if not self._min_interval:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + self._min_interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def __aenter__(self) -> Throttle:
        await self._sem.acquire()
        try:
            await self._wait_for_slot()
        except BaseException:
            self._sem.release()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._sem.release()
