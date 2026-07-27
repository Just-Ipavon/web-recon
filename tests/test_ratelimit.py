"""Tests for the throttle that keeps scans from behaving like a DoS."""

from __future__ import annotations

import asyncio
import time

import pytest

from webrecon.ratelimit import Throttle


class TestThrottle:
    async def test_caps_concurrent_holders(self):
        throttle = Throttle(concurrency=3)
        in_flight = 0
        peak = 0

        async def worker():
            nonlocal in_flight, peak
            async with throttle:
                in_flight += 1
                peak = max(peak, in_flight)
                await asyncio.sleep(0.01)
                in_flight -= 1

        await asyncio.gather(*(worker() for _ in range(12)))
        assert peak <= 3

    async def test_paces_requests_to_the_configured_rate(self):
        throttle = Throttle(concurrency=10, rate_per_second=50)

        async def worker():
            async with throttle:
                pass

        start = time.monotonic()
        await asyncio.gather(*(worker() for _ in range(10)))
        # 10 requests at 50/s cannot finish faster than ~0.18s.
        assert time.monotonic() - start >= 0.15

    async def test_runs_without_delay_when_pacing_is_disabled(self):
        throttle = Throttle(concurrency=10, rate_per_second=0)
        start = time.monotonic()
        for _ in range(50):
            async with throttle:
                pass
        assert time.monotonic() - start < 0.5

    async def test_releases_its_slot_when_the_body_raises(self):
        throttle = Throttle(concurrency=1)
        with pytest.raises(RuntimeError):
            async with throttle:
                raise RuntimeError("boom")
        await asyncio.wait_for(throttle.__aenter__(), timeout=0.5)

    @pytest.mark.parametrize("kwargs", [{"concurrency": 0}, {"rate_per_second": -1}])
    def test_rejects_invalid_settings(self, kwargs):
        with pytest.raises(ValueError):
            Throttle(**kwargs)
