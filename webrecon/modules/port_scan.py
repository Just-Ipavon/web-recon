"""TCP connect scanning of a small, explicit port list.

This is a connect() scan, not a stealth scan: it completes the handshake and
closes cleanly. Slower and fully logged by the target, which is the correct
behaviour for a tool run against systems you own or are authorised to test.
"""

from __future__ import annotations

import asyncio
import contextlib

from ..models import PortResult
from ..ratelimit import Throttle

COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


async def check_port(
    host: str, port: int, timeout: float, throttle: Throttle
) -> PortResult:
    """Attempt a TCP connection, reporting the port as open only on success."""
    async with throttle:
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            return PortResult(port=port, open=True, service=COMMON_SERVICES.get(port))
        except (asyncio.TimeoutError, OSError):
            return PortResult(port=port, open=False, service=COMMON_SERVICES.get(port))
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()


async def scan(
    host: str, ports: list[int], timeout: float = 3.0, concurrency: int = 50
) -> list[PortResult]:
    """Scan the given ports on a host and return only the open ones."""
    throttle = Throttle(concurrency)
    results = await asyncio.gather(
        *(check_port(host, port, timeout, throttle) for port in ports)
    )
    return sorted((r for r in results if r.open), key=lambda r: r.port)
