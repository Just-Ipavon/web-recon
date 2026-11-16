"""TCP connect scanning of a small, explicit port list.

This is a connect() scan, not a stealth scan: it completes the handshake and
closes cleanly. Slower and fully logged by the target, which is the correct
behaviour for a tool run against systems you own or are authorised to test.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable

from ..models import PortResult
from ..ratelimit import Throttle
from ..targets import is_ip

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

BANNER_BYTES = 256
BANNER_TIMEOUT = 2.0
BANNER_MAX_CHARS = 160


class HostResolutionError(OSError):
    """The host to scan has no address; distinct from "every port closed"."""


def sanitise_banner(data: bytes) -> str | None:
    """Make untrusted banner bytes safe to display: printable text, bounded length."""
    text = data[:BANNER_BYTES].decode("utf-8", errors="replace")
    cleaned = "".join(ch if ch.isprintable() and ch != "�" else " " for ch in text)
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    if len(cleaned) > BANNER_MAX_CHARS:
        cleaned = cleaned[: BANNER_MAX_CHARS - 1] + "…"
    return cleaned


async def resolve(host: str, timeout: float, throttle: Throttle) -> str:
    """Resolve the host once, so every port connects to the same address."""
    if is_ip(host):
        return host
    loop = asyncio.get_running_loop()
    try:
        async with throttle:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout
            )
    except (OSError, UnicodeError, ValueError, asyncio.TimeoutError) as exc:
        detail = "timed out" if isinstance(exc, asyncio.TimeoutError) else str(exc)
        raise HostResolutionError(f"cannot resolve {host}: {detail}") from exc
    if not infos:
        raise HostResolutionError(f"cannot resolve {host}: no addresses")
    # Prefer IPv4, which is what most single-stack scanners can reach.
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    return str(infos[0][4][0])


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    return sanitise_banner(data)


async def check_port(
    host: str, port: int, timeout: float, throttle: Throttle, banner: bool = False
) -> PortResult:
    """Attempt a TCP connection, reporting the port as open only on success."""
    service = COMMON_SERVICES.get(port)
    async with throttle:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            text = await _read_banner(reader, min(timeout, BANNER_TIMEOUT)) if banner else None
            return PortResult(port=port, open=True, service=service, banner=text)
        except (asyncio.TimeoutError, OSError, UnicodeError, ValueError):
            return PortResult(port=port, open=False, service=service)
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 1.0)


async def scan(
    host: str,
    ports: list[int],
    timeout: float = 3.0,
    throttle: Throttle | None = None,
    banners: bool = False,
    on_result: Callable[[PortResult], None] | None = None,
) -> list[PortResult]:
    """Scan the given ports on a host and return only the open ones.

    Raises :class:`HostResolutionError` when the host has no address, so an
    unresolvable host is reported as an error instead of "no open ports".
    """
    throttle = throttle or Throttle(50)
    address = await resolve(host, timeout, throttle)

    async def one(port: int) -> PortResult:
        result = await check_port(address, port, timeout, throttle, banners)
        if result.open and on_result is not None:
            on_result(result)
        return result

    results = await asyncio.gather(*(one(port) for port in ports))
    return sorted((r for r in results if r.open), key=lambda r: r.port)
