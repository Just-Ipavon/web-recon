"""Port scanning against loopback listeners (issues #6, #7, #12, #15)."""

from __future__ import annotations

import socket
import threading
import time

import pytest
from conftest import free_port

from webrecon.modules import port_scan
from webrecon.ratelimit import Throttle


@pytest.fixture
def listener():
    """A TCP listener that sends a banner (with control bytes) on accept."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            with conn:
                conn.sendall(b"SSH-2.0-Test\x1b[31m\x00[bold]x\r\n")
                time.sleep(0.05)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield sock.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    sock.close()


class TestCheckPort:
    async def test_open_port(self, listener):
        result = await port_scan.check_port("127.0.0.1", listener, 1, Throttle(1))
        assert result.open

    async def test_closed_port(self):
        result = await port_scan.check_port("127.0.0.1", free_port(), 1, Throttle(1))
        assert not result.open

    async def test_reads_a_sanitised_banner(self, listener):
        result = await port_scan.check_port("127.0.0.1", listener, 1, Throttle(1), banner=True)
        assert result.banner.startswith("SSH-2.0-Test")
        assert "\x1b" not in result.banner and "\x00" not in result.banner


class TestScan:
    async def test_returns_only_open_ports(self, listener):
        results = await port_scan.scan("127.0.0.1", [listener, free_port()], timeout=1)
        assert [r.port for r in results] == [listener]

    async def test_an_unresolvable_host_raises_instead_of_reporting_all_closed(self):
        with pytest.raises(port_scan.HostResolutionError):
            await port_scan.scan("does-not-exist.invalid", [80], timeout=2)

    async def test_an_invalid_hostname_raises_a_resolution_error(self):
        with pytest.raises(port_scan.HostResolutionError):
            await port_scan.scan(f"{'a' * 64}.example", [80], timeout=1)

    async def test_respects_the_rate_limit(self):
        ports = [free_port() for _ in range(5)]
        start = time.monotonic()
        await port_scan.scan("127.0.0.1", ports, timeout=1, throttle=Throttle(10, 20))
        # 5 connects at 20/s cannot finish faster than ~0.2s.
        assert time.monotonic() - start >= 0.18


class TestSanitiseBanner:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            (b"", None),
            (b"\r\n\r\n", None),
            (b"220 mail ESMTP\r\n", "220 mail ESMTP"),
            (b"\xff\xfe\x00ok", "ok"),
        ],
    )
    def test_cleans_untrusted_bytes(self, raw, expected):
        assert port_scan.sanitise_banner(raw) == expected

    def test_bounds_the_length(self):
        assert len(port_scan.sanitise_banner(b"a" * 1000)) == port_scan.BANNER_MAX_CHARS
