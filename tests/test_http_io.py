"""HTTP probing against a loopback server (issues #11, #12, #13, #14, #17)."""

from __future__ import annotations

import httpx
import pytest
from conftest import response

from webrecon.config import ScanConfig
from webrecon.context import ScanContext
from webrecon.modules import http_probe
from webrecon.ratelimit import Throttle
from webrecon.targets import Scope


@pytest.fixture
async def client():
    async with httpx.AsyncClient(timeout=2, follow_redirects=False, trust_env=False) as c:
        yield c


def scope_for_loopback() -> Scope:
    return Scope.build("127.0.0.1", allow_private=True)


class TestProbeUrl:
    async def test_reads_status_title_headers_and_findings(self, http_server, client):
        server = http_server(
            {
                "/": response(
                    200,
                    "<html><head><title>Home &amp; Away</title></head></html>",
                    [("Server", "nginx/1.25"), ("Set-Cookie", "sid=topsecret; Path=/"),
                     ("Content-Type", "text/html")],
                )
            }
        )
        result = await http_probe.probe_url(client, server.url, Throttle(5))
        assert result.reachable and result.status == 200
        assert result.title == "Home & Away"
        assert "nginx" in result.technologies
        assert "topsecret" not in result.headers["set-cookie"]
        assert "missing Content-Security-Policy" in result.findings
        assert any(f.startswith("cookie sid without") for f in result.findings)

    async def test_follows_and_records_a_redirect_chain(self, http_server, client):
        server = http_server(
            {
                "/": response(301, "", [("Location", "/a")]),
                "/a": response(302, "", [("Location", "/b")]),
                "/b": response(200, "<title>end</title>"),
            }
        )
        result = await http_probe.probe_url(client, server.url + "/", Throttle(5),
                                            discover_paths=False)
        assert [r.status for r in result.redirects] == [301, 302]
        assert result.final_url.endswith("/b")
        assert result.title == "end"

    async def test_reports_a_redirect_loop(self, http_server, client):
        server = http_server(
            {
                "/a": response(302, "", [("Location", "/b")]),
                "/b": response(302, "", [("Location", "/a")]),
            }
        )
        result = await http_probe.probe_url(client, server.url + "/a", Throttle(5),
                                            discover_paths=False)
        assert not result.reachable
        assert "redirect loop" in result.error

    async def test_does_not_follow_a_redirect_out_of_scope(self, http_server, client):
        server = http_server({"/": response(302, "", [("Location", "https://evil.test/x")])})
        skipped: list[tuple[str, str]] = []
        result = await http_probe.probe_url(
            client, server.url + "/", Throttle(5), discover_paths=False,
            scope=scope_for_loopback(), on_skip=lambda h, r: skipped.append((h, r)),
        )
        assert result.reachable and result.status == 302
        assert skipped[0][0] == "evil.test"
        assert all("evil.test" not in hit for hit in server.hits)

    async def test_unreachable_host_is_an_error_not_a_crash(self, client):
        from conftest import free_port

        result = await http_probe.probe_url(client, f"http://127.0.0.1:{free_port()}", Throttle(1))
        assert result.reachable is False
        assert result.error

    async def test_honours_the_per_host_budget(self, http_server, client):
        server = http_server({"/": response(200, "<title>x</title>")})
        budget = http_probe.RequestBudget(2)
        result = await http_probe.probe_url(client, server.url, Throttle(5), budget=budget)
        assert result.reachable
        assert len(server.hits) == 2  # the page itself and one discovery request


class TestDiscoverContent:
    async def test_finds_real_files_and_expands_robots(self, http_server, client):
        server = http_server(
            {
                "/robots.txt": response(200, "User-agent: *\nDisallow: /admin"),
                "/.git/HEAD": response(200, "ref: refs/heads/main\n"),
                "/.env": response(200, "<html>nope</html>", [("Content-Type", "text/html")]),
            }
        )
        found = await http_probe.discover_content(client, server.url, Throttle(5))
        assert found == ["/robots.txt", "robots: /admin", "/.git/HEAD"]

    async def test_a_server_that_answers_200_to_everything_yields_nothing(
        self, http_server, client
    ):
        server = http_server(default=response(200, "User-agent: *\nDisallow: /"))
        assert await http_probe.discover_content(client, server.url, Throttle(5)) == []


class TestProbeHosts:
    async def test_falls_back_to_http_and_records_unreachable_hosts(self, http_server):
        server = http_server({"/": response(200, "<title>plain</title>")})
        config = ScanConfig(target="127.0.0.1", timeout=2, allow_private=True)
        ctx = ScanContext.create(config)
        results = await http_probe.probe_hosts(
            [("127.0.0.1", server.port, None)], ctx
        )
        assert results[0].reachable
        assert results[0].url == f"http://127.0.0.1:{server.port}"

    async def test_rate_applies_to_http_requests(self, http_server):
        import time

        server = http_server({"/": response(200, "x")})
        config = ScanConfig(target="127.0.0.1", rate_per_second=20, allow_private=True)
        ctx = ScanContext.create(config)
        start = time.monotonic()
        await http_probe.probe_hosts([("127.0.0.1", server.port, "http")], ctx)
        # page + random baseline + 5 discovery paths = 7 requests at 20/s
        assert time.monotonic() - start >= 0.25
