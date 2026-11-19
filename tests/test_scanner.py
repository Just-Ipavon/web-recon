"""Tests for scan orchestration, with every module stubbed out (issues #6, #7, #14)."""

from __future__ import annotations

import asyncio

import pytest

from webrecon import scanner
from webrecon.config import ScanConfig
from webrecon.models import DnsRecords, HttpResult, PortResult, Subdomain, TlsInfo


@pytest.fixture
def stub_modules(monkeypatch):
    """Replace every network-touching module function with a recorded stub."""
    calls: list[str] = []
    seen: dict[str, object] = {}

    async def fake_records(domain, timeout=5.0, throttle=None, *args, **kwargs):
        calls.append("dns")
        seen["dns_throttle"] = throttle
        return DnsRecords(domain=domain, records={"A": ["1.2.3.4"]})

    async def fake_subdomains(ctx):
        calls.append("subdomains")
        seen["subdomains_throttle"] = ctx.throttle
        return [Subdomain(name=f"www.{ctx.config.target}", addresses=["1.2.3.4"])]

    async def fake_http(endpoints, ctx):
        calls.append("http")
        seen["http_throttle"] = ctx.throttle
        seen["endpoints"] = endpoints
        return [
            HttpResult(url=f"https://{h}" + (f":{p}" if p else ""), reachable=True, status=200)
            for h, p, _ in endpoints
        ]

    async def fake_tls(endpoints, ctx):
        calls.append("tls")
        seen["tls_throttle"] = ctx.throttle
        seen["tls_endpoints"] = list(endpoints)
        return [TlsInfo(host=h, port=p, valid=True) for h, p in endpoints]

    async def fake_ports(host, ports, timeout=3.0, throttle=None, banners=False, on_result=None):
        calls.append("ports")
        seen["ports_throttle"] = throttle
        return [PortResult(port=443, open=True, service="https"),
                PortResult(port=8443, open=True, service="https-alt")]

    monkeypatch.setattr(scanner.dns_enum, "fetch_records", fake_records)
    monkeypatch.setattr(scanner.dns_enum, "enumerate_subdomains", fake_subdomains)
    monkeypatch.setattr(scanner.http_probe, "probe_hosts", fake_http)
    monkeypatch.setattr(scanner.tls_info, "inspect_hosts", fake_tls)
    monkeypatch.setattr(scanner.port_scan, "scan", fake_ports)
    return calls, seen


def make_config(**kwargs) -> ScanConfig:
    kwargs.setdefault("target", "example.com")
    kwargs.setdefault("allow_private", True)  # skip the target address lookup
    return ScanConfig(**kwargs)


class TestRunScan:
    async def test_runs_every_enabled_module(self, stub_modules):
        calls, _ = stub_modules
        report = await scanner.run_scan(
            make_config(modules={"dns", "subdomains", "http", "tls", "ports"})
        )
        assert set(calls) == {"dns", "subdomains", "http", "tls", "ports"}
        assert report.dns.records["A"] == ["1.2.3.4"]
        assert report.subdomains[0].name == "www.example.com"
        assert report.ports[0].port == 443
        assert report.finished_at is not None
        assert report.complete is True

    async def test_every_module_shares_one_throttle(self, stub_modules):
        _, seen = stub_modules
        await scanner.run_scan(make_config(modules={"dns", "subdomains", "http", "tls", "ports"}))
        throttles = {id(v) for k, v in seen.items() if k.endswith("_throttle")}
        assert len(throttles) == 1

    async def test_skips_modules_that_are_not_enabled(self, stub_modules):
        calls, _ = stub_modules
        report = await scanner.run_scan(make_config(modules={"dns"}))
        assert calls == ["dns"]
        assert report.subdomains == []
        assert report.http == []

    async def test_probes_discovered_subdomains_rather_than_the_apex(self, stub_modules):
        report = await scanner.run_scan(make_config(modules={"subdomains", "http"}))
        assert [r.url for r in report.http] == ["https://www.example.com"]

    async def test_falls_back_to_the_target_when_no_subdomains_resolve(
        self, monkeypatch, stub_modules
    ):
        async def no_subdomains(ctx):
            return []

        monkeypatch.setattr(scanner.dns_enum, "enumerate_subdomains", no_subdomains)
        report = await scanner.run_scan(make_config(modules={"subdomains", "http"}))
        assert [r.url for r in report.http] == ["https://example.com"]

    async def test_open_web_ports_feed_the_http_and_tls_stages(self, stub_modules):
        _, seen = stub_modules
        await scanner.run_scan(make_config(modules={"ports", "http", "tls"}))
        assert ("example.com", 8443, None) in seen["endpoints"]
        assert ("example.com", 8443) in seen["tls_endpoints"]

    async def test_probes_the_port_given_in_the_target(self, stub_modules):
        _, seen = stub_modules
        await scanner.run_scan(make_config(modules={"http", "tls"}, port=8443, scheme="https"))
        assert seen["endpoints"] == [("example.com", 8443, "https")]
        assert seen["tls_endpoints"] == [("example.com", 8443)]

    async def test_reports_stage_progress(self, stub_modules):
        seen: list[str] = []
        await scanner.run_scan(make_config(modules={"dns", "http"}), on_stage=seen.append)
        assert any("DNS" in message for message in seen)
        assert any("HTTP" in message for message in seen)

    async def test_records_a_dns_failure_without_aborting(self, monkeypatch, stub_modules):
        async def failing_dns(domain, *args, **kwargs):
            return DnsRecords(domain=domain, error="no DNS records resolved")

        monkeypatch.setattr(scanner.dns_enum, "fetch_records", failing_dns)
        report = await scanner.run_scan(make_config(modules={"dns", "http"}))
        assert report.errors == ["dns: no DNS records resolved"]
        assert report.http  # the scan carried on

    async def test_an_exception_in_one_stage_keeps_the_other_results(
        self, monkeypatch, stub_modules
    ):
        async def broken_tls(endpoints, ctx):
            raise UnicodeError("label too long")

        monkeypatch.setattr(scanner.tls_info, "inspect_hosts", broken_tls)
        report = await scanner.run_scan(make_config(modules={"dns", "http", "tls", "ports"}))
        assert report.dns.records
        assert report.http and report.ports
        assert any(e.startswith("tls: UnicodeError") for e in report.errors)
        assert report.complete is False
        assert report.incomplete_reason == "1 error during the scan (see errors)"

    async def test_a_failed_module_marks_the_report_incomplete(
        self, monkeypatch, stub_modules
    ):
        async def failing_dns(domain, *args, **kwargs):
            return DnsRecords(domain=domain, error="DNS queries timed out")

        monkeypatch.setattr(scanner.dns_enum, "fetch_records", failing_dns)
        report = await scanner.run_scan(make_config(modules={"dns", "http"}))
        assert report.complete is False
        assert "1 error" in report.incomplete_reason

    async def test_a_silent_in_scope_host_marks_the_report_incomplete(
        self, monkeypatch, stub_modules
    ):
        async def silent_http(endpoints, ctx):
            return [
                HttpResult(url="https://www.example.com", reachable=False,
                           error="ConnectTimeout: timed out", timed_out=True),
                HttpResult(url="https://example.com", reachable=False,
                           error="ConnectError: connection refused"),
            ]

        async def silent_tls(endpoints, ctx):
            return [TlsInfo(host="api.example.com", port=443, valid=False,
                            error=scanner.tls_info.HANDSHAKE_TIMEOUT)]

        monkeypatch.setattr(scanner.http_probe, "probe_hosts", silent_http)
        monkeypatch.setattr(scanner.tls_info, "inspect_hosts", silent_tls)
        report = await scanner.run_scan(make_config(modules={"http", "tls"}))
        assert report.complete is False
        # A refused connection is an answer; only the timeouts count.
        assert report.incomplete_reason == (
            "no response from in-scope host(s): www.example.com, api.example.com"
        )

    async def test_max_time_returns_a_partial_report(self, monkeypatch, stub_modules):
        async def slow_http(endpoints, ctx):
            await asyncio.sleep(5)
            return []

        monkeypatch.setattr(scanner.http_probe, "probe_hosts", slow_http)
        report = await scanner.run_scan(make_config(modules={"dns", "http"}, max_time=0.2))
        assert report.dns.records  # gathered before the limit
        assert report.complete is False
        assert "maximum scan time" in report.incomplete_reason
        assert report.finished_at is not None

    async def test_emits_results_as_they_arrive(self, stub_modules):
        events: list[str] = []
        await scanner.run_scan(
            make_config(modules={"dns"}), emit=lambda kind, payload: events.append(kind)
        )
        assert events[0] == "dns"
        assert events[-1] == "summary"

    async def test_records_scope_and_settings(self, stub_modules):
        report = await scanner.run_scan(
            make_config(modules={"dns"}, proxy="http://user:secret@proxy.test:3128")
        )
        assert report.scope[0] == "example.com (and subdomains)"
        assert report.settings["proxy"] == "http://<redacted>@proxy.test:3128"
        assert "directly" in report.settings["proxy_applies_to"]


class TestTargetGate:
    async def test_private_target_is_skipped_without_opt_in(self, stub_modules):
        calls, _ = stub_modules
        report = await scanner.run_scan(
            ScanConfig(target="127.0.0.1", modules={"http", "ports"})
        )
        assert calls == []
        assert report.skipped[0].host == "127.0.0.1"
        assert "non-public" in report.skipped[0].reason

    async def test_name_resolving_to_loopback_is_skipped(self, stub_modules):
        calls, _ = stub_modules
        report = await scanner.run_scan(ScanConfig(target="localhost", modules={"http"}))
        assert calls == []
        assert report.skipped and report.skipped[0].host == "localhost"

    async def test_out_of_scope_target_is_skipped(self, stub_modules):
        calls, _ = stub_modules
        report = await scanner.run_scan(
            make_config(modules={"http"}, scope=["other.example.org"])
        )
        assert calls == []
        assert report.skipped[0].reason == "out of scope"

    async def test_subdomains_on_private_addresses_are_not_probed(
        self, monkeypatch, stub_modules
    ):
        async def private_subdomains(ctx):
            return [
                Subdomain(name="intranet.example.com", addresses=["10.0.0.5"]),
                Subdomain(name="www.example.com", addresses=["93.184.216.34"]),
            ]

        monkeypatch.setattr(scanner.dns_enum, "enumerate_subdomains", private_subdomains)
        monkeypatch.setattr(scanner, "_target_refusal", _no_refusal)
        report = await scanner.run_scan(
            ScanConfig(target="example.com", modules={"subdomains", "http"})
        )
        assert [r.url for r in report.http] == ["https://www.example.com"]
        assert report.skipped[0].host == "intranet.example.com"


async def _no_refusal(ctx):
    return None
