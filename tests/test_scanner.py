"""Tests for scan orchestration, with every module stubbed out."""

from __future__ import annotations

import pytest

from webrecon import scanner
from webrecon.config import ScanConfig
from webrecon.models import DnsRecords, HttpResult, PortResult, Subdomain, TlsInfo


@pytest.fixture
def stub_modules(monkeypatch):
    """Replace every network-touching module function with a recorded stub."""
    calls: list[str] = []

    async def fake_records(domain, timeout=5.0):
        calls.append("dns")
        return DnsRecords(domain=domain, records={"A": ["1.2.3.4"]})

    async def fake_subdomains(config):
        calls.append("subdomains")
        return [Subdomain(name=f"www.{config.target}", addresses=["1.2.3.4"])]

    async def fake_http(hosts, config):
        calls.append("http")
        return [HttpResult(url=f"https://{h}", reachable=True, status=200) for h in hosts]

    async def fake_tls(hosts, timeout=5.0, concurrency=10):
        calls.append("tls")
        return [TlsInfo(host=h, port=443, valid=True) for h in hosts]

    async def fake_ports(host, ports, timeout=3.0, concurrency=50):
        calls.append("ports")
        return [PortResult(port=443, open=True, service="https")]

    monkeypatch.setattr(scanner.dns_enum, "fetch_records", fake_records)
    monkeypatch.setattr(scanner.dns_enum, "enumerate_subdomains", fake_subdomains)
    monkeypatch.setattr(scanner.http_probe, "probe_hosts", fake_http)
    monkeypatch.setattr(scanner.tls_info, "inspect_hosts", fake_tls)
    monkeypatch.setattr(scanner.port_scan, "scan", fake_ports)
    return calls


class TestRunScan:
    async def test_runs_every_enabled_module(self, stub_modules):
        config = ScanConfig(
            target="example.com",
            modules={"dns", "subdomains", "http", "tls", "ports"},
        )
        report = await scanner.run_scan(config)

        assert set(stub_modules) == {"dns", "subdomains", "http", "tls", "ports"}
        assert report.dns.records["A"] == ["1.2.3.4"]
        assert report.subdomains[0].name == "www.example.com"
        assert report.ports[0].port == 443
        assert report.finished_at is not None

    async def test_skips_modules_that_are_not_enabled(self, stub_modules):
        config = ScanConfig(target="example.com", modules={"dns"})
        report = await scanner.run_scan(config)

        assert stub_modules == ["dns"]
        assert report.subdomains == []
        assert report.http == []

    async def test_probes_discovered_subdomains_rather_than_the_apex(self, stub_modules):
        config = ScanConfig(target="example.com", modules={"subdomains", "http"})
        report = await scanner.run_scan(config)

        assert [r.url for r in report.http] == ["https://www.example.com"]

    async def test_falls_back_to_the_target_when_no_subdomains_resolve(
        self, monkeypatch, stub_modules
    ):
        async def no_subdomains(config):
            return []

        monkeypatch.setattr(scanner.dns_enum, "enumerate_subdomains", no_subdomains)
        config = ScanConfig(target="example.com", modules={"subdomains", "http"})
        report = await scanner.run_scan(config)

        assert [r.url for r in report.http] == ["https://example.com"]

    async def test_reports_stage_progress(self, stub_modules):
        seen: list[str] = []
        config = ScanConfig(target="example.com", modules={"dns", "http"})
        await scanner.run_scan(config, on_stage=seen.append)

        assert any("DNS" in message for message in seen)
        assert any("HTTP" in message for message in seen)

    async def test_records_a_dns_failure_without_aborting(self, monkeypatch, stub_modules):
        async def failing_dns(domain, timeout=5.0):
            return DnsRecords(domain=domain, error="no DNS records resolved")

        monkeypatch.setattr(scanner.dns_enum, "fetch_records", failing_dns)
        config = ScanConfig(target="example.com", modules={"dns", "http"})
        report = await scanner.run_scan(config)

        assert report.errors == ["dns: no DNS records resolved"]
        assert report.http  # the scan carried on
