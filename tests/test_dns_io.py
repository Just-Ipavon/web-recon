"""DNS lookups against a loopback DNS server (issues #6, #7, #10, #15)."""

from __future__ import annotations

import json

import pytest
from conftest import response

from webrecon.config import ScanConfig
from webrecon.context import ScanContext
from webrecon.modules import dns_enum
from webrecon.ratelimit import Throttle

ZONE = {
    ("example.com", "A"): ["93.184.216.34"],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "TXT"): ['"v=spf1 -all"'],
    ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"'],
    ("www.example.com", "A"): ["93.184.216.34"],
    ("api.example.com", "A"): ["93.184.216.35"],
}


def config_for(server, **kwargs) -> ScanConfig:
    kwargs.setdefault("passive", False)
    return ScanConfig(
        target="example.com",
        timeout=1,
        nameservers=["127.0.0.1"],
        dns_port=server.port,
        **kwargs,
    )


class TestFetchRecords:
    async def test_reads_records_status_and_mail_hints(self, fake_dns):
        server = fake_dns(ZONE)
        result = await dns_enum.fetch_records(
            "example.com", 1, nameservers=["127.0.0.1"], port=server.port
        )
        assert result.records["A"] == ["93.184.216.34"]
        assert result.records["CAA"] == ['0 issue "letsencrypt.org"']
        assert result.status["AAAA"] == "NOANSWER"
        assert result.records["DMARC"] == ['"v=DMARC1; p=none"']
        assert any("p=none" in f for f in result.findings)
        assert result.error is None

    async def test_distinguishes_nxdomain(self, fake_dns):
        server = fake_dns(ZONE)
        result = await dns_enum.fetch_records(
            "missing.example.com", 1, nameservers=["127.0.0.1"], port=server.port
        )
        assert set(result.status.values()) == {"NXDOMAIN"}
        assert result.error == "domain does not exist (NXDOMAIN)"

    async def test_distinguishes_servfail(self, fake_dns):
        server = fake_dns(ZONE, servfail={"broken.example.com"})
        result = await dns_enum.fetch_records(
            "broken.example.com", 1, nameservers=["127.0.0.1"], port=server.port
        )
        assert result.status["A"] == "SERVFAIL"
        assert "SERVFAIL" in result.error

    async def test_respects_the_shared_rate(self, fake_dns):
        import time

        server = fake_dns(ZONE)
        start = time.monotonic()
        await dns_enum.fetch_records(
            "missing.example.com", 1, Throttle(10, 20), ["127.0.0.1"], server.port
        )
        # 8 record types at 20/s
        assert time.monotonic() - start >= 0.3

    async def test_missing_resolver_configuration_is_an_error_entry(self, monkeypatch):
        import dns.resolver

        def no_config(*args, **kwargs):
            raise dns.resolver.NoResolverConfiguration("no nameservers")

        monkeypatch.setattr(dns_enum, "make_resolver", no_config)
        result = await dns_enum.fetch_records("example.com")
        assert "no usable DNS resolver" in result.error


class TestEnumerateSubdomains:
    async def test_brute_force_finds_existing_names(self, fake_dns, tmp_path):
        server = fake_dns(ZONE)
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("www\napi\nnope\n")
        ctx = ScanContext.create(config_for(server, wordlist=wordlist))
        subs = await dns_enum.enumerate_subdomains(ctx)
        assert [s.name for s in subs] == ["api.example.com", "example.com", "www.example.com"]
        assert {s.name: s.source for s in subs}["example.com"] == "target"

    async def test_wildcard_zone_yields_no_false_subdomains(self, fake_dns, tmp_path):
        server = fake_dns(
            ZONE, wildcard_suffix="example.com", wildcard={"A": ["203.0.113.9"]}
        )
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("\n".join(f"guess{i}" for i in range(20)) + "\nwww\n")
        ctx = ScanContext.create(config_for(server, wordlist=wordlist))
        subs = await dns_enum.enumerate_subdomains(ctx)
        assert sorted(s.name for s in subs) == ["example.com", "www.example.com"]
        assert any("wildcard DNS detected" in n for n in ctx.report.notes)

    async def test_apex_is_kept_with_source_target_when_crtsh_lists_it(
        self, fake_dns, http_server, monkeypatch
    ):
        names = ["example.com"] + [f"h{i}.example.com" for i in range(30)]
        crt = http_server({"/": response(200, json.dumps([{"name_value": n} for n in names]))})
        monkeypatch.setattr(dns_enum, "CRT_SH_URL", crt.url + "/")
        server = fake_dns(ZONE)
        ctx = ScanContext.create(config_for(server, passive=True, max_subdomains=5))
        subs = await dns_enum.enumerate_subdomains(ctx)
        assert {s.name: s.source for s in subs}.get("example.com") == "target"
        assert crt.agents and crt.agents[0].startswith("webrecon/")

    async def test_crtsh_failure_is_recorded(self, fake_dns, http_server, monkeypatch):
        crt = http_server({"/": response(502, "bad gateway")})
        monkeypatch.setattr(dns_enum, "CRT_SH_URL", crt.url + "/")
        server = fake_dns(ZONE)
        ctx = ScanContext.create(config_for(server, passive=True))
        await dns_enum.enumerate_subdomains(ctx)
        assert any("crt.sh lookup failed" in e for e in ctx.report.errors)

    async def test_out_of_scope_candidates_are_skipped(self, fake_dns, tmp_path):
        server = fake_dns(ZONE)
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("www\napi\n")
        ctx = ScanContext.create(
            config_for(server, wordlist=wordlist, scope=["api.example.com"])
        )
        subs = await dns_enum.enumerate_subdomains(ctx)
        assert [s.name for s in subs] == ["api.example.com"]
        assert {s.host for s in ctx.report.skipped} == {"example.com", "www.example.com"}


@pytest.mark.parametrize("status", ["NXDOMAIN", "TIMEOUT", "SERVFAIL"])
def test_summarise_failure_names_the_cause(status):
    message = dns_enum.summarise_failure({"A": status, "AAAA": status})
    assert message != "no DNS records resolved"
