"""Target parsing and scope enforcement (issues #8, #10, #13)."""

from __future__ import annotations

import pytest

from webrecon.targets import Scope, Target, TargetError, parse_target


class TestParseTarget:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", Target("example.com")),
            ("https://example.com", Target("example.com", scheme="https")),
            ("HTTPS://Example.COM/", Target("example.com", scheme="https")),
            ("http://example.com/path/here", Target("example.com", scheme="http")),
            ("example.com:8443", Target("example.com", 8443)),
            ("http://user:pw@example.com:8080/x", Target("example.com", 8080, "http")),
            ("example.com.", Target("example.com")),
            ("  example.com  ", Target("example.com")),
            ("example.com?x=1", Target("example.com")),
            ("example.com#frag", Target("example.com")),
            ("2001:db8::1", Target("2001:db8::1")),
            ("::1", Target("::1")),
            ("[::1]", Target("::1")),
            ("http://[::1]:8080/x", Target("::1", 8080, "http")),
            ("192.0.2.10", Target("192.0.2.10")),
            ("192.0.2.10:8443", Target("192.0.2.10", 8443)),
            ("bücher.de", Target("xn--bcher-kva.de")),
            ("localhost", Target("localhost")),
        ],
    )
    def test_accepts_and_normalises(self, raw, expected):
        assert parse_target(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            ".",
            "..",
            "exa mple.com",
            "*.example.com",
            "a..b.com",
            f"{'a' * 64}.com",
            "-bad.example.com",
            "ftp://example.com",
            "example.com:99999",
            "example.com:0",
            "com",
            "co.uk",
            "github.io",
        ],
    )
    def test_rejects(self, raw):
        with pytest.raises(TargetError):
            parse_target(raw)


class TestScope:
    def test_defaults_to_the_target_and_its_subdomains(self):
        scope = Scope.build("example.com")
        assert scope.allows_name("example.com")
        assert scope.allows_name("www.example.com")
        assert not scope.allows_name("example.org")
        assert not scope.allows_name("badexample.com")

    def test_default_scope_for_an_ip_is_that_address(self):
        scope = Scope.build("192.0.2.1")
        assert scope.allows_name("192.0.2.1")
        assert not scope.allows_name("192.0.2.2")

    def test_explicit_entries_replace_the_default(self):
        scope = Scope.build("example.com", ["api.example.com, 198.51.100.0/24"])
        assert scope.allows_name("v1.api.example.com")
        assert not scope.allows_name("www.example.com")
        assert scope.allows_name("198.51.100.7")
        assert scope.explicit

    def test_private_addresses_need_opt_in(self):
        assert Scope.build("127.0.0.1").refusal("127.0.0.1")
        assert Scope.build("10.0.0.1").refusal("10.0.0.1")
        assert Scope.build("::ffff:127.0.0.1").refusal("::ffff:127.0.0.1")
        assert Scope.build("127.0.0.1", allow_private=True).refusal("127.0.0.1") is None

    def test_public_address_in_scope_is_allowed(self):
        assert Scope.build("8.8.8.8").refusal("8.8.8.8") is None

    def test_rejects_an_invalid_entry(self):
        with pytest.raises(TargetError):
            Scope.build("example.com", ["not a domain"])

    def test_describes_itself_for_the_report(self):
        described = Scope.build("example.com", allow_private=True).describe()
        assert "example.com (and subdomains)" in described
        assert "private addresses allowed" in described
