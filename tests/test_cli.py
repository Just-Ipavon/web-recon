"""Tests for argument parsing and target normalisation."""

from __future__ import annotations

import argparse

import pytest

from webrecon import cli


class TestNormaliseTarget:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "example.com"),
            ("https://example.com", "example.com"),
            ("http://example.com/path/here", "example.com"),
            ("HTTPS://Example.COM/", "example.com"),
            ("example.com:8443", "example.com"),
            ("example.com.", "example.com"),
            ("  example.com  ", "example.com"),
        ],
    )
    def test_reduces_input_to_a_bare_hostname(self, raw, expected):
        assert cli.normalise_target(raw) == expected

    def test_rejects_an_empty_target(self):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.normalise_target("   ")


class TestParsePorts:
    def test_parses_a_list(self):
        assert cli.parse_ports("80,443,22") == [22, 80, 443]

    def test_parses_a_range(self):
        assert cli.parse_ports("80-83") == [80, 81, 82, 83]

    def test_parses_a_mixed_specification_and_deduplicates(self):
        assert cli.parse_ports("443,80-82,443") == [80, 81, 82, 443]

    @pytest.mark.parametrize("bad", ["", "abc", "80-", "90-80", "0", "70000", "80,abc"])
    def test_rejects_invalid_input(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports(bad)


class TestResolveModules:
    def test_expands_all(self):
        assert cli.resolve_modules("all") == set(cli.ALL_MODULES)

    def test_parses_an_explicit_list(self):
        assert cli.resolve_modules("dns,http") == {"dns", "http"}

    def test_rejects_unknown_modules(self):
        with pytest.raises(SystemExit):
            cli.resolve_modules("dns,bogus")

    def test_rejects_an_empty_selection(self):
        with pytest.raises(SystemExit):
            cli.resolve_modules(",,")


class TestParser:
    def test_applies_defaults(self):
        args = cli.build_parser().parse_args(["example.com"])
        assert args.target == "example.com"
        assert args.concurrency == 20
        assert args.rate == 0.0

    def test_normalises_the_target_argument(self):
        args = cli.build_parser().parse_args(["https://example.com/x"])
        assert args.target == "example.com"

    def test_requires_a_target(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args([])
