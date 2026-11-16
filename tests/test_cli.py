"""Tests for argument parsing and option validation (issue #8)."""

from __future__ import annotations

import argparse
import time

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
            ("2001:db8::1", "2001:db8::1"),
        ],
    )
    def test_reduces_input_to_a_bare_hostname(self, raw, expected):
        assert cli.normalise_target(raw) == expected

    @pytest.mark.parametrize("raw", ["   ", ".", "..", "exa mple.com"])
    def test_rejects_unusable_targets(self, raw):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.normalise_target(raw)


class TestParsePorts:
    def test_parses_a_list(self):
        assert cli.parse_ports("80,443,22") == [22, 80, 443]

    def test_parses_a_range(self):
        assert cli.parse_ports("80-83") == [80, 81, 82, 83]

    def test_parses_a_mixed_specification_and_deduplicates(self):
        assert cli.parse_ports("443,80-82,443") == [80, 81, 82, 443]

    @pytest.mark.parametrize(
        "bad",
        ["", "abc", "80-", "90-80", "0", "70000", "80,abc", "+80", "8_0", "٨٠", "-80", "1-0"],
    )
    def test_rejects_invalid_input(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports(bad)

    def test_checks_bounds_before_building_a_huge_range(self):
        start = time.monotonic()
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports("1-30000000")
        assert time.monotonic() - start < 0.1


class TestResolveModules:
    def test_expands_all(self):
        assert cli.resolve_modules("all") == set(cli.ALL_MODULES)

    def test_all_inside_a_list_still_means_all(self):
        assert cli.resolve_modules("all,dns") == set(cli.ALL_MODULES)

    def test_parses_an_explicit_list(self):
        assert cli.resolve_modules("dns,http") == {"dns", "http"}

    def test_rejects_unknown_modules(self):
        with pytest.raises(SystemExit):
            cli.resolve_modules("dns,bogus")

    def test_rejects_an_empty_selection(self):
        with pytest.raises(SystemExit):
            cli.resolve_modules(",,")


class TestNumericOptions:
    @pytest.mark.parametrize(
        "argv",
        [
            ["-r", "-1"],
            ["-t", "0"],
            ["-t", "-1"],
            ["-c", "0"],
            ["-c", "1.5"],
            ["--max-subdomains", "-3"],
            ["--max-time", "0"],
            ["-t", "abc"],
        ],
    )
    def test_invalid_values_exit_2_before_scanning(self, argv, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["example.com", *argv])
        assert exc.value.code == 2

    def test_accepts_zero_rate(self):
        assert cli.build_parser().parse_args(["example.com", "-r", "0"]).rate == 0.0


class TestParser:
    def test_applies_defaults(self):
        args = cli.build_parser().parse_args(["example.com"])
        assert args.targets == ["example.com"]
        assert args.concurrency == 20
        assert args.rate == 0.0
        assert args.ports is None

    def test_accepts_several_targets(self):
        args = cli.build_parser().parse_args(["a.example.com", "b.example.com"])
        assert args.targets == ["a.example.com", "b.example.com"]

    def test_prints_the_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["--version"])
        assert exc.value.code == 0
        assert "webrecon 0." in capsys.readouterr().out
