"""End-to-end tests of ``cli.main`` against loopback servers (issues #7, #8, #13, #16)."""

from __future__ import annotations

import json
import os
import stat

import pytest
from conftest import free_port, response

from webrecon import cli
from webrecon.models import DnsRecords

LOCAL = ["--allow-private", "--i-have-authorization", "-t", "2", "--no-passive", "--no-wordlist"]


class TestEndToEnd:
    def test_scans_a_local_http_server_and_writes_reports(self, http_server, tmp_path, capsys):
        server = http_server({"/": response(200, "<title>local</title>")})
        out = tmp_path / "r.json"
        html = tmp_path / "r.html"
        jsonl = tmp_path / "r.jsonl"
        code = cli.main(
            [f"127.0.0.1:{server.port}", "-m", "http", *LOCAL, "-q",
             "-o", str(out), "--html", str(html), "--jsonl", str(jsonl)]
        )
        assert code == 0
        data = json.loads(out.read_text())
        assert data["http"][0]["title"] == "local"
        assert data["complete"] is True
        assert data["authorization"]["method"] == "flag"
        assert "local" in html.read_text()
        kinds = [json.loads(line)["type"] for line in jsonl.read_text().splitlines()]
        assert kinds[0] == "http" and kinds[-1] == "summary"
        for path in (out, html, jsonl):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_json_to_stdout(self, http_server, capsys):
        server = http_server({"/": response(200, "<title>piped</title>")})
        code = cli.main([f"http://127.0.0.1:{server.port}", "-m", "http", *LOCAL, "--json"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["http"][0]["title"] == "piped"

    def test_several_targets_produce_a_list(self, http_server, tmp_path, capsys):
        a = http_server({"/": response(200, "<title>a</title>")})
        b = http_server({"/": response(200, "<title>b</title>")})
        targets = tmp_path / "targets.txt"
        targets.write_text(f"# list\nhttp://127.0.0.1:{b.port}\n")
        code = cli.main(
            [f"http://127.0.0.1:{a.port}", "-iL", str(targets), "-m", "http", *LOCAL, "--json"]
        )
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert [r["http"][0]["title"] for r in payload] == ["a", "b"]

    def test_fail_if_unreachable_exits_3(self, capsys):
        code = cli.main(
            [f"http://127.0.0.1:{free_port()}", "-m", "http", *LOCAL, "-q", "--json",
             "--fail-if-unreachable"]
        )
        assert code == cli.EXIT_NOTHING_REACHABLE

    def test_private_target_needs_opt_in(self, capsys):
        code = cli.main(["127.0.0.1", "-m", "http", "--i-have-authorization", "--json"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["skipped"][0]["host"] == "127.0.0.1"
        assert payload["http"] == []


class TestUsageErrors:
    @pytest.mark.parametrize(
        "argv",
        [
            ["example.com", "-r", "-1"],
            ["example.com", "-t", "-1"],
            ["exa mple.com"],
            ["."],
            ["com"],
            [],
            ["example.com", "-w", "/nonexistent/list.txt"],
            ["example.com", "-m", "bogus"],
            ["example.com", "--scope", "not a domain"],
        ],
    )
    def test_exit_2_before_any_network_activity(self, argv, monkeypatch, capsys):
        async def must_not_run(*args, **kwargs):
            raise AssertionError("scan started")

        monkeypatch.setattr(cli, "run_scan", must_not_run)
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code == 2

    def test_a_directory_is_not_a_wordlist(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["example.com", "-w", str(tmp_path)])
        assert exc.value.code == 2

    def test_output_in_a_missing_directory_fails_before_scanning(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["example.com", "-m", "dns", "-o", str(tmp_path / "nope" / "x.json")])
        assert exc.value.code == 2

    def test_existing_output_needs_force(self, tmp_path, capsys):
        path = tmp_path / "x.json"
        path.write_text("{}")
        with pytest.raises(SystemExit) as exc:
            cli.main(["example.com", "-m", "dns", "-o", str(path)])
        assert exc.value.code == 2

    def test_active_scan_without_authorization_is_refused_non_interactively(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        with pytest.raises(SystemExit) as exc:
            cli.main(["example.com", "-m", "http"])
        assert exc.value.code == 2
        assert "--i-have-authorization" in capsys.readouterr().err

    def test_interactive_refusal_scans_nothing(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr(cli.Console, "input", lambda self, prompt="": "no")
        assert cli.main(["example.com", "-m", "http"]) == 2

    def test_warns_about_options_without_effect(self, monkeypatch, capsys):
        async def fake_scan(config, on_stage=None, report=None, emit=None):
            report.complete = True
            return report

        monkeypatch.setattr(cli, "run_scan", fake_scan)
        cli.main(["example.com", "-m", "dns", "-p", "80", "-q"])
        err = capsys.readouterr().err
        assert "-p/--ports has no effect" in err
        assert "-q without" in err


class TestPartialReports:
    def test_ctrl_c_writes_a_partial_report(self, monkeypatch, tmp_path, capsys):
        async def interrupted(config, on_stage=None, report=None, emit=None):
            report.dns = DnsRecords(domain=config.target, records={"A": ["192.0.2.1"]})
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "run_scan", interrupted)
        out = tmp_path / "partial.json"
        code = cli.main(["example.com", "-m", "dns", "-q", "-o", str(out)])
        assert code == cli.EXIT_INTERRUPTED
        data = json.loads(out.read_text())
        assert data["complete"] is False
        assert data["incomplete_reason"] == "interrupted by the operator"
        assert data["dns"]["records"]["A"] == ["192.0.2.1"]

    def test_a_crash_still_writes_what_was_gathered(self, monkeypatch, tmp_path, capsys):
        async def crashing(config, on_stage=None, report=None, emit=None):
            report.dns = DnsRecords(domain=config.target, records={"A": ["192.0.2.1"]})
            raise RuntimeError("boom")

        monkeypatch.setattr(cli, "run_scan", crashing)
        out = tmp_path / "crash.json"
        assert cli.main(["example.com", "-m", "dns", "-q", "-o", str(out)]) == cli.EXIT_ERROR
        data = json.loads(out.read_text())
        assert "boom" in data["incomplete_reason"]
        assert data["dns"]["records"]


class TestFailingHostMixedWithHealthyOne:
    def test_one_bad_target_does_not_hide_the_other(self, http_server, capsys):
        server = http_server({"/": response(200, "<title>ok</title>")})
        dead = free_port()
        code = cli.main(
            [f"http://127.0.0.1:{dead}", f"http://127.0.0.1:{server.port}",
             "-m", "http,tls", *LOCAL, "--json"]
        )
        assert code == 0
        first, second = json.loads(capsys.readouterr().out)
        assert first["http"][0]["reachable"] is False and first["http"][0]["error"]
        assert second["http"][0]["title"] == "ok"


class TestReportLocation:
    def test_bare_flags_write_one_file_per_target_under_reports(
        self, http_server, tmp_path, monkeypatch, capsys
    ):
        a = http_server({"/": response(200, "<title>a</title>")})
        b = http_server({"/": response(200, "<title>b</title>")})
        monkeypatch.chdir(tmp_path)
        code = cli.main(
            [f"http://127.0.0.1:{a.port}", f"http://127.0.0.1:{b.port}", "-m", "http",
             *LOCAL, "-q", "-o", "--html"]
        )
        assert code == 0
        reports = tmp_path / "reports"
        for server, title in ((a, "a"), (b, "b")):
            data = json.loads((reports / f"127.0.0.1_{server.port}.json").read_text())
            assert data["http"][0]["title"] == title
            assert (reports / f"127.0.0.1_{server.port}.html").exists()
        assert stat.S_IMODE(os.stat(reports).st_mode) == 0o700

    def test_a_trailing_slash_means_a_directory(self, http_server, tmp_path, capsys):
        server = http_server({"/": response(200, "<title>x</title>")})
        out = tmp_path / "out"
        code = cli.main(
            [f"http://127.0.0.1:{server.port}", "-m", "http", *LOCAL, "-q", "-o", f"{out}/"]
        )
        assert code == 0
        assert (out / f"127.0.0.1_{server.port}.json").exists()

    def test_an_existing_per_target_file_needs_force(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "example.com.json").write_text("{}")
        with pytest.raises(SystemExit) as exc:
            cli.main(["example.com", "-m", "dns", "-o"])
        assert exc.value.code == 2

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "example.com.json"),
            ("https://example.com:8443", "example.com_8443.json"),
            ("2001:db8::1", "2001_db8__1.json"),
        ],
    )
    def test_file_names(self, raw, expected):
        from webrecon.targets import parse_target

        assert cli.report_filename(parse_target(raw), "json") == expected
