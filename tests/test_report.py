"""Tests for report serialisation and certificate parsing."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from webrecon.models import DnsRecords, HttpResult, ScanReport, SkippedHost, Subdomain, TlsInfo
from webrecon.modules import report as report_module
from webrecon.modules import tls_info


def sample_report() -> ScanReport:
    report = ScanReport(target="example.com")
    report.dns = DnsRecords(domain="example.com", records={"A": ["93.184.216.34"]})
    report.subdomains = [Subdomain(name="www.example.com", addresses=["93.184.216.34"])]
    report.http = [
        HttpResult(
            url="https://www.example.com",
            reachable=True,
            status=200,
            title="Example Domain",
            technologies=["nginx"],
            interesting_paths=["/robots.txt"],
        )
    ]
    report.finished_at = "2026-07-27T12:00:00+00:00"
    return report


class TestJson:
    def test_round_trips_through_json(self):
        payload = json.loads(report_module.to_json(sample_report()))
        assert payload["target"] == "example.com"
        assert payload["dns"]["records"]["A"] == ["93.184.216.34"]
        assert payload["http"][0]["technologies"] == ["nginx"]

    def test_writes_a_file(self, tmp_path):
        path = tmp_path / "out.json"
        report_module.write_json(sample_report(), path)
        assert json.loads(path.read_text())["target"] == "example.com"

    def test_serialises_an_empty_report(self):
        payload = json.loads(report_module.to_json(ScanReport(target="x.com")))
        assert payload["subdomains"] == []
        assert payload["dns"] is None


class TestHtml:
    def test_keeps_notes_apart_from_findings(self):
        report = sample_report()
        report.http[0].findings = ["missing Referrer-Policy"]
        report.http[0].notes = ["nginx default page; security headers not checked"]
        report.http[0].schemes = {"https": "200", "http": "301 -> https://www.example.com/"}
        html = report_module.to_html(report)
        findings = html.split("<h2>Findings</h2>")[1].split("<h2")[0]
        notes = html.split("<h2>Notes</h2>")[1].split("<h2")[0]
        assert "Referrer-Policy" in findings and "default page" not in findings
        assert "nginx default page" in notes
        assert "http: 301 -&gt; https://www.example.com/" in html

    def test_includes_the_scan_data(self):
        html = report_module.to_html(sample_report())
        assert "example.com" in html
        assert "Example Domain" in html
        assert "<table>" in html

    def test_escapes_html_in_page_titles(self):
        report = sample_report()
        report.http[0].title = "<script>alert(1)</script>"
        html = report_module.to_html(report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_omits_empty_sections(self):
        html = report_module.to_html(ScanReport(target="x.com"))
        assert "Open ports" not in html

    def test_writes_a_file(self, tmp_path):
        path = tmp_path / "out.html"
        report_module.write_html(sample_report(), path)
        assert path.read_text().startswith("<!doctype html>")


class TestTerminalRender:
    def test_renders_without_raising(self, capsys):
        report_module.render_terminal(sample_report())
        assert "example.com" in capsys.readouterr().out

    def test_renders_an_empty_report(self, capsys):
        report_module.render_terminal(ScanReport(target="x.com"))
        assert "x.com" in capsys.readouterr().out


class TestParseCertificate:
    def _cert(self, days_ahead: int) -> dict:
        expiry = datetime.now(timezone.utc) + timedelta(days=days_ahead)
        return {
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

    def test_extracts_issuer_subject_and_san(self):
        info = tls_info.parse_certificate(self._cert(30), "example.com", 443)
        assert "Let's Encrypt" in info.issuer
        assert "example.com" in info.subject
        assert info.san == ["example.com", "www.example.com"]

    def test_marks_a_future_certificate_valid(self):
        info = tls_info.parse_certificate(self._cert(30), "example.com", 443)
        assert info.valid is True
        assert 28 <= info.days_until_expiry <= 30

    def test_marks_an_expired_certificate_invalid(self):
        info = tls_info.parse_certificate(self._cert(-5), "example.com", 443)
        assert info.valid is False
        assert info.days_until_expiry < 0

    def test_tolerates_an_unparseable_date(self):
        cert = self._cert(10)
        cert["notAfter"] = "whenever"
        info = tls_info.parse_certificate(cert, "example.com", 443)
        assert info.not_after == "whenever"
        assert info.valid is False

    def test_handles_a_certificate_with_no_fields(self):
        info = tls_info.parse_certificate({}, "example.com", 443)
        assert info.issuer is None
        assert info.san == []

    def test_a_certificate_not_yet_valid_is_invalid(self):
        cert = self._cert(400)
        cert["notBefore"] = "Jan  1 00:00:00 2099 GMT"
        info = tls_info.parse_certificate(cert, "example.com", 443)
        assert info.valid is False
        assert any("not valid until" in f for f in info.findings)

    def test_keeps_ip_subject_alt_names(self):
        cert = self._cert(30)
        cert["subjectAltName"] = (("DNS", "example.com"), ("IP Address", "192.0.2.1"))
        info = tls_info.parse_certificate(cert, "example.com", 443)
        assert info.san == ["192.0.2.1", "example.com"]


def failed_report() -> ScanReport:
    report = ScanReport(target="down.example.com")
    report.http = [
        HttpResult(url="https://down.example.com", reachable=False, error="ConnectError: refused")
    ]
    report.tls = [TlsInfo(host="down.example.com", port=443, valid=False, error="timed out")]
    report.errors = ["dns: domain does not exist (NXDOMAIN)"]
    report.skipped = [SkippedHost(host="intranet.example.com", reason="out of scope")]
    report.notes = ["wildcard DNS detected"]
    report.complete = False
    report.incomplete_reason = "interrupted by the operator"
    return report


class TestErrorsAreVisible:
    def test_html_lists_errors_unreachable_hosts_and_skips(self):
        html = report_module.to_html(failed_report())
        assert "NXDOMAIN" in html
        assert "Unreachable" in html and "ConnectError: refused" in html
        assert "intranet.example.com" in html
        assert "wildcard DNS detected" in html
        assert "Incomplete report" in html

    def test_terminal_lists_errors_and_unreachable_hosts(self, capsys):
        report_module.render_terminal(failed_report())
        out = capsys.readouterr().out
        assert "Unreachable" in out
        assert "ConnectError: refused" in out
        assert "NXDOMAIN" in out
        assert "INCOMPLETE" in out

    def test_html_has_a_restrictive_content_security_policy(self):
        html = report_module.to_html(sample_report())
        assert "Content-Security-Policy" in html
        assert "default-src 'none'" in html

    def test_terminal_does_not_interpret_markup_from_the_network(self, capsys):
        report = sample_report()
        report.http[0].title = "[red]spoofed[/red]"
        report_module.render_terminal(report)
        assert "[red]spoofed[/red]" in capsys.readouterr().out

    def test_several_reports_render_together(self):
        html = report_module.to_html([sample_report(), failed_report()])
        assert "example.com" in html and "down.example.com" in html
        payload = json.loads(report_module.to_json([sample_report(), failed_report()]))
        assert [p["target"] for p in payload] == ["example.com", "down.example.com"]


class TestReportFiles:
    def test_files_are_private(self, tmp_path):
        path = tmp_path / "out.json"
        report_module.write_json(sample_report(), path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_refuses_to_overwrite_without_force(self, tmp_path):
        path = tmp_path / "out.html"
        path.write_text("keep me")
        with pytest.raises(FileExistsError):
            report_module.write_html(sample_report(), path)
        assert path.read_text() == "keep me"
        report_module.write_html(sample_report(), path, force=True)
        assert path.read_text().startswith("<!doctype html>")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_jsonl_writes_one_flushed_line_per_result(self, tmp_path):
        path = tmp_path / "out.jsonl"
        writer = report_module.JsonlWriter(path)
        writer.write("example.com", "subdomain", Subdomain(name="www.example.com"))
        lines = path.read_text().splitlines()  # readable before close
        writer.close()
        assert json.loads(lines[0])["data"]["name"] == "www.example.com"
