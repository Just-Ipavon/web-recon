"""Tests for report serialisation and certificate parsing."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from webrecon.models import DnsRecords, HttpResult, ScanReport, Subdomain
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
