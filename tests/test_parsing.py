"""Tests for the pure parsing logic. Nothing here touches the network."""

from __future__ import annotations

import json

import pytest

from webrecon.modules import dns_enum, http_probe, tech_detect


class TestExtractTitle:
    def test_reads_title_text(self):
        assert http_probe.extract_title("<html><title>Hello</title></html>") == "Hello"

    def test_collapses_whitespace_and_newlines(self):
        assert http_probe.extract_title("<title>\n  Big\n  Site\n</title>") == "Big Site"

    def test_handles_attributes_on_the_tag(self):
        assert http_probe.extract_title('<title dir="ltr">X</title>') == "X"

    def test_returns_none_without_a_title(self):
        assert http_probe.extract_title("<html><body>no title</body></html>") is None

    def test_returns_none_for_an_empty_title(self):
        assert http_probe.extract_title("<title>   </title>") is None

    def test_truncates_absurdly_long_titles(self):
        assert len(http_probe.extract_title(f"<title>{'a' * 500}</title>")) == 200


class TestParseRobots:
    def test_collects_disallow_and_sitemap_entries(self):
        body = """
        User-agent: *
        Disallow: /admin
        Disallow: /private/
        Allow: /public
        Sitemap: https://example.com/sitemap.xml
        """
        paths = http_probe.parse_robots(body)
        assert "/admin" in paths
        assert "/private/" in paths
        assert "/public" in paths
        assert "https://example.com/sitemap.xml" in paths

    def test_ignores_comments_blanks_and_bare_root(self):
        assert http_probe.parse_robots("# c\n\nDisallow: /\nUser-agent: *") == []

    def test_deduplicates(self):
        assert http_probe.parse_robots("Disallow: /a\nDisallow: /a") == ["/a"]


class TestParseCrtsh:
    def test_extracts_and_normalises_names(self):
        payload = json.dumps(
            [
                {"name_value": "www.example.com\n*.api.example.com"},
                {"common_name": "MAIL.EXAMPLE.COM"},
            ]
        )
        assert dns_enum.parse_crtsh(payload, "example.com") == {
            "www.example.com",
            "api.example.com",
            "mail.example.com",
        }

    def test_drops_names_outside_the_target_domain(self):
        payload = json.dumps([{"name_value": "www.evil.com"}])
        assert dns_enum.parse_crtsh(payload, "example.com") == set()

    def test_returns_empty_set_on_malformed_json(self):
        assert dns_enum.parse_crtsh("not json", "example.com") == set()

    def test_returns_empty_set_when_payload_is_not_a_list(self):
        assert dns_enum.parse_crtsh('{"a": 1}', "example.com") == set()


class TestLoadWordlist:
    def test_skips_comments_blanks_and_duplicates(self, tmp_path):
        path = tmp_path / "w.txt"
        path.write_text("# comment\nwww\n\nWWW\napi\napi\n")
        assert dns_enum.load_wordlist(path) == ["www", "api"]


class TestTechDetect:
    def test_matches_a_server_header(self):
        assert "nginx" in tech_detect.detect({"Server": "nginx/1.24.0"})

    def test_matches_a_powered_by_header(self):
        assert "PHP" in tech_detect.detect({"X-Powered-By": "PHP/8.2.1"})

    def test_matches_a_cookie_name(self):
        found = tech_detect.detect({"set-cookie": "laravel_session=abc; Path=/"})
        assert "Laravel" in found

    def test_matches_a_body_marker(self):
        assert "WordPress" in tech_detect.detect({}, "<link href='/wp-content/x.css'>")

    def test_returns_empty_list_without_evidence(self):
        assert tech_detect.detect({"Date": "today"}, "<html></html>") == []

    def test_reports_each_technology_once(self):
        found = tech_detect.detect(
            {"x-powered-by": "PHP/8.2", "set-cookie": "PHPSESSID=x"}, ""
        )
        assert found.count("PHP") == 1

    def test_is_case_insensitive_on_header_names(self):
        assert "nginx" in tech_detect.detect({"SERVER": "NGINX"})

    def test_finds_several_technologies_together(self):
        found = tech_detect.detect(
            {"server": "nginx", "cf-ray": "abc"}, "<div data-reactroot>"
        )
        assert {"nginx", "Cloudflare", "React"} <= set(found)


class TestLooksLikeHit:
    @pytest.mark.parametrize(
        "path,body,expected",
        [
            ("/.git/HEAD", "ref: refs/heads/main", True),
            ("/.git/HEAD", "<html>404</html>", False),
            ("/.env", "APP_KEY=base64:x", True),
            ("/.env", "<html>not found</html>", False),
            ("/robots.txt", "User-agent: *", True),
            ("/robots.txt", "<html>soft 404</html>", False),
            ("/sitemap.xml", "<urlset>", True),
        ],
    )
    def test_distinguishes_real_content_from_soft_404s(self, path, body, expected):
        class FakeResponse:
            status_code = 200
            content = b"x"
            text = body

        assert http_probe._looks_like_hit(FakeResponse(), path) is expected

    def test_rejects_non_200_responses(self):
        class FakeResponse:
            status_code = 404
            content = b"ref: refs/heads/main"
            text = "ref: refs/heads/main"

        assert http_probe._looks_like_hit(FakeResponse(), "/.git/HEAD") is False


class TestSelectCandidates:
    def test_keeps_the_apex_target_even_under_a_tight_cap(self):
        candidates = {f"host{i}.example.com": "bruteforce" for i in range(50)}
        candidates["example.com"] = "target"
        selected = dns_enum.select_candidates(candidates, "example.com", 5)
        assert selected[0] == "example.com"
        assert len(selected) == 5

    def test_prefers_passive_findings_over_wordlist_guesses(self):
        candidates = {
            "aaa.example.com": "bruteforce",
            "zzz.example.com": "crt.sh",
            "example.com": "target",
        }
        assert dns_enum.select_candidates(candidates, "example.com", 2) == [
            "example.com",
            "zzz.example.com",
        ]

    def test_returns_everything_when_the_cap_is_not_positive(self):
        candidates = {"a.example.com": "bruteforce", "b.example.com": "bruteforce"}
        assert len(dns_enum.select_candidates(candidates, "example.com", 0)) == 2
