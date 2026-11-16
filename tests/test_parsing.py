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


class FakeResponse:
    def __init__(self, body: str, content_type: str = "text/plain", status: int = 200):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.headers = {"content-type": content_type}


class TestSoftNotFoundGuard:
    @pytest.mark.parametrize(
        "path,body,content_type",
        [
            ("/sitemap.xml", "<html><body>Not found</body></html>", "text/html"),
            ("/robots.txt", '{"error":"not found"}', "application/json"),
            ("/robots.txt", "<!doctype html><body>404</body>", "text/plain"),
            ("/.well-known/security.txt", "Not Found", "text/plain"),
            ("/.env", "<html><script>API_URL='x'</script></html>", "text/html"),
            ("/.env", "API_URL='x'", "text/html"),
            ("/.git/HEAD", "not a ref", "text/plain"),
        ],
    )
    def test_rejects_false_positives(self, path, body, content_type):
        assert not http_probe._looks_like_hit(FakeResponse(body, content_type), path)

    @pytest.mark.parametrize(
        "path,body",
        [
            ("/.env", "db_password=x"),
            ("/.env", "DB1_HOST=x"),
            ("/.env", "export SECRET_KEY=x"),
            ("/.env", "# comment\nAPP_ENV = production"),
            ("/.git/HEAD", "0123456789abcdef0123456789abcdef01234567\n"),
            ("/.git/HEAD", "ref: refs/heads/main\n"),
            ("/robots.txt", "# hi\nUser-agent: *\nDisallow: /a"),
            ("/.well-known/security.txt", "Contact: mailto:sec@example.com"),
            ("/sitemap.xml", '<?xml version="1.0"?><sitemapindex xmlns="x"></sitemapindex>'),
        ],
    )
    def test_accepts_real_files(self, path, body):
        assert http_probe._looks_like_hit(FakeResponse(body), path)

    def test_rejects_a_body_identical_to_the_random_path_baseline(self):
        body = "User-agent: *\nDisallow: /"
        assert not http_probe._looks_like_hit(FakeResponse(body), "/robots.txt", baseline=body)


class TestTechDetectFalsePositives:
    @pytest.mark.parametrize(
        "headers,body,cookies,absent",
        [
            ({}, "", ["session=abc; Path=/"], "Flask"),
            ({}, "", ["prefs=a,session=b; Path=/"], "Flask"),
            ({"server": "Apache-Coyote/1.1"}, "", [], "Apache"),
            ({}, "<p>We migrated away from Joomla! last year</p>", [], "Joomla"),
            ({}, "<p>the csrfmiddlewaretoken field is documented here</p>", [], "Django"),
        ],
    )
    def test_does_not_fire_without_real_evidence(self, headers, body, cookies, absent):
        assert absent not in tech_detect.detect(headers, body, cookies)

    @pytest.mark.parametrize(
        "headers,body,cookies,present",
        [
            ({}, "", ["session=eyJhIjoxfQ.ZxYz12.abcDEF_-123; HttpOnly"], "Flask"),
            ({"server": "Apache-Coyote/1.1"}, "", [], "Apache Tomcat"),
            ({"server": "Apache/2.4.58 (Debian)"}, "", [], "Apache"),
            ({}, '<meta name="generator" content="Joomla! - Open Source">', [], "Joomla"),
            ({}, '<input type="hidden" name="csrfmiddlewaretoken" value="x">', [], "Django"),
        ],
    )
    def test_fires_on_real_evidence(self, headers, body, cookies, present):
        assert present in tech_detect.detect(headers, body, cookies)

    def test_expires_attribute_is_not_a_cookie_name(self):
        jar = tech_detect.parse_cookies(
            ["id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/", "PHPSESSID=x"]
        )
        assert set(jar) == {"id", "phpsessid"}

    def test_newline_joined_header_is_split_per_cookie(self):
        found = tech_detect.detect({"set-cookie": "a=1; Path=/\nlaravel_session=x; Path=/"})
        assert "Laravel" in found


class TestTitleEdgeCases:
    @pytest.mark.parametrize(
        "body,expected",
        [
            ("<title>A &amp; B</title>", "A & B"),
            ("<svg><title>icon</title></svg><title>Real</title>", "Real"),
            ("<!-- <title>old</title> --><title>Real</title>", "Real"),
            ("<script>var t='<title>js</title>'</script><title>Real</title>", "Real"),
            ("<TITLE\n>x</TITLE >", "x"),
            ("<head><title>T&#252;r</title></head>", "Tür"),
        ],
    )
    def test_extracts_the_document_title(self, body, expected):
        assert http_probe.extract_title(body) == expected


class TestHostileCrtsh:
    def test_drops_names_that_are_not_hostnames(self):
        payload = json.dumps(
            [
                {"name_value": "user@mail.example.com"},
                {"name_value": "?.example.com"},
                {"name_value": "foo bar.example.com"},
                {"name_value": "evil.test/x?.example.com"},
                {"name_value": "-x.example.com"},
                {"name_value": "ok.example.com"},
                {"name_value": 7},
                "not a dict",
            ]
        )
        assert dns_enum.parse_crtsh(payload, "example.com") == {"ok.example.com"}


class TestWordlistEdgeCases:
    def test_strips_inline_comments_bom_and_invalid_words(self, tmp_path):
        path = tmp_path / "w.txt"
        path.write_bytes(
            "\ufeff# header comment\nwww # inline\nfoo bar\n*.x\napi\ndev.api\n".encode()
        )
        assert dns_enum.load_wordlist(path) == ["www", "api", "dev.api"]


class TestRedaction:
    def test_redacts_cookie_values_but_keeps_attributes(self):
        import httpx

        headers = httpx.Headers(
            [
                ("Set-Cookie", "sid=secret; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly"),
                ("Set-Cookie", "theme=dark"),
                ("Authorization", "Bearer abc"),
                ("Server", "nginx"),
            ]
        )
        flat = http_probe.collect_headers(headers)
        assert "secret" not in flat["set-cookie"]
        assert flat["set-cookie"].split("\n") == [
            "sid=<redacted>; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly",
            "theme=<redacted>",
        ]
        assert flat["authorization"] == "<redacted>"
        assert flat["server"] == "nginx"

    def test_can_keep_values_when_asked(self):
        import httpx

        flat = http_probe.collect_headers(httpx.Headers([("Set-Cookie", "sid=v")]), redact=False)
        assert flat["set-cookie"] == "sid=v"


class TestSecurityHeaders:
    def test_reports_missing_protections_on_https(self):
        from webrecon.modules import security_headers

        findings = security_headers.analyse({}, ["sid=1; Path=/"], https=True)
        assert "missing Strict-Transport-Security" in findings
        assert "missing Content-Security-Policy" in findings
        assert any(f.startswith("cookie sid without Secure, HttpOnly, SameSite") for f in findings)

    def test_a_hardened_response_has_no_findings(self):
        from webrecon.modules import security_headers

        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        cookies = ["sid=1; Secure; HttpOnly; SameSite=Lax"]
        assert security_headers.analyse(headers, cookies, https=True) == []

    def test_hsts_is_not_expected_over_plain_http(self):
        from webrecon.modules import security_headers

        assert "missing Strict-Transport-Security" not in security_headers.analyse(
            {}, [], https=False
        )
