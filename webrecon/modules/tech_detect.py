"""Signature-based technology fingerprinting from HTTP responses.

Deliberately conservative: a signature only fires on evidence the server
actually sent (headers, cookies, body markers), never on guesswork. Patterns
are anchored to markup or header structure so that prose mentioning a product
name does not count as evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    header: tuple[str, str] | None = None  # (header name, regex over its value)
    cookie: str | None = None  # cookie name, matched case-insensitively
    cookie_value: str | None = None  # optional regex the cookie value must match
    body: str | None = None  # regex over the response body


# itsdangerous-signed Flask session: payload.timestamp.signature, base64url,
# with a leading "." when the payload is compressed.
_FLASK_SESSION = r"^\.?[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"

SIGNATURES: tuple[Signature, ...] = (
    Signature("nginx", header=("server", r"\bnginx\b")),
    Signature("Apache Tomcat", header=("server", r"apache-coyote|\btomcat\b")),
    Signature("Apache", header=("server", r"^apache(?!-coyote)(?:/|\s|$)")),
    Signature("Microsoft IIS", header=("server", r"^microsoft-iis")),
    Signature("Caddy", header=("server", r"^caddy\b")),
    Signature("LiteSpeed", header=("server", r"^litespeed")),
    Signature("Cloudflare", header=("server", r"^cloudflare")),
    Signature("Cloudflare", header=("cf-ray", r".")),
    Signature("Amazon CloudFront", header=("x-amz-cf-id", r".")),
    Signature("Fastly", header=("x-served-by", r"\bcache-")),
    Signature("Varnish", header=("x-varnish", r".")),
    Signature("PHP", header=("x-powered-by", r"\bphp\b")),
    Signature("PHP", cookie="PHPSESSID"),
    Signature("ASP.NET", header=("x-powered-by", r"asp\.net")),
    Signature("ASP.NET", header=("x-aspnet-version", r".")),
    Signature("ASP.NET", cookie="ASP.NET_SessionId"),
    Signature("Express", header=("x-powered-by", r"^express\b")),
    Signature("Next.js", header=("x-powered-by", r"next\.js")),
    Signature("Next.js", body=r"""["'(]/_next/static/"""),
    Signature("Nuxt", body=r"window\.__NUXT__|<div id=[\"']__nuxt[\"']"),
    Signature("React", body=r"\bdata-reactroot\b|__REACT_DEVTOOLS"),
    Signature("Vue.js", body=r"\bdata-v-app\b|__VUE__"),
    Signature("Angular", body=r"\bng-version=[\"']"),
    Signature("WordPress", body=r"""["'(][^"'()]*/wp-(?:content|includes)/"""),
    Signature("WordPress", header=("link", r"/wp-json/")),
    Signature(
        "Joomla",
        body=r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla|"
        r"[\"'][^\"']*/media/(?:jui|system/js)/",
    ),
    Signature("Drupal", header=("x-generator", r"^drupal")),
    Signature("Drupal", header=("x-drupal-cache", r".")),
    Signature("Drupal", body=r"""["'][^"']*/sites/default/files/"""),
    Signature("Shopify", header=("x-shopid", r".")),
    Signature("Django", cookie="csrftoken"),
    Signature("Django", body=r"name=[\"']csrfmiddlewaretoken[\"']"),
    Signature("Laravel", cookie="laravel_session"),
    Signature("Flask", cookie="session", cookie_value=_FLASK_SESSION),
    Signature("Ruby on Rails", cookie="_rails_session"),
    Signature("jQuery", body=r"jquery[.-][\d.]+(?:\.min)?\.js"),
    Signature("Bootstrap", body=r"bootstrap[.-][\d.]+(?:\.min)?\.(?:js|css)"),
    Signature("Google Analytics", body=r"google-analytics\.com/|gtag\(\s*['\"]config['\"]"),
)


def parse_cookies(set_cookie_values: Iterable[str]) -> dict[str, str]:
    """Map cookie name (lowercased) to value, one Set-Cookie header per item.

    Only the part before the first ``;`` is the name/value pair; attributes
    such as ``Expires=Wed, 21 Oct 2026`` are never mistaken for cookies.
    """
    jar: dict[str, str] = {}
    for raw in set_cookie_values:
        pair = raw.split(";", 1)[0]
        name, sep, value = pair.partition("=")
        name = name.strip()
        if sep and name:
            jar[name.lower()] = value.strip().strip('"')
    return jar


def detect(
    headers: Mapping[str, str], body: str = "", cookies: Iterable[str] | None = None
) -> list[str]:
    """Return the technologies evidenced by these headers, cookies and body, sorted.

    ``cookies`` is the list of raw Set-Cookie header values (one per header,
    as ``httpx.Headers.get_list`` returns them). When omitted, a ``set-cookie``
    entry in ``headers`` is split on newlines.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    if cookies is None:
        cookies = [c for c in lowered.get("set-cookie", "").split("\n") if c.strip()]
    jar = parse_cookies(cookies)
    found: set[str] = set()

    for sig in SIGNATURES:
        if sig.name in found:
            continue
        if sig.header:
            key, pattern = sig.header
            value = lowered.get(key)
            if value and re.search(pattern, value, re.IGNORECASE):
                found.add(sig.name)
                continue
        if sig.cookie:
            value = jar.get(sig.cookie.lower())
            if value is not None and (
                sig.cookie_value is None or re.search(sig.cookie_value, value)
            ):
                found.add(sig.name)
                continue
        if sig.body and body and re.search(sig.body, body, re.IGNORECASE):
            found.add(sig.name)

    return sorted(found)
