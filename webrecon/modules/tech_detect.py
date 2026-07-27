"""Signature-based technology fingerprinting from HTTP responses.

Deliberately conservative: a signature only fires on evidence the server
actually sent (headers, cookies, body markers), never on guesswork.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    header: tuple[str, str] | None = None  # (header name, regex over its value)
    cookie: str | None = None  # cookie name, matched case-insensitively
    body: str | None = None  # regex over the response body


SIGNATURES: tuple[Signature, ...] = (
    Signature("nginx", header=("server", r"nginx")),
    Signature("Apache", header=("server", r"apache")),
    Signature("Microsoft IIS", header=("server", r"microsoft-iis")),
    Signature("Caddy", header=("server", r"caddy")),
    Signature("LiteSpeed", header=("server", r"litespeed")),
    Signature("Cloudflare", header=("server", r"cloudflare")),
    Signature("Cloudflare", header=("cf-ray", r".")),
    Signature("Amazon CloudFront", header=("x-amz-cf-id", r".")),
    Signature("Fastly", header=("x-served-by", r"cache-")),
    Signature("Varnish", header=("x-varnish", r".")),
    Signature("PHP", header=("x-powered-by", r"php")),
    Signature("PHP", cookie="PHPSESSID"),
    Signature("ASP.NET", header=("x-powered-by", r"asp\.net")),
    Signature("ASP.NET", cookie="ASP.NET_SessionId"),
    Signature("Express", header=("x-powered-by", r"express")),
    Signature("Next.js", header=("x-powered-by", r"next\.js")),
    Signature("Next.js", body=r"/_next/static/"),
    Signature("Nuxt", body=r"__NUXT__"),
    Signature("React", body=r"data-reactroot|__REACT_DEVTOOLS"),
    Signature("Vue.js", body=r"data-v-app|__VUE__"),
    Signature("Angular", body=r"ng-version="),
    Signature("WordPress", body=r"/wp-content/|/wp-includes/"),
    Signature("WordPress", header=("link", r"/wp-json/")),
    Signature("Joomla", body=r"/media/jui/|Joomla!"),
    Signature("Drupal", header=("x-generator", r"drupal")),
    Signature("Drupal", body=r"/sites/default/files/"),
    Signature("Shopify", header=("x-shopid", r".")),
    Signature("Django", cookie="csrftoken"),
    Signature("Django", body=r"csrfmiddlewaretoken"),
    Signature("Laravel", cookie="laravel_session"),
    Signature("Flask", cookie="session"),
    Signature("Ruby on Rails", cookie="_rails_session"),
    Signature("jQuery", body=r"jquery[.-][\d.]+(?:\.min)?\.js"),
    Signature("Bootstrap", body=r"bootstrap[.-][\d.]+(?:\.min)?\.(?:js|css)"),
    Signature("Google Analytics", body=r"google-analytics\.com|gtag\('config'"),
)


def _cookie_names(headers: dict[str, str]) -> set[str]:
    """Pull cookie names out of Set-Cookie headers, lowercased."""
    raw = headers.get("set-cookie", "")
    names: set[str] = set()
    for chunk in raw.split("\n"):
        for part in chunk.split(","):
            name, _, rest = part.partition("=")
            if rest:
                names.add(name.strip().lower())
    return names


def detect(headers: dict[str, str], body: str = "") -> list[str]:
    """Return the technologies evidenced by these headers and body, sorted."""
    lowered = {k.lower(): v for k, v in headers.items()}
    cookies = _cookie_names(lowered)
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
        if sig.cookie and sig.cookie.lower() in cookies:
            found.add(sig.name)
            continue
        if sig.body and body and re.search(sig.body, body, re.IGNORECASE):
            found.add(sig.name)

    return sorted(found)
