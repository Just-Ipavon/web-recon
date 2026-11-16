"""HTTP probing: reachability, redirect chain, title, headers, content discovery."""

from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from ..context import ScanContext
from ..models import HttpResult, Redirect
from ..ratelimit import Throttle
from ..targets import Scope, format_netloc
from . import security_headers, tech_detect

MAX_BODY_BYTES = 256_000
MAX_TITLE_SCAN = 64_000
MAX_REDIRECTS = 5

# Paths worth reporting when present. Nothing here is an exploit attempt; these
# are files servers publish or commonly leave world-readable by mistake.
COMMON_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
)

# Response headers whose values are credentials or session tokens.
SENSITIVE_HEADERS = ("set-cookie", "authorization", "proxy-authorization")
REDACTED = "<redacted>"

# Ports on which plain HTTP is the more likely protocol, so it is tried first.
PLAIN_HTTP_PORTS = frozenset({80, 3000, 5000, 8000, 8008, 8080, 8888})

_GIT_HEAD_RE = re.compile(r"^(?:ref: refs/\S+|[0-9a-f]{40}|[0-9a-f]{64})\s*$")
_ENV_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=", re.MULTILINE)
_ROBOTS_RE = re.compile(
    r"^[ \t]*(?:user-agent|disallow|allow|sitemap|crawl-delay)[ \t]*:", re.I | re.M
)
_SECURITY_TXT_RE = re.compile(r"^[ \t]*contact[ \t]*:", re.I | re.M)
_SITEMAP_RE = re.compile(r"<(?:[\w-]+:)?(?:urlset|sitemapindex)\b", re.I)
_HTML_RE = re.compile(r"<(?:!doctype\s+html|html|head|body)\b", re.I)

SkipCallback = Callable[[str, str], None]


class _TitleParser(HTMLParser):
    """Find the document title, ignoring <title> inside SVG, script and the like."""

    SKIP = frozenset({"svg", "math", "script", "style", "template", "noscript"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.in_title = False
        self.parts: list[str] = []
        self.title: str | None = None

    @property
    def done(self) -> bool:
        return self.title is not None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.done:
            return
        if tag in self.SKIP:
            self.skip_depth += 1
        elif tag == "title" and not self.skip_depth and not self.in_title:
            self.in_title = True
            self.parts = []

    def handle_endtag(self, tag: str) -> None:
        if self.done:
            return
        if tag in self.SKIP and self.skip_depth:
            self.skip_depth -= 1
        elif tag == "title" and self.in_title:
            self.in_title = False
            self.title = "".join(self.parts)

    def handle_data(self, data: str) -> None:
        if self.in_title and not self.done:
            self.parts.append(data)


def extract_title(body: str) -> str | None:
    """Pull the document <title> text out of an HTML page, entities decoded."""
    parser = _TitleParser()
    try:
        parser.feed(body[:MAX_TITLE_SCAN])
        parser.close()
    except (AssertionError, ValueError):
        pass
    raw = parser.title if parser.title is not None else ("".join(parser.parts) or None)
    if raw is None:
        return None
    title = re.sub(r"\s+", " ", raw).strip()
    return title[:200] or None


def parse_robots(body: str) -> list[str]:
    """Return the paths named by Disallow/Allow/Sitemap directives in robots.txt."""
    paths: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        directive, _, value = line.partition(":")
        if directive.strip().lower() not in {"disallow", "allow", "sitemap"}:
            continue
        value = value.strip()
        if value and value != "/" and value not in seen:
            seen.add(value)
            paths.append(value)
    return paths


def redact_cookie(raw: str) -> str:
    """Replace a Set-Cookie value, keeping its name and attributes."""
    pair, sep, attrs = raw.partition(";")
    name = pair.split("=", 1)[0].strip()
    return f"{name}={REDACTED}{sep}{attrs}"


def collect_headers(headers: httpx.Headers, redact: bool = True) -> dict[str, str]:
    """Flatten response headers to a dict; repeated Set-Cookie values are newline-joined.

    httpx joins repeated headers with ``", "``, which corrupts Set-Cookie
    (``Expires`` dates contain commas), so each header is read with
    ``get_list``. Credentials and session tokens are redacted unless
    ``redact`` is False.
    """
    out: dict[str, str] = {}
    for name in headers.keys():
        key = name.lower()
        values = headers.get_list(key)
        if redact and key == "set-cookie":
            values = [redact_cookie(v) for v in values]
        elif redact and key in SENSITIVE_HEADERS:
            values = [REDACTED for _ in values]
        out[key] = ("\n" if key == "set-cookie" else ", ").join(values)
    return out


def _looks_like_html(body: str, content_type: str) -> bool:
    return "html" in content_type or bool(_HTML_RE.search(body[:2000]))


def _looks_like_hit(response: httpx.Response, path: str, baseline: str | None = None) -> bool:
    """Guard against servers that answer 200 to everything with an error page.

    Each path must have the shape of the real file, and a body identical to
    the one served for a random non-existent path never counts.
    """
    if response.status_code != 200 or not response.content:
        return False
    headers = getattr(response, "headers", None) or {}
    content_type = str(headers.get("content-type", "")).lower()
    body = response.text[:4000]
    stripped = body.strip()
    if baseline is not None and stripped == baseline.strip():
        return False
    html_like = _looks_like_html(body, content_type)

    if path == "/.git/HEAD":
        return bool(_GIT_HEAD_RE.match(stripped))
    if path == "/.env":
        return (
            not html_like
            and not stripped.startswith(("<", "{", "["))
            and bool(_ENV_RE.search(body))
        )
    if path == "/robots.txt":
        return not html_like and bool(_ROBOTS_RE.search(body))
    if path.endswith("security.txt"):
        return not html_like and bool(_SECURITY_TXT_RE.search(body))
    if path.endswith(".xml"):
        return bool(_SITEMAP_RE.search(body))
    return not html_like


class RequestBudget:
    """Caps how many requests each host may receive; 0 means unlimited."""

    def __init__(self, per_host: int = 0) -> None:
        self.per_host = per_host
        self._used: dict[str, int] = {}

    def take(self, url: str) -> bool:
        if self.per_host <= 0:
            return True
        host = urlsplit(url).netloc.lower()
        used = self._used.get(host, 0)
        if used >= self.per_host:
            return False
        self._used[host] = used + 1
        return True


async def _get(
    client: httpx.AsyncClient, url: str, throttle: Throttle, budget: RequestBudget | None
) -> httpx.Response | None:
    if budget is not None and not budget.take(url):
        return None
    async with throttle:
        return await client.get(url)


async def probe_url(
    client: httpx.AsyncClient,
    url: str,
    throttle: Throttle,
    discover_paths: bool = True,
    scope: Scope | None = None,
    budget: RequestBudget | None = None,
    redact: bool = True,
    on_skip: SkipCallback | None = None,
) -> HttpResult:
    """Fetch a URL, following redirects manually so the chain is recorded.

    Redirects to hosts outside ``scope`` are recorded but not followed; loops
    and chains longer than MAX_REDIRECTS are reported as errors.
    """
    result = HttpResult(url=url, reachable=False)
    current = url
    seen = {url}

    try:
        for _ in range(MAX_REDIRECTS + 1):
            response = await _get(client, current, throttle, budget)
            if response is None:
                result.error = "per-host request budget exhausted"
                return result

            if not response.is_redirect:
                break
            location = response.headers.get("location", "")
            result.redirects.append(Redirect(status=response.status_code, location=location))
            if not location:
                break
            target = urljoin(current, location)
            parts = urlsplit(target)
            if parts.scheme not in ("http", "https"):
                break
            if scope is not None and parts.hostname:
                reason = scope.refusal(parts.hostname)
                if reason:
                    result.findings.append(
                        f"redirect to {parts.hostname} not followed ({reason})"
                    )
                    if on_skip:
                        on_skip(parts.hostname, f"{reason} (redirect target)")
                    break
            if target in seen:
                result.error = f"redirect loop at {target}"
                return result
            seen.add(target)
            current = target
        else:
            result.error = "too many redirects"
            return result

        body = response.text[:MAX_BODY_BYTES] if response.content else ""
        raw_cookies = response.headers.get_list("set-cookie")

        result.reachable = True
        result.status = response.status_code
        result.final_url = str(response.url)
        result.title = extract_title(body)
        result.server = response.headers.get("server")
        result.headers = collect_headers(response.headers, redact)
        result.technologies = tech_detect.detect(result.headers, body, raw_cookies)
        result.findings.extend(
            security_headers.analyse(
                result.headers, raw_cookies, https=result.final_url.startswith("https://")
            )
        )

        length = response.headers.get("content-length")
        result.content_length = (
            int(length) if length and length.isascii() and length.isdigit()
            else len(response.content)
        )

        if discover_paths:
            result.interesting_paths = await discover_content(client, current, throttle, budget)

    except httpx.HTTPError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"

    return result


async def discover_content(
    client: httpx.AsyncClient,
    base_url: str,
    throttle: Throttle,
    budget: RequestBudget | None = None,
) -> list[str]:
    """Check the well-known paths and expand robots.txt into its listed paths.

    A request for a random path first records what this server sends for
    something that does not exist; identical answers are soft 404s.
    """
    parsed = urlsplit(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    found: list[str] = []

    async def fetch(path: str) -> httpx.Response | None:
        try:
            return await _get(client, root + path, throttle, budget)
        except httpx.HTTPError:
            return None

    baseline_response = await fetch(f"/wr-{secrets.token_hex(8)}")
    baseline = (
        baseline_response.text[:4000]
        if baseline_response is not None and baseline_response.status_code == 200
        else None
    )

    responses = await asyncio.gather(*(fetch(p) for p in COMMON_PATHS))
    for path, response in zip(COMMON_PATHS, responses, strict=True):
        if response is None or not _looks_like_hit(response, path, baseline):
            continue
        found.append(path)
        if path == "/robots.txt":
            found.extend(f"robots: {p}" for p in parse_robots(response.text)[:20])

    return found


def _schemes_for(port: int | None, scheme: str | None) -> list[str]:
    if scheme:
        return [scheme]
    if port in PLAIN_HTTP_PORTS:
        return ["http", "https"]
    return ["https", "http"]


async def probe_hosts(
    endpoints: list[tuple[str, int | None, str | None]], ctx: ScanContext
) -> list[HttpResult]:
    """Probe each (host, port, scheme) endpoint, trying HTTPS and HTTP as needed.

    Without an explicit scheme, HTTPS is tried first except on ports where
    plain HTTP is the norm. The first reachable answer wins.
    """
    config = ctx.config
    budget = RequestBudget(config.max_requests_per_host)
    limits = httpx.Limits(max_connections=config.concurrency)

    async with httpx.AsyncClient(
        timeout=config.timeout,
        follow_redirects=False,
        verify=config.verify_tls,
        limits=limits,
        headers={"User-Agent": config.user_agent},
        proxy=config.proxy,
        trust_env=False,
    ) as client:

        async def probe_endpoint(endpoint: tuple[str, int | None, str | None]) -> HttpResult:
            host, port, scheme = endpoint
            netloc = format_netloc(host, port)
            first: HttpResult | None = None
            for candidate in _schemes_for(port, scheme):
                result = await probe_url(
                    client,
                    f"{candidate}://{netloc}",
                    ctx.throttle,
                    scope=ctx.scope,
                    budget=budget,
                    redact=config.redact,
                    on_skip=ctx.skip,
                )
                if result.reachable:
                    return result
                first = first or result
            assert first is not None
            return first

        async def guarded(endpoint: tuple[str, int | None, str | None]) -> HttpResult:
            try:
                result = await probe_endpoint(endpoint)
            except Exception as exc:  # one broken host must not end the scan
                host, port, _ = endpoint
                result = HttpResult(
                    url=format_netloc(host, port),
                    reachable=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            ctx.emit("http", result)
            return result

        results = await asyncio.gather(*(guarded(e) for e in endpoints))

    return list(results)
