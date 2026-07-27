"""HTTP probing: reachability, redirect chain, title, headers, content discovery."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from ..config import ScanConfig
from ..models import HttpResult, Redirect
from ..ratelimit import Throttle
from . import tech_detect

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

MAX_BODY_BYTES = 256_000
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


def extract_title(body: str) -> str | None:
    """Pull the <title> text out of an HTML document."""
    match = TITLE_RE.search(body)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] or None


def parse_robots(body: str) -> list[str]:
    """Return the paths named by Disallow/Allow/Sitemap directives in robots.txt."""
    paths: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        directive, _, value = line.partition(":")
        if directive.strip().lower() not in {"disallow", "allow", "sitemap"}:
            continue
        value = value.strip()
        if value and value != "/" and value not in seen:
            seen.add(value)
            paths.append(value)
    return paths


def _looks_like_hit(response: httpx.Response, path: str) -> bool:
    """Guard against servers that answer 200 to everything with an HTML error page."""
    if response.status_code != 200 or not response.content:
        return False
    body = response.text[:2000]
    if path == "/.git/HEAD":
        return body.lstrip().startswith("ref:")
    if path == "/.env":
        return bool(re.search(r"^[A-Z_]{3,}=", body, re.MULTILINE))
    if path.endswith(".xml"):
        return "<" in body
    return "<html" not in body.lower()


async def probe_url(
    client: httpx.AsyncClient,
    url: str,
    throttle: Throttle,
    discover_paths: bool = True,
) -> HttpResult:
    """Fetch a URL, following redirects manually so the chain is recorded."""
    result = HttpResult(url=url, reachable=False)
    current = url

    try:
        for _ in range(MAX_REDIRECTS + 1):
            async with throttle:
                response = await client.get(current)

            if response.is_redirect:
                location = response.headers.get("location", "")
                result.redirects.append(
                    Redirect(status=response.status_code, location=location)
                )
                if not location:
                    break
                current = urljoin(current, location)
                continue
            break
        else:
            result.error = "too many redirects"
            return result

        body = response.text[:MAX_BODY_BYTES] if response.content else ""
        headers = dict(response.headers)

        result.reachable = True
        result.status = response.status_code
        result.final_url = str(response.url)
        result.title = extract_title(body)
        result.server = response.headers.get("server")
        result.headers = headers
        result.technologies = tech_detect.detect(headers, body)

        length = response.headers.get("content-length")
        result.content_length = (
            int(length) if length and length.isdigit() else len(response.content)
        )

        if discover_paths:
            result.interesting_paths = await discover_content(client, current, throttle)

    except httpx.HTTPError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    except (UnicodeDecodeError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"

    return result


async def discover_content(
    client: httpx.AsyncClient, base_url: str, throttle: Throttle
) -> list[str]:
    """Check the well-known paths and expand robots.txt into its listed paths."""
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    found: list[str] = []

    async def check(path: str) -> tuple[str, httpx.Response | None]:
        try:
            async with throttle:
                return path, await client.get(root + path)
        except httpx.HTTPError:
            return path, None

    for path, response in await asyncio.gather(*(check(p) for p in COMMON_PATHS)):
        if response is None or not _looks_like_hit(response, path):
            continue
        found.append(path)
        if path == "/robots.txt":
            found.extend(f"robots: {p}" for p in parse_robots(response.text)[:20])

    return found


async def probe_hosts(hosts: list[str], config: ScanConfig) -> list[HttpResult]:
    """Probe every host over HTTPS, falling back to HTTP when TLS fails."""
    throttle = Throttle(config.concurrency, config.rate_per_second)
    limits = httpx.Limits(max_connections=config.concurrency)

    async with httpx.AsyncClient(
        timeout=config.timeout,
        follow_redirects=False,
        verify=config.verify_tls,
        limits=limits,
        headers={"User-Agent": config.user_agent},
    ) as client:

        async def probe_host(host: str) -> HttpResult:
            https = await probe_url(client, f"https://{host}", throttle)
            if https.reachable:
                return https
            http = await probe_url(client, f"http://{host}", throttle)
            return http if http.reachable else https

        results = await asyncio.gather(*(probe_host(h) for h in hosts))

    return list(results)
