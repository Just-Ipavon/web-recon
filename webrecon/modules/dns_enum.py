"""DNS record lookup, passive subdomain discovery and wordlist brute-force."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from ..config import ScanConfig
from ..models import DnsRecords, Subdomain
from ..ratelimit import Throttle

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

CRT_SH_URL = "https://crt.sh/"


def _make_resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


async def fetch_records(domain: str, timeout: float = 5.0) -> DnsRecords:
    """Query the common record types for a domain, tolerating partial failure."""
    resolver = _make_resolver(timeout)
    result = DnsRecords(domain=domain)

    async def one(rtype: str) -> tuple[str, list[str]]:
        try:
            answer = await resolver.resolve(domain, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return rtype, []
        except (dns.exception.Timeout, dns.exception.DNSException):
            return rtype, []
        return rtype, sorted(rdata.to_text() for rdata in answer)

    for rtype, values in await asyncio.gather(*(one(r) for r in RECORD_TYPES)):
        if values:
            result.records[rtype] = values

    if not result.records:
        result.error = "no DNS records resolved"
    return result


async def _resolve_host(
    resolver: dns.asyncresolver.Resolver, host: str, throttle: Throttle
) -> list[str]:
    """Return the A/AAAA addresses for a host, or an empty list if it does not resolve."""
    addresses: list[str] = []
    async with throttle:
        for rtype in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(host, rtype)
            except dns.exception.DNSException:
                continue
            addresses.extend(rdata.to_text() for rdata in answer)
    return sorted(set(addresses))


def load_wordlist(path: Path) -> list[str]:
    """Read a subdomain wordlist, skipping blanks and ``#`` comments."""
    words: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        word = raw.strip().lower().strip(".")
        if not word or word.startswith("#") or word in seen:
            continue
        seen.add(word)
        words.append(word)
    return words


def parse_crtsh(payload: str, domain: str) -> set[str]:
    """Extract unique subdomains from a crt.sh JSON response.

    Certificate name fields may hold several newline-separated names and
    wildcard entries, both of which are normalised here.
    """
    try:
        entries = json.loads(payload)
    except json.JSONDecodeError:
        return set()
    if not isinstance(entries, list):
        return set()

    found: set[str] = set()
    suffix = "." + domain.lower()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            value = entry.get(key)
            if not isinstance(value, str):
                continue
            for name in value.split("\n"):
                name = name.strip().lower().lstrip("*.").strip(".")
                if name and (name == domain.lower() or name.endswith(suffix)):
                    found.add(name)
    return found


async def passive_subdomains(domain: str, timeout: float = 15.0) -> set[str]:
    """Query certificate transparency logs via crt.sh. Failures are non-fatal."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"}
            )
            response.raise_for_status()
            return parse_crtsh(response.text, domain)
    except (httpx.HTTPError, ValueError):
        return set()


def select_candidates(
    candidates: dict[str, str], domain: str, limit: int
) -> list[str]:
    """Trim the candidate set to ``limit`` hosts without losing the good ones.

    Plain alphabetical truncation silently drops the apex domain and every
    passively discovered name that sorts late, which are the hosts most likely
    to exist. Order by confidence first: the target, then names seen in
    certificate transparency, then wordlist guesses.
    """
    priority = {"target": 0, "crt.sh": 1, "bruteforce": 2}
    ordered = sorted(
        candidates, key=lambda host: (priority.get(candidates[host], 3), host)
    )
    return ordered[:limit] if limit > 0 else ordered


async def enumerate_subdomains(config: ScanConfig) -> list[Subdomain]:
    """Discover subdomains passively and/or by brute-force, then resolve them."""
    domain = config.target
    resolver = _make_resolver(config.timeout)
    throttle = Throttle(config.concurrency, config.rate_per_second)

    candidates: dict[str, str] = {}

    if config.passive:
        for name in await passive_subdomains(domain):
            candidates.setdefault(name, "crt.sh")

    if config.wordlist and config.wordlist.exists():
        for word in load_wordlist(config.wordlist):
            candidates.setdefault(f"{word}.{domain}", "bruteforce")

    candidates.setdefault(domain, "target")

    ordered = select_candidates(candidates, domain, config.max_subdomains)

    async def check(host: str) -> Subdomain | None:
        addresses = await _resolve_host(resolver, host, throttle)
        if not addresses:
            return None
        return Subdomain(name=host, addresses=addresses, source=candidates[host])

    results = await asyncio.gather(*(check(h) for h in ordered))
    return sorted((r for r in results if r), key=lambda s: s.name)
