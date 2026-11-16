"""DNS record lookup, passive subdomain discovery and wordlist brute-force."""

from __future__ import annotations

import asyncio
import json
import secrets
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

from ..config import USER_AGENT
from ..context import ScanContext
from ..models import DnsRecords, Subdomain
from ..ratelimit import Throttle
from ..targets import is_valid_hostname

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:
        from importlib.abc import Traversable


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")

# Common DKIM selectors; DKIM keys cannot be enumerated, only guessed.
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim")

CRT_SH_URL = "https://crt.sh/"

# crt.sh is slow; its lookup gets at least this long whatever -t says.
CRT_SH_MIN_TIMEOUT = 15.0

WILDCARD_PROBES = 3


def make_resolver(
    timeout: float, nameservers: list[str] | None = None, port: int = 53
) -> dns.asyncresolver.Resolver:
    """Build a resolver; raises dns.resolver.NoResolverConfiguration when none exists."""
    if nameservers:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers)
        resolver.port = port
    else:
        resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def query_status(exc: BaseException) -> str:
    """Name the outcome of a failed query so NXDOMAIN, timeouts and SERVFAIL differ."""
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "NOANSWER"
    if isinstance(exc, dns.exception.Timeout):
        return "TIMEOUT"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "SERVFAIL"
    return "ERROR"


async def _query(
    resolver: dns.asyncresolver.Resolver, name: str, rtype: str, throttle: Throttle
) -> tuple[str, list[str]]:
    """One throttled query. Returns ``(status, sorted values)``; never raises DNS errors."""
    async with throttle:
        try:
            answer = await resolver.resolve(name, rtype)
        except dns.exception.DNSException as exc:
            return query_status(exc), []
    return "OK", sorted(rdata.to_text() for rdata in answer)


def summarise_failure(status: dict[str, str]) -> str:
    values = set(status.values())
    if values == {"NXDOMAIN"}:
        return "domain does not exist (NXDOMAIN)"
    if "TIMEOUT" in values and "OK" not in values and "NOANSWER" not in values:
        return "DNS queries timed out"
    if "SERVFAIL" in values and "OK" not in values and "NOANSWER" not in values:
        return "DNS server failure (SERVFAIL or REFUSED)"
    return "no DNS records resolved"


async def fetch_records(
    domain: str,
    timeout: float = 5.0,
    throttle: Throttle | None = None,
    nameservers: list[str] | None = None,
    port: int = 53,
    axfr: bool = False,
) -> DnsRecords:
    """Query the common record types for a domain, tolerating partial failure.

    Also looks up DMARC and common DKIM selectors when the domain handles mail,
    flags missing SPF/DMARC, and optionally attempts a zone transfer.
    """
    result = DnsRecords(domain=domain)
    throttle = throttle or Throttle(len(RECORD_TYPES))
    try:
        resolver = make_resolver(timeout, nameservers, port)
    except dns.exception.DNSException as exc:
        result.error = f"no usable DNS resolver: {exc}"
        return result

    answers = await asyncio.gather(
        *(_query(resolver, domain, rtype, throttle) for rtype in RECORD_TYPES)
    )
    for rtype, (status, values) in zip(RECORD_TYPES, answers, strict=True):
        result.status[rtype] = status
        if values:
            result.records[rtype] = values

    if not result.records:
        result.error = summarise_failure(result.status)
        return result

    if "MX" in result.records:
        await _mail_hints(result, resolver, throttle)

    if axfr and result.records.get("NS"):
        await _attempt_axfr(result, resolver, timeout, throttle)

    return result


async def _mail_hints(
    result: DnsRecords, resolver: dns.asyncresolver.Resolver, throttle: Throttle
) -> None:
    domain = result.domain
    spf = [t for t in result.records.get("TXT", []) if "v=spf1" in t.lower()]
    if not spf:
        result.findings.append("domain receives mail but publishes no SPF record")
    elif any("+all" in t.lower() for t in spf):
        result.findings.append("SPF record ends in +all (any sender is authorised)")

    status, values = await _query(resolver, f"_dmarc.{domain}", "TXT", throttle)
    result.status["DMARC"] = status
    dmarc = [v for v in values if "v=dmarc1" in v.lower()]
    if dmarc:
        result.records["DMARC"] = dmarc
        if any("p=none" in v.lower().replace(" ", "") for v in dmarc):
            result.findings.append("DMARC policy is p=none (monitoring only)")
    else:
        result.findings.append("domain receives mail but publishes no DMARC record")

    answers = await asyncio.gather(
        *(_query(resolver, f"{s}._domainkey.{domain}", "TXT", throttle) for s in DKIM_SELECTORS)
    )
    dkim = [
        f"{selector}: {value}"
        for selector, (_, values) in zip(DKIM_SELECTORS, answers, strict=True)
        for value in values
    ]
    if dkim:
        result.records["DKIM"] = dkim


def _axfr_count(address: str, domain: str, timeout: float) -> int:
    zone = dns.zone.from_xfr(dns.query.xfr(address, domain, timeout=timeout, lifetime=timeout))
    return sum(1 for _ in zone.iterate_rdatas())


async def _attempt_axfr(
    result: DnsRecords,
    resolver: dns.asyncresolver.Resolver,
    timeout: float,
    throttle: Throttle,
) -> None:
    """Try a zone transfer against each authoritative server; a success is a finding."""
    outcomes: list[str] = []
    for ns in result.records.get("NS", []):
        ns = ns.rstrip(".")
        _, addresses = await _query(resolver, ns, "A", throttle)
        if not addresses:
            continue
        try:
            async with throttle:
                count = await asyncio.wait_for(
                    asyncio.to_thread(_axfr_count, addresses[0], result.domain, timeout),
                    timeout * 2,
                )
        except (dns.exception.DNSException, OSError, EOFError, asyncio.TimeoutError):
            outcomes.append("REFUSED")
            continue
        outcomes.append("ALLOWED")
        result.findings.append(f"zone transfer (AXFR) allowed by {ns}: {count} records")
    if outcomes:
        result.status["AXFR"] = "ALLOWED" if "ALLOWED" in outcomes else "REFUSED"


async def _resolve_host(
    resolver: dns.asyncresolver.Resolver, host: str, throttle: Throttle
) -> tuple[list[str], bool]:
    """Return the A/AAAA addresses for a host and whether a lookup failed abnormally.

    Each query takes its own throttle slot. "Abnormal" means a timeout or
    server failure rather than a clean NXDOMAIN/no-answer.
    """
    addresses: list[str] = []
    failed = False
    for rtype in ("A", "AAAA"):
        status, values = await _query(resolver, host, rtype, throttle)
        addresses.extend(values)
        if status in ("TIMEOUT", "SERVFAIL", "ERROR"):
            failed = True
        if status == "NXDOMAIN":
            break
    return sorted(set(addresses)), failed


def load_wordlist(path: Path | Traversable) -> list[str]:
    """Read a subdomain wordlist, skipping blanks, comments and invalid labels.

    ``#`` starts a comment anywhere on a line; a UTF-8 byte order mark is
    ignored; entries that are not valid hostname labels (``foo bar``, ``*.x``)
    are dropped.
    """
    text = path.read_bytes().decode("utf-8-sig", errors="ignore")
    words: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        word = raw.split("#", 1)[0].strip().lower().strip(".")
        if not word or word in seen or not is_valid_hostname(word):
            continue
        seen.add(word)
        words.append(word)
    return words


def parse_crtsh(payload: str, domain: str) -> set[str]:
    """Extract unique subdomains from a crt.sh JSON response.

    Certificate name fields may hold several newline-separated names and
    wildcard entries, both of which are normalised here. Anything that is not
    a valid hostname (e-mail addresses, ``?`` placeholders, spaces, slashes)
    is discarded.
    """
    try:
        entries = json.loads(payload)
    except json.JSONDecodeError:
        return set()
    if not isinstance(entries, list):
        return set()

    found: set[str] = set()
    domain = domain.lower()
    suffix = "." + domain
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            value = entry.get(key)
            if not isinstance(value, str):
                continue
            for name in value.split("\n"):
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                name = name.rstrip(".")
                if not is_valid_hostname(name):
                    continue
                if name == domain or name.endswith(suffix):
                    found.add(name)
    return found


async def passive_subdomains(
    domain: str,
    timeout: float = CRT_SH_MIN_TIMEOUT,
    user_agent: str = USER_AGENT,
    throttle: Throttle | None = None,
    proxy: str | None = None,
) -> set[str]:
    """Query certificate transparency logs via crt.sh.

    Raises ``httpx.HTTPError`` (or ``ValueError`` for a non-JSON body) so the
    caller can record the failure instead of mistaking it for "no names".
    """
    throttle = throttle or Throttle(1)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": user_agent},
        proxy=proxy,
        trust_env=False,
    ) as client:
        async with throttle:
            response = await client.get(
                CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"}
            )
        response.raise_for_status()
        if response.text.strip() and not response.text.lstrip().startswith("["):
            raise ValueError("crt.sh returned a non-JSON response")
        return parse_crtsh(response.text, domain)


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


async def detect_wildcard(
    resolver: dns.asyncresolver.Resolver, domain: str, throttle: Throttle
) -> set[str]:
    """Resolve a few random labels; any answer means the zone has a wildcard."""
    labels = [f"wr-{secrets.token_hex(8)}.{domain}" for _ in range(WILDCARD_PROBES)]
    answers = await asyncio.gather(*(_resolve_host(resolver, h, throttle) for h in labels))
    return {address for addresses, _ in answers for address in addresses}


async def enumerate_subdomains(ctx: ScanContext) -> list[Subdomain]:
    """Discover subdomains passively and/or by brute-force, then resolve them."""
    config = ctx.config
    domain = config.target
    resolver = make_resolver(config.timeout, config.nameservers, config.dns_port)

    candidates: dict[str, str] = {}

    if config.passive:
        try:
            names = await passive_subdomains(
                domain,
                max(config.timeout, CRT_SH_MIN_TIMEOUT),
                config.user_agent,
                ctx.throttle,
                config.proxy,
            )
        except (httpx.HTTPError, ValueError) as exc:
            ctx.error(f"subdomains: crt.sh lookup failed: {type(exc).__name__}: {exc}")
            names = set()
        for name in names:
            candidates.setdefault(name, "crt.sh")

    if config.wordlist is not None:
        for word in load_wordlist(config.wordlist):
            candidates.setdefault(f"{word}.{domain}", "bruteforce")

    # The apex always ranks as the target, even when crt.sh listed it too.
    candidates[domain] = "target"

    for name in list(candidates):
        if not ctx.scope.allows_name(name):
            ctx.skip(name, "out of scope")
            del candidates[name]

    wildcard = await detect_wildcard(resolver, domain, ctx.throttle)
    ordered = select_candidates(candidates, domain, config.max_subdomains)

    discarded = 0
    failures = 0

    async def check(host: str) -> Subdomain | None:
        nonlocal discarded, failures
        addresses, failed = await _resolve_host(resolver, host, ctx.throttle)
        if failed and not addresses:
            failures += 1
        if not addresses:
            return None
        source = candidates[host]
        if wildcard and source == "bruteforce" and set(addresses) <= wildcard:
            discarded += 1
            return None
        sub = Subdomain(name=host, addresses=addresses, source=source)
        ctx.emit("subdomain", sub)
        return sub

    results = await asyncio.gather(*(check(h) for h in ordered), return_exceptions=True)
    found: list[Subdomain] = []
    for host, outcome in zip(ordered, results, strict=True):
        if isinstance(outcome, BaseException):
            ctx.error(f"subdomains: {host}: {type(outcome).__name__}: {outcome}")
        elif outcome is not None:
            found.append(outcome)

    if wildcard:
        ctx.note(
            f"wildcard DNS detected for *.{domain} ({', '.join(sorted(wildcard))}); "
            f"{discarded} wordlist candidate(s) resolving only to those addresses discarded"
        )
    if failures:
        ctx.note(
            f"{failures} subdomain candidate(s) could not be resolved because of DNS "
            "timeouts or server failures"
        )
    return sorted(found, key=lambda s: s.name)
