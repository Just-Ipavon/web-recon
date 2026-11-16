"""Scan orchestration: runs the enabled modules and assembles the report.

One :class:`~webrecon.context.ScanContext` carries a single shared throttle and
scope for every stage. Each stage is isolated: an exception is recorded in
``report.errors`` and the scan moves on, so results gathered earlier are never
lost. ``config.max_time`` bounds the whole scan; when it is reached the report
is returned marked as incomplete.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import urlsplit

from .config import WEB_PORTS, ScanConfig
from .context import Emit, ScanContext
from .models import ScanReport
from .modules import dns_enum, http_probe, port_scan, tls_info
from .targets import is_ip

T = TypeVar("T")

ACTIVE_MODULES = frozenset({"subdomains", "http", "tls", "ports"})
TLS_PORTS = frozenset({443, 8443, 9443})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def redact_proxy(proxy: str | None) -> str | None:
    """Drop credentials from a proxy URL before it is written to a report."""
    if not proxy:
        return None
    parts = urlsplit(proxy)
    if parts.username or parts.password:
        host = parts.hostname or ""
        netloc = f"{host}:{parts.port}" if parts.port else host
        return parts._replace(netloc=f"<redacted>@{netloc}").geturl()
    return proxy


def describe_settings(config: ScanConfig) -> dict[str, Any]:
    wordlist = config.wordlist
    return {
        "modules": sorted(config.modules),
        "port": config.port,
        "concurrency": config.concurrency,
        "rate_per_second": config.rate_per_second,
        "timeout": config.timeout,
        "max_time": config.max_time,
        "max_requests_per_host": config.max_requests_per_host,
        "verify_tls": config.verify_tls,
        "proxy": redact_proxy(config.proxy),
        "proxy_applies_to": "HTTP probes and crt.sh only; DNS, TLS and port scans connect directly"
        if config.proxy
        else None,
        "user_agent": config.user_agent,
        "passive_lookups": "crt.sh" if config.passive and config.enabled("subdomains") else None,
        "wordlist": getattr(wordlist, "name", None) if wordlist is not None else None,
        "allow_private": config.allow_private,
        "redact_secrets": config.redact,
    }


async def run_scan(
    config: ScanConfig,
    on_stage: Callable[[str], None] | None = None,
    report: ScanReport | None = None,
    emit: Emit | None = None,
) -> ScanReport:
    """Execute a scan, filling ``report`` (created if omitted) in place.

    ``on_stage`` is an optional callable invoked with a short status string
    before each stage, so a CLI can show progress without this module knowing
    anything about the terminal. ``emit(kind, payload)`` receives each result
    as soon as it exists.
    """
    ctx = ScanContext.create(config, report, emit)
    report = ctx.report
    report.complete = False
    report.scope = ctx.scope.describe()
    report.settings = describe_settings(config)

    def stage(message: str) -> None:
        if on_stage:
            on_stage(message)

    try:
        if config.max_time:
            await asyncio.wait_for(_run_stages(ctx, stage), config.max_time)
        else:
            await _run_stages(ctx, stage)
        report.complete = True
    except asyncio.TimeoutError:
        report.incomplete_reason = f"maximum scan time of {config.max_time:g}s reached"
        ctx.error(f"scan stopped: {report.incomplete_reason}")
    finally:
        report.finished_at = _now()
    ctx.emit(
        "summary",
        {
            "complete": report.complete,
            "incomplete_reason": report.incomplete_reason,
            "errors": len(report.errors),
        },
    )
    return report


async def _guarded(ctx: ScanContext, name: str, work: Awaitable[T]) -> T | None:
    """Run one stage; an exception becomes an error entry instead of a traceback."""
    try:
        return await work
    except Exception as exc:
        ctx.error(f"{name}: {type(exc).__name__}: {exc}")
        return None


async def _target_refusal(ctx: ScanContext) -> str | None:
    """Why the target itself must not be actively probed, or None."""
    target = ctx.config.target
    reason = ctx.scope.refusal(target)
    if reason or is_ip(target) or ctx.scope.allow_private:
        return reason
    loop = asyncio.get_running_loop()
    try:
        async with ctx.throttle:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(target, None, type=socket.SOCK_STREAM), ctx.config.timeout
            )
    except (OSError, UnicodeError, asyncio.TimeoutError):
        return None  # unresolvable: the modules report it themselves
    addresses = {str(info[4][0]) for info in infos}
    if addresses and all(ctx.scope.address_refusal(a) for a in addresses):
        return f"resolves only to non-public addresses ({', '.join(sorted(addresses))}); " \
            "use --allow-private"
    return None


async def _run_stages(ctx: ScanContext, stage: Callable[[str], None]) -> None:
    config = ctx.config
    report = ctx.report
    target = config.target

    if config.enabled("dns"):
        stage("resolving DNS records")
        dns_result = await _guarded(
            ctx,
            "dns",
            dns_enum.fetch_records(
                target,
                config.timeout,
                ctx.throttle,
                config.nameservers or None,
                config.dns_port,
                config.axfr,
            ),
        )
        if dns_result is not None:
            report.dns = dns_result
            ctx.emit("dns", dns_result)
            if dns_result.error:
                ctx.error(f"dns: {dns_result.error}")

    if not config.modules & ACTIVE_MODULES:
        return

    refusal = await _target_refusal(ctx)
    if refusal:
        ctx.skip(target, refusal)
        ctx.error(f"{target}: active modules skipped ({refusal})")
        return

    hosts = [target]
    if config.enabled("subdomains"):
        if is_ip(target):
            ctx.note("subdomain enumeration skipped: the target is an IP address")
        else:
            stage("enumerating subdomains")
            subs = await _guarded(ctx, "subdomains", dns_enum.enumerate_subdomains(ctx))
            report.subdomains = subs or []
            names = []
            for sub in report.subdomains:
                refused = [a for a in sub.addresses if ctx.scope.address_refusal(a)]
                if sub.addresses and len(refused) == len(sub.addresses):
                    ctx.skip(sub.name, "resolves only to non-public addresses")
                    continue
                names.append(sub.name)
            hosts = names or hosts

    open_web_ports: list[int] = []
    if config.enabled("ports"):
        stage(f"scanning {len(config.ports)} ports")
        open_ports = await _guarded(
            ctx,
            "ports",
            port_scan.scan(
                target,
                config.ports,
                config.timeout,
                ctx.throttle,
                config.banners,
                on_result=lambda r: ctx.emit("port", r),
            ),
        )
        report.ports = open_ports or []
        open_web_ports = [p.port for p in report.ports if p.port in WEB_PORTS]

    if config.enabled("http"):
        endpoints = _http_endpoints(config, hosts, open_web_ports)
        stage(f"probing HTTP on {len(endpoints)} endpoint(s)")
        report.http = (
            await _guarded(ctx, "http", http_probe.probe_hosts(endpoints, ctx)) or []
        )

    if config.enabled("tls"):
        endpoints_tls = _tls_endpoints(config, report, open_web_ports)
        stage(f"inspecting TLS on {len(endpoints_tls)} endpoint(s)")
        report.tls = (
            await _guarded(ctx, "tls", tls_info.inspect_hosts(endpoints_tls, ctx)) or []
        )


def _http_endpoints(
    config: ScanConfig, hosts: list[str], open_web_ports: list[int]
) -> list[tuple[str, int | None, str | None]]:
    endpoints: list[tuple[str, int | None, str | None]] = []
    for host in hosts:
        if host == config.target and (config.port or config.scheme):
            endpoints.append((host, config.port, config.scheme))
        else:
            endpoints.append((host, None, None))
    # Open web ports found by the port scan get their own probe; 80 and 443
    # are already covered by the default HTTPS-then-HTTP probe.
    covered = {config.port} if config.port else {80, 443}
    for port in open_web_ports:
        if port not in covered:
            endpoints.append((config.target, port, None))
    return list(dict.fromkeys(endpoints))


def _tls_endpoints(
    config: ScanConfig, report: ScanReport, open_web_ports: list[int]
) -> list[tuple[str, int]]:
    endpoints: list[tuple[str, int]] = []
    for result in report.http:
        if not result.reachable:
            continue
        for url in (result.url, result.final_url):
            parts = urlsplit(url or "")
            if parts.scheme == "https" and parts.hostname:
                endpoints.append((parts.hostname, parts.port or 443))
                break
    if not endpoints:
        endpoints.append((config.target, config.port or 443))
    for port in open_web_ports:
        if port in TLS_PORTS:
            endpoints.append((config.target, port))
    return list(dict.fromkeys(endpoints))
