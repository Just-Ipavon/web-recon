"""Scan orchestration: runs the enabled modules and assembles the report."""

from __future__ import annotations

from datetime import datetime, timezone

from .config import ScanConfig
from .models import ScanReport
from .modules import dns_enum, http_probe, port_scan, tls_info


async def run_scan(config: ScanConfig, on_stage=None) -> ScanReport:
    """Execute a scan.

    ``on_stage`` is an optional callable invoked with a short status string
    before each stage, so a CLI can show progress without this module knowing
    anything about the terminal.
    """
    report = ScanReport(target=config.target)

    def stage(message: str) -> None:
        if on_stage:
            on_stage(message)

    if config.enabled("dns"):
        stage("resolving DNS records")
        report.dns = await dns_enum.fetch_records(config.target, config.timeout)
        if report.dns.error:
            report.errors.append(f"dns: {report.dns.error}")

    hosts = [config.target]
    if config.enabled("subdomains"):
        stage("enumerating subdomains")
        report.subdomains = await dns_enum.enumerate_subdomains(config)
        hosts = [s.name for s in report.subdomains] or hosts

    if config.enabled("http"):
        stage(f"probing HTTP on {len(hosts)} host(s)")
        report.http = await http_probe.probe_hosts(hosts, config)

    if config.enabled("tls"):
        # Only inspect certificates for hosts that actually answered.
        live = [
            r.url.split("://", 1)[-1].split("/", 1)[0]
            for r in report.http
            if r.reachable and r.url.startswith("https://")
        ] or hosts[:1]
        stage(f"inspecting TLS on {len(live)} host(s)")
        report.tls = await tls_info.inspect_hosts(live, config.timeout, config.concurrency)

    if config.enabled("ports"):
        stage(f"scanning {len(config.ports)} ports")
        report.ports = await port_scan.scan(
            config.target, config.ports, config.timeout, config.concurrency
        )

    report.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return report
