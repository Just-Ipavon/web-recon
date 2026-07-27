"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from .config import DEFAULT_PORTS, ScanConfig
from .modules import report as report_module
from .scanner import run_scan

ALL_MODULES = ("dns", "subdomains", "http", "tls", "ports")

BANNER = "webrecon - passive/active reconnaissance for authorised targets only"


def parse_ports(value: str) -> list[int]:
    """Parse a port specification such as ``80,443,8000-8100``."""
    ports: set[int] = set()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            try:
                lo, hi = int(start), int(end)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid port range: {chunk}") from exc
            if lo > hi:
                raise argparse.ArgumentTypeError(f"invalid port range: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                ports.add(int(chunk))
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid port: {chunk}") from exc
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return sorted(ports)


def normalise_target(value: str) -> str:
    """Strip scheme, path and port so modules always receive a bare hostname."""
    target = value.strip().lower()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0].split("@")[-1]
    if ":" in target and not target.startswith("["):
        target = target.split(":", 1)[0]
    if not target:
        raise argparse.ArgumentTypeError("empty target")
    return target.strip(".")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description=BANNER,
        epilog="Only scan systems you own or have written permission to test.",
    )
    parser.add_argument("target", type=normalise_target, help="domain to scan, e.g. example.com")
    parser.add_argument(
        "-m",
        "--modules",
        default="dns,subdomains,http,tls",
        help=f"comma-separated modules to run ({', '.join(ALL_MODULES)}, or 'all')",
    )
    parser.add_argument(
        "-w", "--wordlist", type=Path, help="subdomain wordlist for brute-force"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=20, help="max concurrent requests (default 20)"
    )
    parser.add_argument(
        "-r",
        "--rate",
        type=float,
        default=0.0,
        help="max requests per second, 0 disables pacing (default 0)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0, help="per-request timeout in seconds"
    )
    parser.add_argument(
        "-p", "--ports", type=parse_ports, default=list(DEFAULT_PORTS), help="ports to scan"
    )
    parser.add_argument(
        "--max-subdomains",
        type=int,
        default=200,
        help="cap on how many candidate subdomains are resolved (default 200)",
    )
    parser.add_argument(
        "--no-passive", action="store_true", help="skip certificate transparency lookups"
    )
    parser.add_argument("-o", "--output", type=Path, help="write JSON report to this path")
    parser.add_argument("--html", type=Path, help="write an HTML report to this path")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress terminal report")
    return parser


def resolve_modules(value: str) -> set[str]:
    if value.strip().lower() == "all":
        return set(ALL_MODULES)
    requested = {m.strip().lower() for m in value.split(",") if m.strip()}
    unknown = requested - set(ALL_MODULES)
    if unknown:
        raise SystemExit(
            f"unknown module(s): {', '.join(sorted(unknown))}. "
            f"Valid modules: {', '.join(ALL_MODULES)}"
        )
    if not requested:
        raise SystemExit("no modules selected")
    return requested


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(stderr=True)

    if args.concurrency < 1:
        raise SystemExit("concurrency must be at least 1")
    if args.wordlist and not args.wordlist.exists():
        raise SystemExit(f"wordlist not found: {args.wordlist}")

    config = ScanConfig(
        target=args.target,
        wordlist=args.wordlist,
        concurrency=args.concurrency,
        rate_per_second=args.rate,
        timeout=args.timeout,
        modules=resolve_modules(args.modules),
        ports=args.ports,
        passive=not args.no_passive,
        max_subdomains=args.max_subdomains,
    )

    def on_stage(message: str) -> None:
        if not args.quiet:
            console.print(f"[dim]->[/dim] {message}")

    try:
        report = asyncio.run(run_scan(config, on_stage))
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/yellow]")
        return 130

    if not args.quiet:
        report_module.render_terminal(report, Console())

    if args.output:
        report_module.write_json(report, args.output)
        console.print(f"[green]JSON report written to[/green] {args.output}")
    if args.html:
        report_module.write_html(report, args.html)
        console.print(f"[green]HTML report written to[/green] {args.html}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
