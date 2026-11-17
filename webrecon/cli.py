"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import ipaddress
import re
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rich.console import Console

from . import __version__
from .config import DEFAULT_PORTS, USER_AGENT, ScanConfig, bundled_wordlist
from .models import ScanReport
from .modules import report as report_module
from .scanner import ACTIVE_MODULES, run_scan
from .targets import Scope, Target, TargetError, parse_target

ALL_MODULES = ("dns", "subdomains", "http", "tls", "ports")

BANNER = "webrecon - passive/active reconnaissance for authorised targets only"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOTHING_REACHABLE = 3
EXIT_INTERRUPTED = 130

MAX_PORT = 65535

# Where -o and --html write when given no path: one file per target.
DEFAULT_REPORT_DIR = "reports/"
_DIGITS = re.compile(r"^[0-9]{1,5}$")
_NUMBER = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")


def _port_number(text: str, chunk: str) -> int:
    text = text.strip()
    if not _DIGITS.match(text):
        raise argparse.ArgumentTypeError(f"invalid port: {chunk}")
    port = int(text)
    if not 1 <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(f"ports must be between 1 and {MAX_PORT}: {chunk}")
    return port


def parse_ports(value: str) -> list[int]:
    """Parse a port specification such as ``80,443,8000-8100``.

    Only ASCII digits are accepted, and bounds are checked before a range is
    expanded, so ``1-30000000`` fails immediately instead of allocating.
    """
    ports: set[int] = set()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            lo, hi = _port_number(start, chunk), _port_number(end, chunk)
            if lo > hi:
                raise argparse.ArgumentTypeError(f"invalid port range: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(_port_number(chunk, chunk))
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    return sorted(ports)


def _number(value: str, *, minimum: float, inclusive: bool, integer: bool) -> Any:
    text = value.strip()
    if not _NUMBER.match(text) or (integer and "." in text):
        kind = "an integer" if integer else "a number"
        raise argparse.ArgumentTypeError(f"{value!r} is not {kind}")
    number: float = int(text) if integer else float(text)
    if number < minimum or (not inclusive and number == minimum):
        relation = ">=" if inclusive else ">"
        raise argparse.ArgumentTypeError(f"must be {relation} {minimum:g}, got {value}")
    return number


def positive_float(value: str) -> float:
    return float(_number(value, minimum=0, inclusive=False, integer=False))


def non_negative_float(value: str) -> float:
    return float(_number(value, minimum=0, inclusive=True, integer=False))


def positive_int(value: str) -> int:
    return int(_number(value, minimum=1, inclusive=True, integer=True))


def non_negative_int(value: str) -> int:
    return int(_number(value, minimum=0, inclusive=True, integer=True))


def normalise_target(value: str) -> str:
    """Reduce a domain, IP, ``host:port`` or URL to the bare host the modules use."""
    try:
        return parse_target(value).host
    except TargetError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def proxy_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise argparse.ArgumentTypeError("proxy must be an http:// or https:// URL")
    return value


def ip_literal(value: str) -> str:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an IP address: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description=BANNER,
        epilog=(
            "Only scan systems you own or have written permission to test. "
            "Exit codes: 0 success, 1 runtime error, 2 usage error or authorization not "
            "confirmed, 3 nothing reachable (with --fail-if-unreachable), 130 interrupted."
        ),
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="target",
        help="domain, IP, host:port or URL to scan (several allowed)",
    )
    parser.add_argument(
        "-iL", "--input-list", type=Path, metavar="FILE",
        help="read targets from FILE, one per line ('#' comments allowed)",
    )

    scan = parser.add_argument_group("scan")
    scan.add_argument(
        "-m",
        "--modules",
        default="dns,subdomains,http,tls",
        help=f"comma-separated modules to run ({', '.join(ALL_MODULES)}, or 'all')",
    )
    scan.add_argument(
        "-w", "--wordlist", type=Path,
        help="subdomain wordlist for brute-force (default: the bundled list)",
    )
    scan.add_argument(
        "--no-wordlist", action="store_true", help="skip subdomain brute-force entirely"
    )
    scan.add_argument(
        "-p", "--ports", type=parse_ports, default=None,
        help="ports to scan, e.g. 80,443,8000-8100 (default: a list of 15 common ports)",
    )
    scan.add_argument(
        "--max-subdomains", type=non_negative_int, default=200,
        help="cap on how many candidate subdomains are resolved, 0 for no cap (default 200)",
    )
    scan.add_argument(
        "--no-passive", action="store_true",
        help="skip certificate transparency lookups (the target name is otherwise sent to crt.sh)",
    )
    scan.add_argument(
        "--banners", action="store_true",
        help="read a short, sanitised banner from each open port",
    )
    scan.add_argument("--axfr", action="store_true", help="attempt a DNS zone transfer")
    scan.add_argument(
        "--resolver", action="append", type=ip_literal, default=[], metavar="IP",
        help="DNS server to query instead of the system resolver (repeatable)",
    )

    pacing = parser.add_argument_group("pacing and budgets")
    pacing.add_argument(
        "-c", "--concurrency", type=positive_int, default=20,
        help="max concurrent requests (default 20)",
    )
    pacing.add_argument(
        "-r", "--rate", type=non_negative_float, default=0.0,
        help="max requests per second across all modules, 0 disables pacing (default 0)",
    )
    pacing.add_argument(
        "-t", "--timeout", type=positive_float, default=5.0,
        help="per-request timeout in seconds (default 5)",
    )
    pacing.add_argument(
        "--max-time", type=positive_float, metavar="SECONDS",
        help="stop the scan of each target after this long and report what was found",
    )
    pacing.add_argument(
        "--max-requests-per-host", type=non_negative_int, default=0, metavar="N",
        help="HTTP request budget per host, 0 for unlimited (default 0)",
    )

    safety = parser.add_argument_group("scope and authorization")
    safety.add_argument(
        "--scope", action="append", default=[], metavar="ENTRIES",
        help="comma-separated domains and CIDRs that may be contacted (repeatable; "
        "default: the target and its subdomains)",
    )
    safety.add_argument(
        "--scope-file", type=Path, metavar="FILE", help="read scope entries from FILE"
    )
    safety.add_argument(
        "--allow-private", action="store_true",
        help="allow loopback, private and link-local addresses",
    )
    safety.add_argument(
        "--i-have-authorization", action="store_true",
        help="confirm you are authorised to test the targets (otherwise asked interactively)",
    )
    safety.add_argument(
        "--operator", help="name recorded in the report as the person running the scan"
    )

    http = parser.add_argument_group("HTTP")
    http.add_argument(
        "--verify-tls", action="store_true",
        help="verify certificates on HTTP probes (off by default so bad certificates "
        "do not hide a host; the TLS module always reports verification status)",
    )
    http.add_argument(
        "--proxy", type=proxy_url,
        help="HTTP(S) proxy for HTTP probes and crt.sh; DNS, TLS and ports still go direct. "
        "Environment proxy variables are ignored.",
    )
    http.add_argument("--user-agent", default=USER_AGENT, help="User-Agent for HTTP requests")
    http.add_argument(
        "--no-redact", action="store_true",
        help="keep Set-Cookie and Authorization values in reports (redacted by default)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-o", "--output", nargs="?", const=DEFAULT_REPORT_DIR, metavar="PATH",
        help="write a JSON report: to PATH, or one file per target inside PATH when it is a "
        "directory or ends with '/'; without PATH, to reports/<target>.json",
    )
    output.add_argument(
        "--html", nargs="?", const=DEFAULT_REPORT_DIR, metavar="PATH",
        help="write an HTML report, with the same rules as -o (reports/<target>.html)",
    )
    output.add_argument(
        "--jsonl", type=Path, help="append each result to this JSONL file as it is found"
    )
    output.add_argument(
        "--json", action="store_true", help="print the JSON report to stdout (for piping)"
    )
    output.add_argument("--force", action="store_true", help="overwrite existing report files")
    output.add_argument("-q", "--quiet", action="store_true", help="suppress terminal report")
    output.add_argument(
        "--fail-if-unreachable", action="store_true",
        help="exit with status 3 when no target answered",
    )
    return parser


def resolve_modules(value: str) -> set[str]:
    requested = {m.strip().lower() for m in value.split(",") if m.strip()}
    if "all" in requested:
        return set(ALL_MODULES)
    unknown = requested - set(ALL_MODULES)
    if unknown:
        raise SystemExit(
            f"unknown module(s): {', '.join(sorted(unknown))}. "
            f"Valid modules: {', '.join(ALL_MODULES)}"
        )
    if not requested:
        raise SystemExit("no modules selected")
    return requested


def _read_lines(path: Path) -> list[str]:
    text = path.read_bytes().decode("utf-8-sig", errors="replace")
    return [s for s in (line.split("#", 1)[0].strip() for line in text.splitlines()) if s]


def _check_output(parser: argparse.ArgumentParser, path: Path | None, force: bool) -> None:
    if path is None:
        return
    if path.is_dir():
        parser.error(f"{path} is a directory")
    if not path.parent.is_dir():
        parser.error(f"directory {path.parent} does not exist (for {path})")
    if path.exists() and not force:
        parser.error(f"{path} already exists; use --force to overwrite it")


def report_filename(target: Target, extension: str) -> str:
    """File name for one target's report: ``example.com.json``, ``192.0.2.1_8443.html``."""
    name = target.host.replace(":", "_")  # IPv6 literals
    if target.port:
        name += f"_{target.port}"
    return f"{name}.{extension}"


# Each entry: where to write, and the indexes of the targets whose reports go there.
OutputPlan = list[tuple[Path, list[int]]]


def plan_output(
    parser: argparse.ArgumentParser,
    value: str | None,
    targets: list[Target],
    extension: str,
    force: bool,
) -> OutputPlan:
    """Decide the report files for -o or --html, failing before any scan starts.

    A path that is an existing directory or ends with ``/`` (including the
    default ``reports/``) gets one file per target; any other path is a single
    file holding every target's report.
    """
    if value is None:
        return []
    path = Path(value)
    if value.endswith(("/", "\\")) or path.is_dir():
        if path.exists() and not path.is_dir():
            parser.error(f"{path} is not a directory")
        plan: OutputPlan = []
        for index, target in enumerate(targets):
            file = path / report_filename(target, extension)
            if file.exists() and not force:
                parser.error(f"{file} already exists; use --force to overwrite it")
            plan.append((file, [index]))
        return plan
    _check_output(parser, path, force)
    return [(path, list(range(len(targets))))]


def _confirm(
    console: Console, targets: list[Target], scope_entries: list[str], modules: set[str],
    passive: bool,
) -> bool:
    console.print("[bold]Active scan confirmation[/bold]")
    console.print(f"  targets: {', '.join(str(t) for t in targets)}")
    shown_scope = ", ".join(scope_entries) or "each target and its subdomains"
    console.print(f"  scope:   {shown_scope}")
    console.print(f"  modules: {', '.join(sorted(modules))}")
    if passive and "subdomains" in modules:
        console.print("  note:    target names are sent to crt.sh (disable with --no-passive)")
    answer = console.input("Type 'yes' if you are authorised to test these targets: ")
    return answer.strip().lower() == "yes"


def _operator(name: str | None) -> str:
    if name:
        return name
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _warn(console: Console, message: str) -> None:
    console.print(f"[yellow]warning:[/yellow] {message}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(stderr=True)

    # ---- targets
    raw_targets = list(args.targets)
    if args.input_list:
        if not args.input_list.is_file():
            parser.error(f"target list not found: {args.input_list}")
        raw_targets += _read_lines(args.input_list)
    if not raw_targets:
        parser.error("no target given")
    targets: list[Target] = []
    for raw in raw_targets:
        try:
            target = parse_target(raw)
        except TargetError as exc:
            parser.error(f"invalid target {raw!r}: {exc}")
        if target not in targets:
            targets.append(target)

    try:
        modules = resolve_modules(args.modules)
    except SystemExit as exc:
        parser.error(str(exc))

    # ---- scope
    scope_entries = [e for e in args.scope]
    if args.scope_file:
        if not args.scope_file.is_file():
            parser.error(f"scope file not found: {args.scope_file}")
        scope_entries += _read_lines(args.scope_file)
    try:
        for target in targets:
            Scope.build(target.host, scope_entries, args.allow_private)
    except TargetError as exc:
        parser.error(f"invalid scope entry: {exc}")

    # ---- wordlist
    wordlist: Any = None
    if args.wordlist is not None:
        if not args.wordlist.is_file():
            parser.error(f"wordlist not found or not a file: {args.wordlist}")
        wordlist = args.wordlist
    elif not args.no_wordlist:
        wordlist = bundled_wordlist()

    # ---- outputs
    json_plan = plan_output(parser, args.output, targets, "json", args.force)
    html_plan = plan_output(parser, args.html, targets, "html", args.force)
    _check_output(parser, args.jsonl, args.force)

    # ---- options that would silently do nothing
    if args.ports is not None and "ports" not in modules:
        _warn(console, "-p/--ports has no effect without the ports module (-m ports)")
    if (args.wordlist or args.no_wordlist) and "subdomains" not in modules:
        _warn(console, "wordlist options have no effect without the subdomains module")
    if args.banners and "ports" not in modules:
        _warn(console, "--banners has no effect without the ports module")
    if args.axfr and "dns" not in modules:
        _warn(console, "--axfr has no effect without the dns module")
    if args.quiet and not (args.output or args.html or args.jsonl or args.json):
        _warn(console, "-q without -o, --html, --jsonl or --json produces no report")

    # ---- authorization gate
    authorization: dict[str, Any] | None = None
    if modules & ACTIVE_MODULES:
        if args.i_have_authorization:
            method = "flag"
        elif sys.stdin.isatty():
            if not _confirm(console, targets, scope_entries, modules, not args.no_passive):
                console.print("[red]not confirmed; nothing was scanned[/red]")
                return EXIT_USAGE
            method = "interactive"
        else:
            parser.error(
                "active modules need confirmation: pass --i-have-authorization "
                "or run interactively"
            )
        authorization = {
            "operator": _operator(args.operator),
            "confirmed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "method": method,
            "scope": scope_entries or ["each target and its subdomains"],
        }

    # ---- scan
    show_progress = not args.quiet and not args.json

    def on_stage(message: str) -> None:
        if show_progress:
            console.print(f"[dim]->[/dim] {message}")

    jsonl = report_module.JsonlWriter(args.jsonl, args.force) if args.jsonl else None
    reports: list[ScanReport] = []
    exit_code = EXIT_OK
    try:
        for target in targets:
            report = ScanReport(target=target.host)
            report.authorization = authorization
            reports.append(report)
            if len(targets) > 1:
                on_stage(f"[bold]{target}[/bold]")
            config = ScanConfig(
                target=target.host,
                port=target.port,
                scheme=target.scheme,
                wordlist=wordlist,
                concurrency=args.concurrency,
                rate_per_second=args.rate,
                timeout=args.timeout,
                modules=modules,
                ports=args.ports or list(DEFAULT_PORTS),
                passive=not args.no_passive,
                max_subdomains=args.max_subdomains,
                user_agent=args.user_agent,
                verify_tls=args.verify_tls,
                proxy=args.proxy,
                scope=scope_entries,
                allow_private=args.allow_private,
                max_time=args.max_time,
                max_requests_per_host=args.max_requests_per_host,
                banners=args.banners,
                axfr=args.axfr,
                redact=not args.no_redact,
                nameservers=args.resolver,
            )
            emit = _jsonl_emitter(jsonl, target.host) if jsonl is not None else None
            asyncio.run(run_scan(config, on_stage, report=report, emit=emit))
    except KeyboardInterrupt:
        console.print("[yellow]interrupted; writing a partial report[/yellow]")
        _mark_unfinished(reports, "interrupted by the operator", jsonl)
        exit_code = EXIT_INTERRUPTED
    except Exception as exc:  # last resort: never lose what was gathered
        console.print(f"[red]scan crashed:[/red] {type(exc).__name__}: {exc}")
        _mark_unfinished(reports, f"scan crashed: {type(exc).__name__}: {exc}", jsonl)
        exit_code = EXIT_ERROR
    finally:
        if jsonl is not None:
            jsonl.close()

    # ---- output
    if not args.quiet and not args.json:
        report_module.render_terminal(reports, Console())
    if args.json:
        payload = reports[0] if len(reports) == 1 else reports
        sys.stdout.write(report_module.to_json(payload) + "\n")

    try:
        for kind, plan, write in (
            ("JSON", json_plan, report_module.write_json),
            ("HTML", html_plan, report_module.write_html),
        ):
            for path, indexes in plan:
                selected = [reports[i] for i in indexes if i < len(reports)]
                if not selected:
                    continue  # interrupted before this target was scanned
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                write(selected[0] if len(selected) == 1 else selected, path, args.force)
                console.print(f"[green]{kind} report written to[/green] {path}")
    except OSError as exc:
        console.print(f"[red]could not write report:[/red] {exc}")
        return EXIT_ERROR

    if exit_code == EXIT_OK and args.fail_if_unreachable:
        if not any(_reachable(r, modules) for r in reports):
            exit_code = EXIT_NOTHING_REACHABLE
    return exit_code


def _jsonl_emitter(
    writer: report_module.JsonlWriter, host: str
) -> Callable[[str, Any], None]:
    def emit(kind: str, payload: Any) -> None:
        writer.write(host, kind, payload)

    return emit


def _reachable(report: ScanReport, modules: set[str]) -> bool:
    if modules & ACTIVE_MODULES - {"subdomains"}:
        return report.anything_reachable()
    if "subdomains" in modules:
        return bool(report.subdomains)
    return bool(report.dns and report.dns.records)


def _mark_unfinished(
    reports: list[ScanReport], reason: str, jsonl: report_module.JsonlWriter | None
) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for report in reports:
        if report.complete:
            continue
        report.incomplete_reason = report.incomplete_reason or reason
        report.finished_at = report.finished_at or now
        if jsonl is not None:
            jsonl.write(
                report.target, "summary",
                {"complete": False, "incomplete_reason": report.incomplete_reason},
            )


if __name__ == "__main__":
    sys.exit(main())
