"""Rendering of scan reports to JSON, JSONL, terminal output and standalone HTML.

Reports can contain response headers, banners and other data chosen by the
scanned servers. Report files are therefore created readable by the owner only
(mode 0600) and an existing file is never overwritten unless asked to.
"""

from __future__ import annotations

import html
import json
import os
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import IO, Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..models import ScanReport

Reports = ScanReport | Sequence[ScanReport]

HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'"


def _as_list(reports: Reports) -> list[ScanReport]:
    return [reports] if isinstance(reports, ScanReport) else list(reports)


def to_json(reports: Reports, indent: int = 2) -> str:
    """One report serialises to an object, several to an array of objects."""
    if isinstance(reports, ScanReport):
        payload: Any = reports.to_dict()
    else:
        payload = [r.to_dict() for r in reports]
    return json.dumps(payload, indent=indent, sort_keys=False)


def open_private(path: Path, force: bool = False) -> IO[str]:
    """Open ``path`` for writing with mode 0600, refusing to overwrite unless ``force``."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if not force:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)  # an overwritten file keeps its old mode otherwise
    return os.fdopen(fd, "w", encoding="utf-8")


def _write(path: Path, text: str, force: bool) -> None:
    with open_private(path, force) as fh:
        fh.write(text)


def write_json(reports: Reports, path: Path, force: bool = False) -> None:
    _write(path, to_json(reports) + "\n", force)


def write_html(reports: Reports, path: Path, force: bool = False) -> None:
    _write(path, to_html(reports), force)


class JsonlWriter:
    """Appends one JSON object per result as the scan produces it.

    Every line is flushed immediately, so an interrupted or crashed scan still
    leaves a usable file behind.
    """

    def __init__(self, path: Path, force: bool = False) -> None:
        self.path = path
        self._fh = open_private(path, force)

    def write(self, target: str, kind: str, payload: Any) -> None:
        data = asdict(payload) if is_dataclass(payload) and not isinstance(payload, type) \
            else payload
        self._fh.write(json.dumps({"target": target, "type": kind, "data": data}) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


# --------------------------------------------------------------------------- terminal


def _status_line(report: ScanReport) -> str:
    if report.complete:
        return "[green]complete[/green]"
    reason = escape(report.incomplete_reason or "scan did not finish")
    return f"[bold yellow]INCOMPLETE[/bold yellow] ({reason})"


def render_terminal(reports: Reports, console: Console | None = None) -> None:
    """Print a human-readable summary of each scan.

    Every value that came from the network is escaped, so a page title or a
    banner cannot inject rich markup into the terminal.
    """
    console = console or Console()
    for report in _as_list(reports):
        _render_one(report, console)


def _render_one(report: ScanReport, console: Console) -> None:
    e = escape
    lines = [
        f"[bold]{e(report.target)}[/bold]",
        f"started  {e(report.started_at)}",
        f"finished {e(report.finished_at or '-')}",
        f"status   {_status_line(report)}",
    ]
    if report.scope:
        lines.append(f"scope    {e('; '.join(report.scope))}")
    if report.authorization:
        auth = report.authorization
        lines.append(
            f"authorised by {e(str(auth.get('operator') or '-'))} at "
            f"{e(str(auth.get('confirmed_at') or '-'))}"
        )
    console.print(Panel("\n".join(lines), title="webrecon", border_style="cyan"))

    if report.dns:
        if report.dns.records:
            table = Table(title="DNS records", header_style="bold cyan")
            table.add_column("type")
            table.add_column("value", overflow="fold")
            for rtype, values in report.dns.records.items():
                table.add_row(e(rtype), e("\n".join(values)))
            console.print(table)
        failed = {k: v for k, v in report.dns.status.items() if v not in ("OK", "NOANSWER")}
        if failed:
            console.print(
                "[dim]DNS query status:[/dim] "
                + e(", ".join(f"{k}={v}" for k, v in failed.items()))
            )

    if report.subdomains:
        table = Table(title=f"Subdomains ({len(report.subdomains)})", header_style="bold cyan")
        table.add_column("host")
        table.add_column("addresses", overflow="fold")
        table.add_column("source")
        for sub in report.subdomains:
            table.add_row(e(sub.name), e(", ".join(sub.addresses)), e(sub.source))
        console.print(table)

    live = [h for h in report.http if h.reachable]
    dead = [h for h in report.http if not h.reachable]
    if live:
        table = Table(title=f"HTTP ({len(live)} reachable)", header_style="bold cyan")
        table.add_column("url", overflow="fold")
        table.add_column("status", justify="right")
        table.add_column("title", overflow="fold")
        table.add_column("technologies", overflow="fold")
        for result in live:
            colour = "green" if result.status and result.status < 400 else "yellow"
            table.add_row(
                e(result.final_url or result.url),
                f"[{colour}]{result.status}[/{colour}]",
                e(result.title or "-"),
                e(", ".join(result.technologies) or "-"),
            )
        console.print(table)

    if dead:
        table = Table(title=f"Unreachable ({len(dead)})", header_style="bold cyan")
        table.add_column("url", overflow="fold")
        table.add_column("error", overflow="fold")
        for result in dead:
            table.add_row(e(result.url), f"[red]{e(result.error or 'no response')}[/red]")
        console.print(table)

    paths = [(r.url, p) for r in live for p in r.interesting_paths]
    if paths:
        table = Table(title="Interesting paths", header_style="bold cyan")
        table.add_column("host", overflow="fold")
        table.add_column("path", overflow="fold")
        for url, path in paths:
            table.add_row(e(url), e(path))
        console.print(table)

    findings = _findings(report)
    if findings:
        table = Table(title=f"Findings ({len(findings)})", header_style="bold cyan")
        table.add_column("where", overflow="fold")
        table.add_column("finding", overflow="fold")
        for where, finding in findings:
            table.add_row(e(where), e(finding))
        console.print(table)

    if report.tls:
        table = Table(title="TLS certificates", header_style="bold cyan")
        table.add_column("endpoint")
        table.add_column("issuer", overflow="fold")
        table.add_column("expires")
        table.add_column("days", justify="right")
        table.add_column("trusted")
        for cert in report.tls:
            endpoint = e(f"{cert.host}:{cert.port}")
            if cert.error:
                table.add_row(endpoint, f"[red]{e(cert.error)}[/red]", "-", "-", "-")
                continue
            days = cert.days_until_expiry
            colour = "red" if days is not None and days < 15 else "green"
            trusted = {True: "[green]yes[/green]", False: "[red]no[/red]"}.get(
                cert.trusted, "-"  # type: ignore[arg-type]
            )
            table.add_row(
                endpoint,
                e(cert.issuer or "-"),
                e(cert.not_after or "-"),
                f"[{colour}]{days if days is not None else '-'}[/{colour}]",
                trusted,
            )
        console.print(table)

    if report.ports:
        table = Table(title="Open ports", header_style="bold cyan")
        table.add_column("port", justify="right")
        table.add_column("service")
        table.add_column("banner", overflow="fold")
        for port in report.ports:
            table.add_row(str(port.port), e(port.service or "-"), e(port.banner or "-"))
        console.print(table)

    if report.skipped:
        table = Table(title=f"Skipped ({len(report.skipped)})", header_style="bold cyan")
        table.add_column("host", overflow="fold")
        table.add_column("reason", overflow="fold")
        for skipped in report.skipped:
            table.add_row(e(skipped.host), e(skipped.reason))
        console.print(table)

    for note in report.notes:
        console.print(f"[cyan]note[/cyan] {e(note)}")
    for error in report.errors:
        console.print(f"[red]error[/red] {e(error)}")


def _findings(report: ScanReport) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if report.dns:
        out += [(report.dns.domain, f) for f in report.dns.findings]
    for result in report.http:
        out += [(result.final_url or result.url, f) for f in result.findings]
    for cert in report.tls:
        out += [(f"{cert.host}:{cert.port}", f) for f in cert.findings]
    return out


# ------------------------------------------------------------------------------- html


def _esc(value: object) -> str:
    return html.escape(str(value if value not in (None, "") else "-"))


def _section(title: str, headers: list[str], rows: list[list[Any]], css: str = "") -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in row) + "</tr>" for row in rows
    )
    cls = f" class='{css}'" if css else ""
    return (
        f"<h2{cls}>{_esc(title)}</h2><div class='wrap'><table>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _html_report(report: ScanReport) -> str:
    dns_records = report.dns.records if report.dns else {}
    status = (
        "<p class='ok'>Scan complete.</p>"
        if report.complete
        else f"<p class='warn'><strong>Incomplete report:</strong> "
        f"{_esc(report.incomplete_reason or 'the scan did not finish')}</p>"
    )
    meta = [f"{_esc(report.started_at)} &rarr; {_esc(report.finished_at)}"]
    if report.scope:
        meta.append(f"Scope: {_esc('; '.join(report.scope))}")
    if report.authorization:
        auth = report.authorization
        meta.append(
            f"Authorised by {_esc(auth.get('operator'))} at {_esc(auth.get('confirmed_at'))} "
            f"({_esc(auth.get('method'))})"
        )
    settings = report.settings
    if settings.get("proxy"):
        meta.append(f"Proxy: {_esc(settings['proxy'])} ({_esc(settings.get('proxy_applies_to'))})")
    if settings:
        meta.append(f"TLS verification: {'on' if settings.get('verify_tls') else 'off'}")

    parts = [
        f"<h1>webrecon &mdash; {_esc(report.target)}</h1>",
        "<p class='meta'>" + "<br>".join(meta) + "</p>",
        status,
        _section("Errors", ["Error"], [[e] for e in report.errors], css="bad"),
        _section(
            "DNS records",
            ["Type", "Values"],
            [[k, ", ".join(v)] for k, v in dns_records.items()],
        ),
        _section(
            "DNS query status",
            ["Query", "Status"],
            [
                [k, v]
                for k, v in (report.dns.status.items() if report.dns else [])
                if v not in ("OK", "NOANSWER")
            ],
        ),
        _section(
            "Subdomains",
            ["Host", "Addresses", "Source"],
            [[s.name, ", ".join(s.addresses), s.source] for s in report.subdomains],
        ),
        _section(
            "HTTP",
            ["URL", "Status", "Title", "Technologies"],
            [
                [r.final_url or r.url, r.status, r.title, ", ".join(r.technologies)]
                for r in report.http
                if r.reachable
            ],
        ),
        _section(
            "Unreachable",
            ["URL", "Error"],
            [[r.url, r.error or "no response"] for r in report.http if not r.reachable],
        ),
        _section(
            "Interesting paths",
            ["Host", "Path"],
            [[r.url, p] for r in report.http for p in r.interesting_paths],
        ),
        _section("Findings", ["Where", "Finding"], [list(f) for f in _findings(report)]),
        _section(
            "TLS",
            ["Endpoint", "Issuer", "Expires", "Days left", "Trusted", "Protocol"],
            [
                [
                    f"{c.host}:{c.port}",
                    c.issuer or c.error,
                    c.not_after,
                    c.days_until_expiry,
                    {True: "yes", False: "no"}.get(c.trusted) if c.trusted is not None else None,
                    c.protocol,
                ]
                for c in report.tls
            ],
        ),
        _section(
            "Open ports",
            ["Port", "Service", "Banner"],
            [[p.port, p.service, p.banner] for p in report.ports],
        ),
        _section("Skipped", ["Host", "Reason"], [[s.host, s.reason] for s in report.skipped]),
        _section("Notes", ["Note"], [[n] for n in report.notes]),
    ]
    if not any(
        (report.dns and report.dns.records, report.subdomains, report.http, report.tls,
         report.ports, report.errors)
    ):
        parts.append("<p class='meta'>No results were collected.</p>")
    return "<section>" + "".join(parts) + "</section>"


def to_html(reports: Reports) -> str:
    """Render a self-contained HTML report with no external assets.

    A Content-Security-Policy meta tag forbids scripts and remote resources as
    defence in depth on top of escaping every value.
    """
    items = _as_list(reports)
    title = ", ".join(r.target for r in items) or "no targets"
    body = "<hr>".join(_html_report(r) for r in items)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{HTML_CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>webrecon &mdash; {_esc(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; padding: 2rem 1rem;
         max-width: 60rem; }}
  h1 {{ margin-bottom: .25rem; }}
  .meta {{ color: #888; margin-bottom: 1rem; }}
  .warn {{ color: #b35c00; }}
  .ok {{ color: #2f9e44; }}
  h2 {{ margin-top: 2rem; font-size: 1.1rem; }}
  h2.bad {{ color: #c92a2a; }}
  .wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
  th, td {{ text-align: left; padding: .4rem .6rem;
            border-bottom: 1px solid rgba(128,128,128,.3); vertical-align: top; }}
  th {{ font-weight: 600; white-space: nowrap; }}
  td {{ word-break: break-word; }}
  hr {{ margin: 3rem 0; border: 0; border-top: 1px solid rgba(128,128,128,.4); }}
</style></head>
<body>
{body}
</body></html>"""
