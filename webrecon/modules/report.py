"""Rendering of a ScanReport to JSON, terminal output and standalone HTML."""

from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import ScanReport


def to_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


def write_json(report: ScanReport, path: Path) -> None:
    path.write_text(to_json(report), encoding="utf-8")


def render_terminal(report: ScanReport, console: Console | None = None) -> None:
    """Print a human-readable summary of the scan."""
    console = console or Console()

    console.print(
        Panel(
            f"[bold]{report.target}[/bold]\n"
            f"started  {report.started_at}\n"
            f"finished {report.finished_at or '-'}",
            title="webrecon",
            border_style="cyan",
        )
    )

    if report.dns and report.dns.records:
        table = Table(title="DNS records", show_lines=False, header_style="bold cyan")
        table.add_column("type")
        table.add_column("value", overflow="fold")
        for rtype, values in report.dns.records.items():
            table.add_row(rtype, "\n".join(values))
        console.print(table)

    if report.subdomains:
        table = Table(title=f"Subdomains ({len(report.subdomains)})", header_style="bold cyan")
        table.add_column("host")
        table.add_column("addresses", overflow="fold")
        table.add_column("source")
        for sub in report.subdomains:
            table.add_row(sub.name, ", ".join(sub.addresses), sub.source)
        console.print(table)

    live = [h for h in report.http if h.reachable]
    if live:
        table = Table(title=f"HTTP ({len(live)} reachable)", header_style="bold cyan")
        table.add_column("url", overflow="fold")
        table.add_column("status", justify="right")
        table.add_column("title", overflow="fold")
        table.add_column("technologies", overflow="fold")
        for result in live:
            status = str(result.status)
            colour = "green" if result.status and result.status < 400 else "yellow"
            table.add_row(
                result.final_url or result.url,
                f"[{colour}]{status}[/{colour}]",
                result.title or "-",
                ", ".join(result.technologies) or "-",
            )
        console.print(table)

        paths = [(r.url, p) for r in live for p in r.interesting_paths]
        if paths:
            table = Table(title="Interesting paths", header_style="bold cyan")
            table.add_column("host", overflow="fold")
            table.add_column("path", overflow="fold")
            for url, path in paths:
                table.add_row(url, path)
            console.print(table)

    if report.tls:
        table = Table(title="TLS certificates", header_style="bold cyan")
        table.add_column("host")
        table.add_column("issuer", overflow="fold")
        table.add_column("expires")
        table.add_column("days", justify="right")
        for cert in report.tls:
            if cert.error:
                table.add_row(cert.host, f"[red]{cert.error}[/red]", "-", "-")
                continue
            days = cert.days_until_expiry
            colour = "red" if days is not None and days < 15 else "green"
            table.add_row(
                cert.host,
                cert.issuer or "-",
                cert.not_after or "-",
                f"[{colour}]{days if days is not None else '-'}[/{colour}]",
            )
        console.print(table)

    if report.ports:
        table = Table(title="Open ports", header_style="bold cyan")
        table.add_column("port", justify="right")
        table.add_column("service")
        for port in report.ports:
            table.add_row(str(port.port), port.service or "-")
        console.print(table)

    for error in report.errors:
        console.print(f"[red]error[/red] {error}")


def to_html(report: ScanReport) -> str:
    """Render a self-contained HTML report with no external assets."""

    def esc(value: object) -> str:
        return html.escape(str(value if value not in (None, "") else "-"))

    def section(title: str, headers: list[str], rows: list[list[str]]) -> str:
        if not rows:
            return ""
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows
        )
        return (
            f"<h2>{esc(title)}</h2><div class='wrap'><table>"
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
        )

    parts = [
        section(
            "DNS records",
            ["Type", "Values"],
            [[k, ", ".join(v)] for k, v in (report.dns.records if report.dns else {}).items()],
        ),
        section(
            "Subdomains",
            ["Host", "Addresses", "Source"],
            [[s.name, ", ".join(s.addresses), s.source] for s in report.subdomains],
        ),
        section(
            "HTTP",
            ["URL", "Status", "Title", "Technologies"],
            [
                [r.final_url or r.url, r.status, r.title, ", ".join(r.technologies)]
                for r in report.http
                if r.reachable
            ],
        ),
        section(
            "Interesting paths",
            ["Host", "Path"],
            [[r.url, p] for r in report.http for p in r.interesting_paths],
        ),
        section(
            "TLS",
            ["Host", "Issuer", "Expires", "Days left"],
            [[c.host, c.issuer or c.error, c.not_after, c.days_until_expiry] for c in report.tls],
        ),
        section(
            "Open ports",
            ["Port", "Service"],
            [[p.port, p.service] for p in report.ports],
        ),
    ]

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>webrecon &mdash; {esc(report.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; padding: 2rem 1rem;
         max-width: 60rem; }}
  h1 {{ margin-bottom: .25rem; }}
  .meta {{ color: #888; margin-bottom: 2rem; }}
  h2 {{ margin-top: 2rem; font-size: 1.1rem; }}
  .wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
  th, td {{ text-align: left; padding: .4rem .6rem;
            border-bottom: 1px solid rgba(128,128,128,.3); vertical-align: top; }}
  th {{ font-weight: 600; white-space: nowrap; }}
  td {{ word-break: break-word; }}
</style></head>
<body>
<h1>webrecon &mdash; {esc(report.target)}</h1>
<p class="meta">{esc(report.started_at)} &rarr; {esc(report.finished_at)}</p>
{"".join(parts)}
</body></html>"""


def write_html(report: ScanReport, path: Path) -> None:
    path.write_text(to_html(report), encoding="utf-8")
