# webrecon

[![CI](https://github.com/Just-Ipavon/web-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/Just-Ipavon/web-recon/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small asynchronous web reconnaissance scanner: DNS enumeration, passive and
active subdomain discovery, HTTP fingerprinting, technology detection, TLS
certificate inspection and TCP port scanning — with JSON, terminal and HTML
reports.

> **Authorised use only.** Run this against systems you own or have written
> permission to test. Unauthorised scanning is illegal in most jurisdictions.

## Features

| Module | What it does |
| --- | --- |
| `dns` | Resolves A, AAAA, MX, NS, TXT, CNAME and SOA records |
| `subdomains` | Certificate transparency lookups (crt.sh) plus wordlist brute-force, then resolves each candidate |
| `http` | Reachability, redirect chain, status, page title, headers, and content discovery (`robots.txt`, `sitemap.xml`, `security.txt`, exposed `.git`/`.env`) |
| `tls` | Issuer, subject, SANs, validity window and days until expiry |
| `ports` | TCP connect scan over an explicit port list |

Technology detection runs on every HTTP response and identifies ~30 servers,
CDNs, frameworks and CMSs from headers, cookies and body markers.

## Install

```bash
git clone https://github.com/Just-Ipavon/web-recon.git
cd web-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Default scan: DNS, subdomains, HTTP and TLS
webrecon example.com

# Everything, with a wordlist and a JSON + HTML report
webrecon example.com -m all -w wordlists/subdomains-small.txt -o report.json --html report.html

# 10 requests per second, 5 at a time
webrecon example.com -r 10 -c 5

# Active only — skip certificate transparency lookups
webrecon example.com --no-passive
```

### Options

| Flag | Meaning |
| --- | --- |
| `-m, --modules` | Modules to run: `dns`, `subdomains`, `http`, `tls`, `ports`, or `all` |
| `-w, --wordlist` | Subdomain wordlist for brute-force |
| `-c, --concurrency` | Maximum concurrent requests (default 20) |
| `-r, --rate` | Maximum requests per second; `0` disables pacing |
| `-t, --timeout` | Per-request timeout in seconds (default 5) |
| `-p, --ports` | Ports to scan, e.g. `80,443,8000-8100` |
| `--max-subdomains` | Cap on candidates resolved (default 200) |
| `--no-passive` | Skip crt.sh lookups |
| `-o, --output` | Write a JSON report |
| `--html` | Write a self-contained HTML report |
| `-q, --quiet` | Suppress terminal output |

### Example output

```text
╭──────────────────── webrecon ────────────────────╮
│ example.com                                      │
│ started  2026-07-27T14:14:39+00:00               │
│ finished 2026-07-27T14:14:40+00:00               │
╰──────────────────────────────────────────────────╯
                       HTTP (1 reachable)
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ url                 ┃ status ┃ title          ┃ technologies ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ https://example.com │    200 │ Example Domain │ Cloudflare   │
└─────────────────────┴────────┴────────────────┴──────────────┘
```

The JSON report carries the same data in full, suitable for piping into `jq` or
feeding another tool:

```json
{
  "target": "example.com",
  "http": [
    {
      "url": "https://example.com",
      "status": 200,
      "title": "Example Domain",
      "technologies": ["Cloudflare"],
      "interesting_paths": ["/robots.txt"]
    }
  ]
}
```

## Design notes

**Everything is rate limited.** Each module routes its outbound calls through
`Throttle` ([webrecon/ratelimit.py](webrecon/ratelimit.py)), which combines a
semaphore for in-flight work with a token bucket for request rate. Unbounded
concurrency is what separates a recon tool from a denial-of-service tool.

**Failures are contained, not fatal.** A DNS timeout, an unreachable host or an
unparseable certificate is recorded in the result and the scan continues. A
partial report beats a traceback.

**Modules return dataclasses, not dicts.** Every module produces types from
[webrecon/models.py](webrecon/models.py), so the report layer never guesses at
a schema and JSON output stays stable.

**Content discovery avoids soft 404s.** Servers that answer `200` with an HTML
error page are common, so a path only counts as a hit when its body matches the
shape expected for that file — a `.git/HEAD` must start with `ref:`, an `.env`
must contain `KEY=value` lines.

**Candidates are ranked before truncation.** `--max-subdomains` cuts by
confidence (target, then certificate transparency, then wordlist guesses), not
alphabetically, so the hosts most likely to exist survive the cap.

## Architecture

```text
webrecon/
├── cli.py              argument parsing, output selection
├── scanner.py          orchestration: runs enabled modules, assembles report
├── config.py           ScanConfig
├── models.py           result dataclasses
├── ratelimit.py        Throttle: concurrency + rate limiting
└── modules/
    ├── dns_enum.py     records, crt.sh, wordlist brute-force
    ├── http_probe.py   probing, redirects, content discovery
    ├── tech_detect.py  signature-based fingerprinting
    ├── tls_info.py     certificate inspection
    ├── port_scan.py    TCP connect scan
    └── report.py       JSON / terminal / HTML rendering
```

## Documentation

Full technical documentation lives in [docs/](docs/README.md): architecture and
design decisions, use case specifications, a function-by-function reference, and
the runtime behaviour — with UML diagrams throughout.

| Document | Contents |
| --- | --- |
| [01 — Architecture](docs/01-architecture.md) | Context, packages, data model, architectural decisions, deployment |
| [02 — Use cases](docs/02-use-cases.md) | Actors, use case diagram, eight detailed specifications, operational scenarios |
| [03 — Function reference](docs/03-function-reference.md) | Every function: behaviour, edge cases, error handling, covering tests |
| [04 — Runtime behaviour](docs/04-runtime-behaviour.md) | Sequence diagrams, lifecycle, concurrency model, error propagation |

## License

MIT — see [LICENSE](LICENSE).
