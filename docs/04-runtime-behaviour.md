# 4. Runtime behaviour

| | |
| --- | --- |
| Document | SDD-04 — Dynamic view |
| System | webrecon 0.2.0 |
| Status | Approved |
| Last revised | 2026-11-16 |

## 4.1 Purpose

This document describes what happens at runtime: the sequence of interactions
between components, the scan lifecycle, error propagation, and the concurrency
model. The corresponding static structure is in
[01-architecture.md](01-architecture.md).

## 4.2 Overall scan sequence

```mermaid
sequenceDiagram
    actor A as Analyst
    participant CLI as cli.main
    participant SC as scanner.run_scan
    participant CTX as ScanContext
    participant DNS as dns_enum
    participant PS as port_scan
    participant HTTP as http_probe
    participant TLS as tls_info
    participant REP as report

    A->>CLI: webrecon example.com -m all -o report.json
    activate CLI
    CLI->>CLI: parse_target, parse_ports, resolve_modules,<br/>Scope.build, check wordlist and output paths
    CLI->>A: confirmation prompt (or --i-have-authorization)
    A-->>CLI: yes
    CLI->>CLI: record authorization, open JsonlWriter (if --jsonl)

    loop for each target
        CLI->>CLI: build ScanConfig and ScanReport
        CLI->>SC: run_scan(config, on_stage, report, emit)
        activate SC
        SC->>CTX: ScanContext.create(config)
        Note over CTX: one Throttle, one Scope,<br/>the report filled in place

        SC->>DNS: fetch_records(target, throttle, …)
        DNS-->>SC: DnsRecords
        SC->>SC: _target_refusal (scope, public address)

        SC->>DNS: enumerate_subdomains(ctx)
        DNS-->>SC: list[Subdomain]
        Note over SC: in-scope, public subdomains<br/>become the HTTP hosts

        SC->>PS: scan(target, ports, throttle), if -m ports
        PS-->>SC: open ports
        Note over SC: open web ports become<br/>extra HTTP/TLS endpoints

        SC->>HTTP: probe_hosts(endpoints, ctx)
        HTTP-->>SC: list[HttpResult]

        SC->>SC: select HTTPS endpoints<br/>(+ open TLS ports)
        SC->>TLS: inspect_hosts(endpoints, ctx)
        TLS-->>SC: list[TlsInfo]

        SC->>SC: complete = True, populate finished_at
        SC->>CTX: emit("summary")
        SC-->>CLI: ScanReport
        deactivate SC
    end

    CLI->>REP: render_terminal(reports)
    REP-->>A: tables on screen
    CLI->>REP: write_json(reports, path, force)
    REP-->>CLI: file written (0600)
    CLI-->>A: exit 0
    deactivate CLI
```

Two points are worth noting. First, how hosts pass between stages: discovered
subdomains feed the HTTP probe, open web ports found by the port scan add
endpoints, and only endpoints answering over HTTPS (plus open TLS ports) feed
the TLS inspection. Each stage narrows or targets the set the next one works on,
which contains traffic towards the target. Second, every stage receives the
same `ScanContext`, so the throttle, the scope and the report are shared; each
result is also handed to `emit` as soon as it exists, which is how `--jsonl`
writes incrementally.

When only the `dns` module is enabled, the CLI asks for no confirmation and the
scan ends after `fetch_records`: neither the target gate nor any active stage
runs.

## 4.3 Subdomain enumeration

```mermaid
sequenceDiagram
    participant SC as scanner
    participant EN as enumerate_subdomains
    participant TH as Throttle (shared)
    participant CRT as crt.sh
    participant WL as load_wordlist
    participant SCO as Scope
    participant SEL as select_candidates
    participant DNS as DNS resolver

    SC->>EN: enumerate_subdomains(ctx)
    activate EN

    alt passive mode enabled
        EN->>TH: acquire slot
        EN->>CRT: GET /?q=%.domain&output=json<br/>(User-Agent, proxy, timeout ≥ 15 s)
        alt valid JSON response
            CRT-->>EN: certificate JSON
            EN->>EN: parse_crtsh → valid, in-domain names
        else HTTP error or non-JSON body
            CRT--xEN: failure
            EN->>EN: ctx.error("crt.sh lookup failed …")
            Note over EN: enumeration continues<br/>with the wordlist
        end
        EN->>TH: release slot
    end

    opt wordlist configured (bundled by default)
        EN->>WL: load_wordlist(path)
        WL-->>EN: valid, deduplicated labels
    end

    EN->>EN: add the apex domain (source = target)
    EN->>SCO: allows_name(candidate)
    SCO-->>EN: out-of-scope names → ctx.skip

    EN->>DNS: resolve 3 random labels (detect_wildcard)
    DNS-->>EN: wildcard addresses, or none

    EN->>SEL: select_candidates(candidates, limit)
    SEL-->>EN: candidates ordered by confidence

    loop for each candidate, in parallel
        EN->>TH: acquire slot
        EN->>DNS: A query
        DNS-->>EN: addresses or NXDOMAIN
        EN->>TH: release slot
        opt A did not return NXDOMAIN
            EN->>TH: acquire slot
            EN->>DNS: AAAA query
            DNS-->>EN: addresses
            EN->>TH: release slot
        end
        EN->>EN: ctx.emit("subdomain") if kept
    end

    EN->>EN: discard non-resolving and wildcard-only<br/>brute-force hits, notes, sort by name
    EN-->>SC: list[Subdomain]
    deactivate EN
```

## 4.4 HTTP probe with redirect chain

```mermaid
sequenceDiagram
    participant PH as probe_hosts
    participant PU as probe_url
    participant BU as RequestBudget
    participant TH as Throttle (shared)
    participant T as Target
    participant SCO as Scope
    participant TD as tech_detect
    participant SH as security_headers
    participant DC as discover_content

    PH->>PU: probe_url("https://host") (scheme order from _schemes_for)
    activate PU

    loop up to 5 redirects
        PU->>BU: take(url)
        alt budget exhausted
            BU-->>PU: false
            Note over PU: error: per-host request<br/>budget exhausted
        end
        PU->>TH: acquire slot
        PU->>T: GET url
        T-->>PU: response
        PU->>TH: release slot
        alt is a redirect
            PU->>PU: record Redirect(status, location),<br/>resolve relative destination
            PU->>SCO: refusal(destination host)
            alt out of scope
                PU->>PU: finding, ctx.skip, stop following
            else already visited
                PU->>PU: error: redirect loop
            end
        else final response
            PU->>PU: exit loop
        end
    end

    PU->>PU: extract status, title (_TitleParser),<br/>final URL, collect_headers (redacted)
    PU->>TD: detect(headers, body, raw Set-Cookie list)
    TD-->>PU: detected technologies
    PU->>SH: analyse(headers, raw Set-Cookie list, https)
    SH-->>PU: security findings
    PU->>DC: discover_content(root)
    activate DC
    DC->>T: GET /wr-random-token (baseline)
    par well-known paths checked in parallel
        DC->>T: GET /robots.txt
        DC->>T: GET /sitemap.xml
        DC->>T: GET /.well-known/security.txt
        DC->>T: GET /.git/HEAD
        DC->>T: GET /.env
    end
    Note over DC,T: every request goes through<br/>the budget and the shared throttle
    DC->>DC: _looks_like_hit: baseline comparison<br/>and per-file shape check
    opt robots.txt present
        DC->>DC: parse_robots → max 20 paths
    end
    DC-->>PU: confirmed paths
    deactivate DC

    PU-->>PH: HttpResult
    deactivate PU

    alt first scheme unreachable
        PH->>PU: probe_url("http://host")
        PU-->>PH: HttpResult
        Note over PH: if that fails too,<br/>the first result is returned<br/>with its original error
    end
    PH->>PH: ctx.emit("http", result)
```

## 4.5 TLS inspection

```mermaid
sequenceDiagram
    participant IH as inspect_hosts
    participant SCO as Scope
    participant IN as inspect
    participant TH as Throttle (shared)
    participant T as Target
    participant CR as cryptography

    IH->>SCO: refusal(host)
    alt out of scope or non-public
        SCO-->>IH: reason
        IH->>IH: ctx.skip, TlsInfo(error="skipped: …")
    else allowed
        IH->>IN: inspect(host, port, timeout, throttle)
        activate IN
        IN->>TH: acquire slot
        IN->>T: asyncio.open_connection, verified handshake
        Note over IN,T: runs on the event loop:<br/>no thread, cancellable by<br/>--max-time and Ctrl-C
        alt chain and hostname verify
            T-->>IN: DER certificate, protocol, cipher
            IN->>TH: release slot
        else SSLCertVerificationError<br/>(self-signed, expired, hostname mismatch)
            T--xIN: verify_message
            IN->>TH: release slot
            IN->>IN: record verify_error
            IN->>TH: acquire second slot
            IN->>T: unverified handshake
            T-->>IN: DER certificate, protocol, cipher
            IN->>TH: release slot
            Note over IN: the anomalous certificate<br/>is the finding, not an error
        end
        IN->>CR: load_der_x509_certificate
        CR-->>IN: issuer, subject, SANs (DNS + IP), validity
        IN->>IN: parse_der: validity window,<br/>days remaining, findings
        IN->>IN: trusted, verify_error, protocol, cipher,<br/>legacy-protocol finding
        IN-->>IH: TlsInfo
        deactivate IN
        IH->>IH: ctx.emit("tls", info)
    end
```

In 0.1.0 the handshake ran in a worker thread through `asyncio.to_thread`. A
thread cannot be cancelled, so a slow handshake outlived both the timeout and
Ctrl-C; and the unverified retry returned an empty dictionary. Running the
handshake with `asyncio.open_connection` and reading the DER form solves both.

## 4.6 Scan lifecycle

```mermaid
stateDiagram-v2
    [*] --> Validation
    Validation --> Terminated : invalid arguments, paths or scope (exit 2)
    Validation --> Authorisation : active modules enabled
    Validation --> Scan : dns module only
    Authorisation --> Terminated : not confirmed (exit 2)
    Authorisation --> Scan : confirmed and recorded

    state "Scan of one target" as Scan {
        [*] --> DnsResolution
        DnsResolution --> [*] : dns module only
        DnsResolution --> TargetGate : active modules enabled
        TargetGate --> [*] : target refused, recorded as skipped
        TargetGate --> Enumeration
        Enumeration --> PortScan
        PortScan --> HttpProbe
        HttpProbe --> TlsInspection
        TlsInspection --> [*]
    }

    Scan --> Complete : every stage returned
    Scan --> Incomplete : --max-time reached
    Scan --> Interrupted : Ctrl-C
    Scan --> Crashed : unexpected exception

    Complete --> Scan : next target
    Incomplete --> Scan : next target
    Complete --> Rendering : last target
    Incomplete --> Rendering : last target
    Interrupted --> Rendering : partial report
    Crashed --> Rendering : partial report

    Rendering --> Terminated : exit 0, 3, 130 or 1
    Terminated --> [*]
```

Every stage is entered even when its module is disabled: in that case it
produces no results and hands control straight to the next one. An exception
inside a stage does not leave the `Scan` state: `_guarded` records it and the
next stage starts. `Crashed` covers only an exception that escapes `run_scan`
altogether.

Unlike 0.1.0, the `Interrupted` and `Crashed` states write the requested report
files: the reports are filled in place, so `cli.main` marks the unfinished ones
with `incomplete_reason` and renders them. Remaining targets are not scanned.
`Incomplete` (time limit) instead moves on to the next target.

## 4.7 Concurrency model

The system uses a single event loop per target in a single process
(`asyncio.run` is called once per target). Parallelism is cooperative and lives
entirely within individual stages, never across them. The only thread is the
optional AXFR transfer.

```mermaid
graph TB
    subgraph seq["Sequential — scan stages"]
        F1["DNS"] --> F0["Target gate"] --> F2["Subdomains"] --> F5["Ports"] --> F3["HTTP"] --> F4["TLS"]
    end

    subgraph par["Parallel — within each stage"]
        direction LR
        C1["coroutine 1"]
        C2["coroutine 2"]
        C3["coroutine N"]
    end

    subgraph limit["Cross-cutting constraints — one ScanContext"]
        TH["Throttle<br/>semaphore + token bucket<br/>(shared by every stage)"]
        BU["RequestBudget<br/>(HTTP, per host)"]
        MT["max_time<br/>(asyncio.wait_for)"]
    end

    F3 -.-> par
    C1 --> TH
    C2 --> TH
    C3 --> TH
    C1 -.-> BU
    seq -.-> MT

    style seq fill:#fff4e6
    style par fill:#f3f0ff
    style limit fill:#ffe3e3
```

**Why stages stay sequential.** Each stage depends on the previous one's output:
without subdomains there is no way to know which hosts to probe, without the
port scan no way to know which non-standard web ports to probe, and without the
HTTP responses no way to know whose certificate to inspect. Parallelising them
would mean probing hosts not yet discovered.

**Why in-stage parallelism is bounded.** Every coroutine passes through the
**same** `Throttle` before each outbound call — DNS queries, the crt.sh request,
HTTP requests, TLS handshakes, the address lookups and port connections. The
semaphore limits how many operations are in flight, the token bucket how many
start per second. With `-c 5 -r 10` the system never exceeds five simultaneous
operations nor ten per second, across all modules together, however many hosts
are queued. In 0.1.0 each module had its own throttle, so the effective rate was
a multiple of `--rate`; the shared instance is verified by
`TestRunScan::test_every_module_shares_one_throttle` and, against loopback
servers, by the rate tests of each I/O module.

**Time limit.** With `--max-time`, `run_scan` wraps the whole stage sequence in
`asyncio.wait_for`. When the deadline expires, the running coroutines are
cancelled — including throttle waits and TLS handshakes, which are cancellable —
and the report keeps everything gathered up to that instant.

### Semaphore and token bucket interaction

```mermaid
sequenceDiagram
    participant C1 as Coroutine 1
    participant C2 as Coroutine 2
    participant S as Semaphore
    participant B as Token bucket

    C1->>S: acquire
    S-->>C1: slot granted
    C1->>B: book turn (under lock)
    B-->>C1: turn = t0
    Note over C1: waits outside the lock

    C2->>S: acquire
    S-->>C2: slot granted
    C2->>B: book turn (under lock)
    B-->>C2: turn = t0 + interval
    Note over C1,C2: booking is serialised,<br/>waiting is not: coroutines never<br/>queue behind someone else's wait
```

The lock protects only the turn computation; the wait happens outside it. Were
the wait inside the lock, every coroutine would wait for the sum of all previous
waits and the effective rate would collapse.

## 4.8 Error propagation

The system distinguishes four levels of failure, with different destinations.

```mermaid
flowchart TD
    E["An error occurs"] --> T{"What kind?"}

    T -->|"Failure of a single<br/>network operation"| L1["Recorded in the error field<br/>of that specific result"]
    T -->|"Failure affecting a whole stage,<br/>or an exception inside a stage"| L2["Appended to<br/>ScanReport.errors"]
    T -->|"Time limit, Ctrl-C or<br/>exception escaping the scan"| L3["Report marked incomplete<br/>(incomplete_reason)"]
    T -->|"Violated precondition"| L4["Usage error before<br/>any network traffic"]

    L1 --> R["The scan continues"]
    L2 --> R
    L3 --> P["Partial report written"]
    L4 --> S["The process terminates"]

    R --> O["Report produced — exit 0<br/>(3 with --fail-if-unreachable<br/>if nothing answered)"]
    P --> Q["exit 0 (time limit),<br/>130 (Ctrl-C) or 1 (crash)"]
    S --> X["No report — exit 2"]

    style L1 fill:#ebfbee
    style L2 fill:#fff4e6
    style L3 fill:#fff3bf
    style L4 fill:#ffe3e3
```

| Level | Examples | Destination | Effect |
| --- | --- | --- | --- |
| Operation | Unreachable host, HTTP timeout, redirect loop, budget exhausted, TLS port closed, unverifiable certificate, one DNS query failing | `HttpResult.error`, `TlsInfo.error`, `TlsInfo.verify_error`, `DnsRecords.status` | That single result carries the error; other hosts are unaffected. |
| Stage | No DNS records resolved, crt.sh unreachable, port scan target unresolvable, unexpected exception in a stage, target out of scope | `ScanReport.errors`, `ScanReport.skipped`, `ScanReport.notes` | The stage produces no (or partial) data; later stages proceed on what is available. |
| Scan | `--max-time` reached, Ctrl-C, exception escaping `run_scan`; or, at the end of a scan, any entry in `errors` or an in-scope host whose HTTP or TLS attempts all timed out | `complete=False`, `incomplete_reason`, `errors` | The report keeps everything gathered and is written; exit 0, 130 or 1 respectively. |
| Process | Unknown module, invalid target or scope entry, missing wordlist, malformed ports or numbers, unusable output path, authorisation not confirmed | `argparse` usage error | The process terminates before the scan, writing no report; exit 2. |

The fourth level's preconditions are checked **before** any network traffic
starts: a typo must not cost the user a full scan with an unexpected result.
Every error at the first three levels is visible in all report formats: the
terminal and HTML outputs list errors, unreachable hosts, skipped hosts and
notes, not only successful results.

## 4.9 Indicative timing profile

Measurements taken with version 0.1.0 against `example.com` and `iana.org` from
a home connection, as an order of magnitude.

| Configuration | Hosts resolved | Duration |
| --- | --- | --- |
| `-m dns,http,tls --no-passive` | 1 | ~1 s |
| `-m subdomains` with a 138-entry wordlist and crt.sh | 15 | ~13 s |
| `-m ports` over 3 ports | 1 | ~1 s |

The dominant factor is the number of candidates to resolve, not the number of
enabled modules. Since 0.2.0 the default profile uses the bundled 138-entry
wordlist, each candidate costs up to two throttle slots (A and AAAA), and
enumeration adds three wildcard probes, so `--no-wordlist` is the fastest
option when brute-force is not needed. The crt.sh lookup is allowed at least
15 seconds whatever `-t` says. With `--rate` set, the duration has a lower bound
by construction of the token bucket: `n` operations at `r` per second cannot
complete in less than `n / r` seconds — and since the throttle is now shared,
`n` counts the operations of every module. `--max-time` gives an upper bound.

## 4.10 Verification strategy

```mermaid
graph LR
    subgraph offline["Automated suite — 275 tests, ~4.5 s, no internet access"]
        U1["Pure logic<br/>parsing, signatures, targets,<br/>scope, dates, banners"]
        U2["Components<br/>Throttle, report files, rendering"]
        U3["I/O modules<br/>loopback HTTP, TLS and DNS servers"]
        U4["Orchestration<br/>stubbed modules"]
        U5["CLI end to end<br/>loopback HTTP server"]
    end

    subgraph manual["Manual verification on authorised targets"]
        M1["example.com<br/>DNS, HTTP, TLS"]
        M2["iana.org<br/>passive enumeration"]
    end

    offline --> CI["CI: Python 3.10–3.13<br/>ruff + mypy + pytest"]

    style offline fill:#ebfbee
    style manual fill:#e7f5ff
```

The automated suite sends no traffic beyond the loopback interface. The fixtures
in `tests/conftest.py` start, on ephemeral `127.0.0.1` ports, a threaded HTTP
server with programmable routes (optionally wrapped in TLS), certificates
generated on the fly with `cryptography` (self-signed, expired, not yet valid,
wrong hostname), and a UDP DNS server answering from a dictionary with optional
wildcard and SERVFAIL names. The I/O functions — `fetch_records`,
`enumerate_subdomains`, `probe_url`, `discover_content`, `probe_hosts`,
`inspect`, `check_port`, `scan` — are therefore exercised against real sockets,
including their rate limiting, rather than being stubbed as in 0.1.0. Only
`tests/test_scanner.py` replaces the modules with stubs, to verify orchestration
(stage order, endpoint propagation, shared throttle, target gate, time limit,
stage isolation) independently of the network. This keeps the tests
deterministic, runnable offline and free of traffic towards third-party
systems — a non-negotiable requirement for the CI of a security tool.
