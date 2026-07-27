# 4. Runtime behaviour

| | |
| --- | --- |
| Document | SDD-04 — Dynamic view |
| System | webrecon 0.1.0 |
| Status | Approved |
| Last revised | 2026-07-27 |

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
    participant DNS as dns_enum
    participant HTTP as http_probe
    participant TLS as tls_info
    participant REP as report

    A->>CLI: webrecon example.com -o report.json
    activate CLI
    CLI->>CLI: normalise_target, parse_ports,<br/>resolve_modules
    CLI->>CLI: build ScanConfig
    CLI->>SC: run_scan(config, on_stage)
    activate SC

    SC->>DNS: fetch_records(target)
    activate DNS
    DNS-->>SC: DnsRecords
    deactivate DNS

    SC->>DNS: enumerate_subdomains(config)
    activate DNS
    DNS-->>SC: list[Subdomain]
    deactivate DNS
    Note over SC: resolved hosts become<br/>the next phase's input

    SC->>HTTP: probe_hosts(hosts, config)
    activate HTTP
    HTTP-->>SC: list[HttpResult]
    deactivate HTTP

    SC->>SC: select hosts reachable<br/>over HTTPS
    SC->>TLS: inspect_hosts(live)
    activate TLS
    TLS-->>SC: list[TlsInfo]
    deactivate TLS

    SC->>SC: populate finished_at
    SC-->>CLI: ScanReport
    deactivate SC

    CLI->>REP: render_terminal(report)
    REP-->>A: tables on screen
    CLI->>REP: write_json(report, path)
    REP-->>CLI: file written
    CLI-->>A: exit 0
    deactivate CLI
```

The point worth noting is how hosts pass between phases: discovered subdomains
feed the HTTP probe, and only the hosts answering over HTTPS feed the TLS
inspection. Each phase narrows the set the next one works on, which contains
traffic towards the target.

## 4.3 Subdomain enumeration

```mermaid
sequenceDiagram
    participant SC as scanner
    participant EN as enumerate_subdomains
    participant CRT as crt.sh
    participant WL as load_wordlist
    participant SEL as select_candidates
    participant TH as Throttle
    participant DNS as DNS resolver

    SC->>EN: enumerate_subdomains(config)
    activate EN

    alt passive mode enabled
        EN->>CRT: GET /?q=%.domain&output=json
        alt valid response
            CRT-->>EN: certificate JSON
            EN->>EN: parse_crtsh → normalised names
        else HTTP error or invalid JSON
            CRT--xEN: failure
            Note over EN: empty set,<br/>the scan continues
        end
    end

    opt wordlist supplied
        EN->>WL: load_wordlist(path)
        WL-->>EN: deduplicated labels
    end

    EN->>EN: add the apex domain
    EN->>SEL: select_candidates(candidates, limit)
    SEL-->>EN: candidates ordered by confidence

    loop for each candidate, in parallel
        EN->>TH: acquire slot
        TH-->>EN: slot granted
        EN->>DNS: A and AAAA queries
        DNS-->>EN: addresses or NXDOMAIN
        EN->>TH: release slot
    end

    EN->>EN: discard non-resolving, sort by name
    EN-->>SC: list[Subdomain]
    deactivate EN
```

## 4.4 HTTP probe with redirect chain

```mermaid
sequenceDiagram
    participant PH as probe_hosts
    participant PU as probe_url
    participant TH as Throttle
    participant T as Target
    participant TD as tech_detect
    participant DC as discover_content

    PH->>PU: probe_url("https://host")
    activate PU

    loop up to 5 redirects
        PU->>TH: acquire slot
        PU->>T: GET url
        T-->>PU: response
        alt is a redirect
            PU->>PU: record Redirect(status, location)
            PU->>PU: resolve relative destination
        else final response
            PU->>PU: exit loop
        end
        PU->>TH: release slot
    end

    PU->>PU: extract status, title,<br/>headers, final URL
    PU->>TD: detect(headers, body)
    TD-->>PU: detected technologies
    PU->>DC: discover_content(root)
    activate DC
    par well-known paths checked in parallel
        DC->>T: GET /robots.txt
        DC->>T: GET /sitemap.xml
        DC->>T: GET /.well-known/security.txt
        DC->>T: GET /.git/HEAD
        DC->>T: GET /.env
    end
    DC->>DC: _looks_like_hit filters soft 404s
    opt robots.txt present
        DC->>DC: parse_robots → max 20 paths
    end
    DC-->>PU: confirmed paths
    deactivate DC

    PU-->>PH: HttpResult
    deactivate PU

    alt HTTPS unreachable
        PH->>PU: probe_url("http://host")
        PU-->>PH: HttpResult
        Note over PH: if HTTP fails too,<br/>the HTTPS result is returned<br/>with its original error
    end
```

## 4.5 TLS inspection and thread delegation

```mermaid
sequenceDiagram
    participant IH as inspect_hosts
    participant IN as inspect
    participant TH as Throttle
    participant TR as Thread pool
    participant T as Target

    IH->>IN: inspect(host, 443)
    activate IN
    IN->>TH: acquire slot
    IN->>TR: asyncio.to_thread(_fetch_certificate)
    activate TR
    Note over IN,TR: the ssl module is synchronous:<br/>without delegation it would<br/>block the whole event loop

    TR->>T: handshake with verification
    alt verified handshake succeeds
        T-->>TR: certificate
    else self-signed, expired<br/>or hostname mismatch
        T--xTR: SSLError
        TR->>T: handshake without verification
        T-->>TR: certificate
        Note over TR: the anomalous certificate<br/>is the finding, not an error
    end
    TR-->>IN: certificate dictionary
    deactivate TR
    IN->>TH: release slot
    IN->>IN: parse_certificate:<br/>dates, SANs, days remaining
    IN-->>IH: TlsInfo
    deactivate IN
```

## 4.6 Scan lifecycle

```mermaid
stateDiagram-v2
    [*] --> Validation
    Validation --> Terminated : invalid arguments (exit 1 or 2)
    Validation --> DnsResolution : configuration built

    DnsResolution --> Enumeration
    Enumeration --> HttpProbe
    HttpProbe --> TlsInspection
    TlsInspection --> PortScan
    PortScan --> Rendering
    Rendering --> Terminated : exit 0

    DnsResolution --> Interrupted : Ctrl-C
    Enumeration --> Interrupted : Ctrl-C
    HttpProbe --> Interrupted : Ctrl-C
    TlsInspection --> Interrupted : Ctrl-C
    Interrupted --> Terminated : exit 130

    Terminated --> [*]
```

Every phase is entered even when its module is disabled: in that case it
produces no results and hands control straight to the next one. The
`Interrupted` state writes no report files.

## 4.7 Concurrency model

The system uses a single event loop in a single process. Parallelism is
cooperative and lives entirely within individual phases, never across them.

```mermaid
graph TB
    subgraph seq["Sequential — scan phases"]
        F1["DNS"] --> F2["Subdomains"] --> F3["HTTP"] --> F4["TLS"] --> F5["Ports"]
    end

    subgraph par["Parallel — within each phase"]
        direction LR
        C1["coroutine 1"]
        C2["coroutine 2"]
        C3["coroutine N"]
    end

    subgraph limit["Cross-cutting constraint"]
        TH["Throttle<br/>semaphore + token bucket"]
    end

    F3 -.-> par
    C1 --> TH
    C2 --> TH
    C3 --> TH

    style seq fill:#fff4e6
    style par fill:#f3f0ff
    style limit fill:#ffe3e3
```

**Why phases stay sequential.** Each phase depends on the previous one's output:
without subdomains there is no way to know which hosts to probe, and without the
HTTP responses no way to know whose certificate to inspect. Parallelising them
would mean probing hosts not yet discovered.

**Why in-phase parallelism is bounded.** Every coroutine passes through the
`Throttle` before each outbound call. The semaphore limits how many requests are
in flight, the token bucket how many start per second. With `-c 5 -r 10` the
system never exceeds five simultaneous requests nor ten per second, however many
hosts are queued.

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

The system distinguishes three levels of failure, with different destinations.

```mermaid
flowchart TD
    E["An error occurs"] --> T{"What kind?"}

    T -->|"Failure of a single<br/>network operation"| L1["Recorded in the error field<br/>of that specific result"]
    T -->|"Failure affecting<br/>a whole phase"| L2["Appended to<br/>ScanReport.errors"]
    T -->|"Violated precondition<br/>or programming error"| L3["Propagated: SystemExit<br/>or traceback"]

    L1 --> R["The scan continues"]
    L2 --> R
    L3 --> S["The process terminates"]

    R --> O["Report produced,<br/>possibly partial — exit 0"]
    S --> X["No report — exit 1, 2 or 130"]

    style L1 fill:#ebfbee
    style L2 fill:#fff4e6
    style L3 fill:#ffe3e3
```

| Level | Examples | Destination | Effect |
| --- | --- | --- | --- |
| Operation | Unreachable host, HTTP timeout, port 443 closed, unreadable certificate | `HttpResult.error`, `TlsInfo.error` | That single result carries the error; other hosts are unaffected. |
| Phase | No DNS records resolved, crt.sh unreachable | `ScanReport.errors` or an empty set | The phase produces no data; later phases proceed on what is available. |
| Process | Non-existent module, missing wordlist, malformed ports, Ctrl-C | `SystemExit`, `KeyboardInterrupt` | The process terminates before or during the scan, writing no report. |

The third level's preconditions are checked **before** any network traffic
starts: a typo must not cost the user a full scan with an unexpected result.

## 4.9 Indicative timing profile

Measurements taken against `example.com` and `iana.org` from a home connection,
as an order of magnitude.

| Configuration | Hosts resolved | Duration |
| --- | --- | --- |
| `-m dns,http,tls --no-passive` | 1 | ~1 s |
| `-m subdomains` with a 138-entry wordlist and crt.sh | 15 | ~13 s |
| `-m ports` over 3 ports | 1 | ~1 s |

The dominant factor is the number of candidates to resolve, not the number of
enabled modules. With `--rate` set, the duration has a lower bound by
construction of the token bucket: `n` requests at `r` per second cannot complete
in less than `n / r` seconds.

## 4.10 Verification strategy

```mermaid
graph LR
    subgraph offline["Automated suite — 84 tests, ~0.4 s, no network"]
        U1["Pure logic<br/>parsing, signatures, dates"]
        U2["Components<br/>Throttle, report"]
        U3["Orchestration<br/>stubbed modules"]
    end

    subgraph manual["Manual verification on authorised targets"]
        M1["example.com<br/>DNS, HTTP, TLS"]
        M2["iana.org<br/>passive enumeration"]
    end

    offline --> CI["CI: Python 3.10–3.13<br/>ruff + pytest"]

    style offline fill:#ebfbee
    style manual fill:#e7f5ff
```

The automated suite makes no network calls: I/O functions are replaced by stubs
in `tests/test_scanner.py`, and everything else is pure logic. This keeps the
tests deterministic, runnable offline and free of traffic towards third-party
systems — a non-negotiable requirement for the CI of a security tool.
