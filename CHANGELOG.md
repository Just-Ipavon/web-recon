# Changelog

## [Unreleased]

### Changed

- `complete` is `false` also when a module failed (any entry in `errors`) or an
  in-scope host never answered (all HTTP attempts or the TLS handshake timed
  out); `incomplete_reason` says which. A refused connection still counts as
  an answer.
- Hosts named by the target's MX and NS records join the subdomain candidates
  (sources `mx` and `ns`) when they are in scope.
- HTTP results separate `findings` (weaknesses) from `notes` (context). An
  out-of-scope redirect that is not followed is now a note, and missing
  security headers are no longer reported on such redirects or on placeholder
  pages (default server pages, parked domains, coming-soon and empty pages).
- Every host is tested on both HTTPS and HTTP: the first scheme that answers is
  probed in full and the other checked with one request; `HttpResult.schemes`
  records both outcomes. On default ports, a site served over HTTP only or
  plain HTTP serving content without redirecting to HTTPS is a finding.
- New `HttpResult` fields: `notes`, `schemes`, `timed_out`.

## [0.2.2] - 2026-11-17

### Changed

- `-o` and `--html` take an optional path. Without one, reports go to
  `reports/<target>.json` and `reports/<target>.html`, one file per target; a
  path ending in `/` or naming a directory gets the same per-target layout.

### Fixed

- HTML report tables no longer split short labels in the first column.

## [0.2.1] - 2026-11-17

### Changed

- Published on PyPI as `webrecon-cli` (`pipx install webrecon-cli`); the name
  `webrecon` on PyPI belongs to an unrelated project. The command and the
  Python package are still called `webrecon`.
- Each release is now also uploaded to PyPI through Trusted Publishing, and the
  release workflow can be started by hand with the tag as input.
- Install instructions in the README work in any shell (fish, csh, PowerShell).

## [0.2.0] - 2026-11-16

### Security and scope

- Scope enforcement: `--scope` / `--scope-file` (domains and CIDRs), defaulting to
  the target and its subdomains. Out-of-scope hosts, including redirect targets,
  are listed as skipped instead of being contacted (#13).
- Loopback, private and link-local addresses are refused unless `--allow-private` (#13).
- Active modules require `--i-have-authorization` or an interactive confirmation;
  operator, time and scope are recorded in the report (#13).
- `Set-Cookie` and `Authorization` values are redacted, report files are created
  with mode 0600 and not overwritten without `--force`, and the HTML report carries
  a restrictive Content-Security-Policy (#12, #16).

### Fixed

- TLS: self-signed, expired and mismatched certificates are reported in full, with
  the verification failure reason; `notBefore` is checked and IP SANs kept (#4).
- `--rate` now applies to every module through one shared throttle (#6).
- One failing stage no longer aborts the scan; Ctrl-C or a crash writes a partial
  report marked incomplete (#7).
- Target parsing handles IPv6, `host:port`, IDN and URLs; invalid options exit with
  status 2 before any network activity (#8).
- The subdomain wordlist ships inside the package and is used by default (#9).
- Wildcard-DNS detection, apex always kept, hostname validation for crt.sh and
  wordlist entries, public suffixes rejected, DNS errors told apart (#10).
- Fewer false positives in content discovery, technology detection and title
  extraction (#11).
- Errors, unreachable hosts and skipped hosts appear in every report format (#12).

### Added

- `--max-time`, `--max-requests-per-host` and incremental `--jsonl` output (#14).
- `host:port` targets, open web ports probed over HTTP/TLS, security-header and
  cookie-flag findings, `--banners`, CAA and SPF/DMARC/DKIM hints, `--axfr`, TLS
  protocol, cipher and trust status (#15).
- `--version`, several targets and `-iL`, `--verify-tls`, `--proxy`, `--user-agent`,
  `--json`, `--fail-if-unreachable` (exit 3), `--resolver`, `--no-wordlist` (#16).
- Loopback HTTP/TLS/DNS test fixtures, mypy, wheel smoke test, pip-audit and
  Dependabot in CI (#17).

### Changed

- New dependency: `cryptography>=42`.
- The port scan runs before HTTP so open web ports feed the HTTP and TLS stages.

## [0.1.0] - 2026-07-27

- First release: DNS records, subdomain enumeration, HTTP fingerprinting, TLS
  inspection, TCP port scan, JSON/terminal/HTML reports.

[0.2.2]: https://github.com/Just-Ipavon/web-recon/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Just-Ipavon/web-recon/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Just-Ipavon/web-recon/compare/7d11318...v0.2.0
[0.1.0]: https://github.com/Just-Ipavon/web-recon/tree/7d11318
