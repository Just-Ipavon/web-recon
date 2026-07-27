"""Structured result types shared by every recon module.

Every module returns one of these dataclasses instead of a raw dict, so the
report layer never has to guess at a schema.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class DnsRecords:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Subdomain:
    name: str
    addresses: list[str] = field(default_factory=list)
    source: str = "bruteforce"


@dataclass
class Redirect:
    status: int
    location: str


@dataclass
class HttpResult:
    url: str
    reachable: bool
    status: int | None = None
    title: str | None = None
    server: str | None = None
    content_length: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirects: list[Redirect] = field(default_factory=list)
    final_url: str | None = None
    technologies: list[str] = field(default_factory=list)
    interesting_paths: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class TlsInfo:
    host: str
    port: int
    valid: bool
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    san: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class PortResult:
    port: int
    open: bool
    service: str | None = None


@dataclass
class ScanReport:
    target: str
    started_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None
    dns: DnsRecords | None = None
    subdomains: list[Subdomain] = field(default_factory=list)
    http: list[HttpResult] = field(default_factory=list)
    tls: list[TlsInfo] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
