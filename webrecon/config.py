"""Runtime configuration for a scan."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:
        from importlib.abc import Traversable


DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443]

# Ports on which an open TCP port is worth an HTTP(S) probe and, for the TLS
# ones, a certificate inspection.
WEB_PORTS = (80, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9443)

USER_AGENT = f"webrecon/{__version__} (+https://github.com/Just-Ipavon/web-recon)"

BUNDLED_WORDLIST_NAME = "subdomains-small.txt"


def bundled_wordlist() -> Traversable:
    """The wordlist shipped inside the package, usable from any install."""
    return resources.files("webrecon") / "data" / BUNDLED_WORDLIST_NAME


@dataclass
class ScanConfig:
    target: str
    port: int | None = None
    scheme: str | None = None
    wordlist: Path | Traversable | None = None
    concurrency: int = 20
    rate_per_second: float = 0.0
    timeout: float = 5.0
    modules: set[str] = field(default_factory=lambda: {"dns", "subdomains", "http", "tls"})
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    passive: bool = True
    max_subdomains: int = 200
    user_agent: str = USER_AGENT
    verify_tls: bool = False
    proxy: str | None = None
    scope: list[str] = field(default_factory=list)
    allow_private: bool = False
    max_time: float | None = None
    max_requests_per_host: int = 0
    banners: bool = False
    axfr: bool = False
    redact: bool = True
    nameservers: list[str] = field(default_factory=list)
    dns_port: int = 53

    def enabled(self, module: str) -> bool:
        return module in self.modules
