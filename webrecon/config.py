"""Runtime configuration for a scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443]

USER_AGENT = "webrecon/0.1 (+https://github.com/ipavon/web-recon)"


@dataclass
class ScanConfig:
    target: str
    wordlist: Path | None = None
    concurrency: int = 20
    rate_per_second: float = 0.0
    timeout: float = 5.0
    modules: set[str] = field(default_factory=lambda: {"dns", "subdomains", "http", "tls"})
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    passive: bool = True
    max_subdomains: int = 200
    user_agent: str = USER_AGENT
    verify_tls: bool = False

    def enabled(self, module: str) -> bool:
        return module in self.modules
