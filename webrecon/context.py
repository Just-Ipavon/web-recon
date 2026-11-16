"""Shared state handed to every module during one scan."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import ScanConfig
from .models import ScanReport, SkippedHost
from .ratelimit import Throttle
from .targets import Scope

Emit = Callable[[str, Any], None]


def _discard(kind: str, payload: Any) -> None:
    return None


@dataclass
class ScanContext:
    """One throttle, one scope and one report shared by every stage.

    ``emit`` receives each result as soon as it exists (used for incremental
    JSONL output); the report itself is filled in place, so whatever was
    gathered survives a timeout, an interrupt or a crash in a later stage.
    """

    config: ScanConfig
    throttle: Throttle
    scope: Scope
    report: ScanReport
    emit: Emit = field(default=_discard)

    @classmethod
    def create(
        cls, config: ScanConfig, report: ScanReport | None = None, emit: Emit | None = None
    ) -> ScanContext:
        return cls(
            config=config,
            throttle=Throttle(config.concurrency, config.rate_per_second),
            scope=Scope.build(config.target, config.scope, config.allow_private),
            report=report or ScanReport(target=config.target),
            emit=emit or _discard,
        )

    def error(self, message: str) -> None:
        self.report.errors.append(message)
        self.emit("error", message)

    def note(self, message: str) -> None:
        self.report.notes.append(message)
        self.emit("note", message)

    def skip(self, host: str, reason: str) -> None:
        if any(s.host == host for s in self.report.skipped):
            return
        entry = SkippedHost(host=host, reason=reason)
        self.report.skipped.append(entry)
        self.emit("skipped", entry)
