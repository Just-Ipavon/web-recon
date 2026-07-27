"""TLS certificate inspection.

Certificates are fetched with verification disabled on purpose: an expired or
mismatched certificate is exactly the finding worth reporting, so refusing the
handshake would hide it.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..models import TlsInfo
from ..ratelimit import Throttle

CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _flatten_name(name: Any) -> str | None:
    """Turn the nested tuple form Python uses for X.509 names into a string."""
    if not name:
        return None
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None


def parse_certificate(cert: dict[str, Any], host: str, port: int) -> TlsInfo:
    """Convert a peer certificate dict into a TlsInfo, computing expiry."""
    info = TlsInfo(host=host, port=port, valid=False)
    info.issuer = _flatten_name(cert.get("issuer"))
    info.subject = _flatten_name(cert.get("subject"))
    info.san = sorted(
        value for kind, value in cert.get("subjectAltName", ()) if kind.lower() == "dns"
    )

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")

    for raw, attr in ((not_before, "not_before"), (not_after, "not_after")):
        if not raw:
            continue
        try:
            parsed = datetime.strptime(raw, CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            setattr(info, attr, raw)
            continue
        setattr(info, attr, parsed.isoformat(timespec="seconds"))
        if attr == "not_after":
            delta = parsed - datetime.now(timezone.utc)
            info.days_until_expiry = delta.days
            info.valid = delta.total_seconds() > 0

    return info


def _fetch_certificate(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Retrieve a peer certificate as a dict, verifying only to populate fields.

    A first pass runs with full verification so ``getpeercert()`` returns the
    parsed dict. If that handshake fails (self-signed, expired, hostname
    mismatch) the retry disables verification and reports what it finds.
    """
    for verify in (True, False):
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    if cert:
                        return cert
        except ssl.SSLError:
            continue
    return {}


async def inspect(
    host: str, port: int = 443, timeout: float = 5.0, throttle: Throttle | None = None
) -> TlsInfo:
    """Inspect the TLS certificate served by host:port."""
    throttle = throttle or Throttle(1)
    try:
        async with throttle:
            cert = await asyncio.to_thread(_fetch_certificate, host, port, timeout)
    except (TimeoutError, OSError) as exc:
        return TlsInfo(host=host, port=port, valid=False, error=str(exc))

    if not cert:
        return TlsInfo(
            host=host, port=port, valid=False, error="no certificate retrieved"
        )
    return parse_certificate(cert, host, port)


async def inspect_hosts(
    hosts: list[str], timeout: float = 5.0, concurrency: int = 10
) -> list[TlsInfo]:
    throttle = Throttle(concurrency)
    return list(await asyncio.gather(*(inspect(h, 443, timeout, throttle) for h in hosts)))
