"""TLS certificate inspection.

A first handshake verifies the chain and the hostname against the system
trust store. If that fails (self-signed, expired, hostname mismatch), the
reason is recorded and a second handshake without verification retrieves the
certificate anyway: an anomalous certificate is exactly the finding worth
reporting, so refusing the handshake would hide it. The certificate is read in
DER form and decoded with ``cryptography``, because ``getpeercert()`` returns
an empty dict when verification is disabled.

Handshakes run on the event loop (no threads), so a timeout or Ctrl-C cancels
them immediately.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from cryptography import x509

from ..context import ScanContext
from ..models import TlsInfo
from ..ratelimit import Throttle

EXPIRY_WARNING_DAYS = 30


def _flatten_name(name: Any) -> str | None:
    """Turn the nested tuple form Python uses for X.509 names into a string."""
    if not name:
        return None
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None


def _x509_name(name: x509.Name) -> str | None:
    parts = [f"{attr.rfc4514_attribute_name}={attr.value!s}" for attr in name]
    return ", ".join(parts) or None


def _apply_validity(
    info: TlsInfo, not_before: datetime | None, not_after: datetime | None
) -> None:
    now = datetime.now(timezone.utc)
    if not_before is not None:
        info.not_before = not_before.isoformat(timespec="seconds")
    if not_after is not None:
        info.not_after = not_after.isoformat(timespec="seconds")
        info.days_until_expiry = (not_after - now).days
    info.valid = (
        not_after is not None
        and now <= not_after
        and (not_before is None or not_before <= now)
    )
    if not_before is not None and now < not_before:
        info.findings.append(f"certificate not valid until {info.not_before}")
    if not_after is not None:
        if now > not_after:
            info.findings.append(f"certificate expired on {info.not_after}")
        elif info.days_until_expiry is not None and info.days_until_expiry < EXPIRY_WARNING_DAYS:
            info.findings.append(f"certificate expires in {info.days_until_expiry} day(s)")


def _parse_cert_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        # cert_time_to_seconds does not depend on the locale, unlike %b.
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), timezone.utc)
    except ValueError:
        return None


def parse_certificate(cert: dict[str, Any], host: str, port: int) -> TlsInfo:
    """Convert a ``getpeercert()`` dict into a TlsInfo, computing validity."""
    info = TlsInfo(host=host, port=port, valid=False)
    info.issuer = _flatten_name(cert.get("issuer"))
    info.subject = _flatten_name(cert.get("subject"))
    info.san = sorted(
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind.lower() in ("dns", "ip address")
    )

    not_before = _parse_cert_time(cert.get("notBefore"))
    not_after = _parse_cert_time(cert.get("notAfter"))
    _apply_validity(info, not_before, not_after)
    # Keep an unparseable date visible rather than dropping it.
    if not_after is None and cert.get("notAfter"):
        info.not_after = str(cert["notAfter"])
    if not_before is None and cert.get("notBefore"):
        info.not_before = str(cert["notBefore"])
    return info


def parse_der(der: bytes, host: str, port: int) -> TlsInfo:
    """Decode a DER certificate into a TlsInfo, computing validity."""
    cert = x509.load_der_x509_certificate(der)
    info = TlsInfo(host=host, port=port, valid=False)
    info.issuer = _x509_name(cert.issuer)
    info.subject = _x509_name(cert.subject)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        names: list[str] = []
    else:
        names = list(san.get_values_for_type(x509.DNSName))
        names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    info.san = sorted(names)
    _apply_validity(info, cert.not_valid_before_utc, cert.not_valid_after_utc)
    if cert.issuer == cert.subject:
        info.findings.append("self-signed certificate")
    return info


HANDSHAKE_TIMEOUT = "TLS handshake timed out"


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return HANDSHAKE_TIMEOUT
    text = str(exc) or type(exc).__name__
    return f"{type(exc).__name__}: {text}"


async def _handshake(
    host: str, port: int, timeout: float, verify: bool
) -> tuple[bytes | None, str | None, str | None]:
    """Connect and complete a TLS handshake; returns (DER, protocol, cipher)."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host, port, ssl=context, server_hostname=host, ssl_handshake_timeout=timeout
        ),
        timeout,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True)
        cipher = ssl_object.cipher()
        return der, ssl_object.version(), cipher[0] if cipher else None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def inspect(
    host: str, port: int = 443, timeout: float = 5.0, throttle: Throttle | None = None
) -> TlsInfo:
    """Inspect the TLS certificate served by host:port. Does not raise network errors."""
    throttle = throttle or Throttle(1)
    verify_error: str | None = None
    try:
        try:
            async with throttle:
                der, protocol, cipher = await _handshake(host, port, timeout, verify=True)
        except ssl.SSLCertVerificationError as exc:
            verify_error = exc.verify_message or str(exc)
            async with throttle:
                der, protocol, cipher = await _handshake(host, port, timeout, verify=False)
    except (ssl.SSLError, OSError, asyncio.TimeoutError, UnicodeError, ValueError) as exc:
        return TlsInfo(host=host, port=port, valid=False, error=describe_error(exc))

    if not der:
        return TlsInfo(host=host, port=port, valid=False, error="no certificate retrieved")
    try:
        info = parse_der(der, host, port)
    except ValueError as exc:
        return TlsInfo(host=host, port=port, valid=False, error=f"unparseable certificate: {exc}")

    info.trusted = verify_error is None
    info.verify_error = verify_error
    info.protocol = protocol
    info.cipher = cipher
    if verify_error:
        reason = f"certificate verification failed: {verify_error}"
        if reason not in info.findings:
            info.findings.insert(0, reason)
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        info.findings.append(f"legacy protocol negotiated: {protocol}")
    return info


async def inspect_hosts(endpoints: Iterable[tuple[str, int]], ctx: ScanContext) -> list[TlsInfo]:
    """Inspect every (host, port) endpoint through the scan's shared throttle."""

    async def one(host: str, port: int) -> TlsInfo:
        reason = ctx.scope.refusal(host)
        if reason:
            ctx.skip(host, reason)
            return TlsInfo(host=host, port=port, valid=False, error=f"skipped: {reason}")
        try:
            info = await inspect(host, port, ctx.config.timeout, ctx.throttle)
        except Exception as exc:  # keep the other hosts' results
            info = TlsInfo(host=host, port=port, valid=False, error=describe_error(exc))
        ctx.emit("tls", info)
        return info

    return list(await asyncio.gather(*(one(h, p) for h, p in endpoints)))
