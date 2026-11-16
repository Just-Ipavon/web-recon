"""Security-header and cookie-flag analysis of an HTTP response."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

HSTS_MIN_SECONDS = 180 * 24 * 3600


def cookie_attributes(raw: str) -> tuple[str, set[str], dict[str, str]]:
    """Split a Set-Cookie value into (name, flag attributes, valued attributes)."""
    pair, *attrs = raw.split(";")
    name = pair.split("=", 1)[0].strip()
    flags: set[str] = set()
    values: dict[str, str] = {}
    for attr in attrs:
        key, sep, value = attr.strip().partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if sep:
            values[key] = value.strip().lower()
        else:
            flags.add(key)
    return name, flags, values


def analyse(headers: Mapping[str, str], cookies: Iterable[str], https: bool) -> list[str]:
    """Return human-readable findings for missing or weak protections."""
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[str] = []

    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            findings.append("missing Strict-Transport-Security")
        else:
            match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
            if not match or int(match.group(1)) < HSTS_MIN_SECONDS:
                findings.append("Strict-Transport-Security max-age below 180 days")

    csp = h.get("content-security-policy")
    if not csp:
        findings.append("missing Content-Security-Policy")
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append("missing X-Content-Type-Options: nosniff")
    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp.lower()):
        findings.append("missing X-Frame-Options or CSP frame-ancestors (clickjacking)")
    if "referrer-policy" not in h:
        findings.append("missing Referrer-Policy")

    for raw in cookies:
        name, flags, values = cookie_attributes(raw)
        if not name:
            continue
        missing = []
        if https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in values:
            missing.append("SameSite")
        elif values["samesite"] == "none" and "secure" not in flags:
            missing.append("Secure (required by SameSite=None)")
        if missing:
            findings.append(f"cookie {name} without {', '.join(missing)}")

    return findings
