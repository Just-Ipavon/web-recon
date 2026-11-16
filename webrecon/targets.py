"""Target parsing and scope enforcement.

Every host the tool contacts is checked against one :class:`Scope`, so the
perimeter of a scan is explicit and recorded in the report instead of being
whatever names happen to turn up in certificate logs or redirects.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Registry-controlled suffixes under which unrelated parties register names.
# This is not the full Public Suffix List, only the common multi-label entries
# that a typo or a careless invocation is likely to hit; every single-label
# name (``com``, ``uk``) is rejected separately.
PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
        "co.in", "net.in", "org.in", "co.za", "org.za", "co.il",
        "com.br", "net.br", "org.br", "com.ar", "com.mx", "com.tr", "com.cn",
        "net.cn", "org.cn", "com.hk", "com.sg", "com.tw", "com.ua",
        "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "blogspot.com",
        "cloudfront.net", "azurewebsites.net", "netlify.app", "vercel.app",
        "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    }
)


class TargetError(ValueError):
    """Raised for input that is not a usable scan target."""


def is_valid_hostname(name: str) -> bool:
    """Strict LDH check on an ASCII (punycode) hostname, without a trailing dot."""
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def to_ascii_hostname(name: str) -> str:
    """Lowercase and convert an internationalised name to punycode.

    Raises :class:`TargetError` when a label is empty or longer than 63
    characters, or when the result is not a valid hostname.
    """
    name = name.strip().lower().rstrip(".")
    try:
        ascii_name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError(f"invalid hostname {name!r}: {exc}") from exc
    if not is_valid_hostname(ascii_name):
        raise TargetError(f"invalid hostname {name!r}")
    return ascii_name


@dataclass(frozen=True)
class Target:
    """A parsed target: hostname or IP literal, plus an optional port and scheme."""

    host: str
    port: int | None = None
    scheme: str | None = None

    @property
    def is_ip(self) -> bool:
        return is_ip(self.host)

    def __str__(self) -> str:
        return format_netloc(self.host, self.port)


def format_netloc(host: str, port: int | None = None) -> str:
    shown = f"[{host}]" if ":" in host else host
    return f"{shown}:{port}" if port else shown


def parse_target(value: str) -> Target:
    """Parse a domain, IP literal, ``host:port`` or URL into a :class:`Target`.

    Scheme, credentials, path, query and fragment are dropped; the port is
    kept. IDNs become punycode, bare and bracketed IPv6 literals are accepted,
    and anything that is not a valid hostname, as well as a public suffix such
    as ``com`` or ``co.uk``, is rejected.
    """
    raw = value.strip()
    if not raw:
        raise TargetError("empty target")

    bare = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if is_ip(bare):
        return Target(host=ipaddress.ip_address(bare).compressed)

    try:
        parts = urlsplit(raw if "://" in raw else "//" + raw)
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"invalid target {raw!r}: {exc}") from exc

    scheme = parts.scheme.lower() or None
    if scheme not in (None, "http", "https"):
        raise TargetError(f"unsupported scheme {scheme!r}; use http or https")
    if port == 0:
        raise TargetError("port must be between 1 and 65535")

    host = (parts.hostname or "").strip(".")
    if not host:
        raise TargetError("empty target")
    if is_ip(host):
        return Target(host=ipaddress.ip_address(host).compressed, port=port, scheme=scheme)

    ascii_host = to_ascii_hostname(host)
    if "." not in ascii_host and ascii_host != "localhost":
        raise TargetError(
            f"{ascii_host!r} is a single label (a top-level domain?); give a full domain name"
        )
    if ascii_host in PUBLIC_SUFFIXES:
        raise TargetError(f"{ascii_host!r} is a public suffix, not a domain you can own")
    return Target(host=ascii_host, port=port, scheme=scheme)


def is_restricted_address(address: IPAddress) -> bool:
    """Loopback, private, link-local and other non-public addresses."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
    )


@dataclass
class Scope:
    """The set of names and networks a scan may contact.

    A hostname is in scope when it equals or is a subdomain of one of
    ``domains``; an IP literal when it falls inside one of ``networks``.
    Independently, non-public addresses are refused unless
    ``allow_private`` is set.
    """

    domains: tuple[str, ...] = ()
    networks: tuple[IPNetwork, ...] = ()
    allow_private: bool = False
    explicit: bool = field(default=False, compare=False)

    @classmethod
    def build(
        cls, target: str, entries: Iterable[str] = (), allow_private: bool = False
    ) -> Scope:
        """Scope from explicit entries, defaulting to the target and its subdomains."""
        domains: list[str] = []
        networks: list[IPNetwork] = []
        explicit = False
        for entry in entries:
            for item in entry.split(","):
                item = item.strip()
                if not item or item.startswith("#"):
                    continue
                explicit = True
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                    continue
                except ValueError:
                    pass
                if item.startswith("*."):
                    item = item[2:]
                domains.append(to_ascii_hostname(item))
        if not explicit:
            if is_ip(target):
                networks.append(ipaddress.ip_network(target))
            else:
                domains.append(target)
        return cls(
            domains=tuple(dict.fromkeys(domains)),
            networks=tuple(dict.fromkeys(networks)),
            allow_private=allow_private,
            explicit=explicit,
        )

    def describe(self) -> list[str]:
        out = [f"{d} (and subdomains)" for d in self.domains]
        out += [str(n) for n in self.networks]
        if self.allow_private:
            out.append("private addresses allowed")
        return out

    def allows_name(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if is_ip(host):
            return self.allows_ip_literal(host)
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def allows_ip_literal(self, value: str) -> bool:
        address = ipaddress.ip_address(value)
        return any(address in network for network in self.networks)

    def address_refusal(self, value: str) -> str | None:
        """Why connecting to this address is refused, or None when it is allowed."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if not self.allow_private and is_restricted_address(address):
            return "non-public address (use --allow-private)"
        return None

    def refusal(self, host: str) -> str | None:
        """Why a host must not be contacted, or None when it may be."""
        if not self.allows_name(host):
            return "out of scope"
        return self.address_refusal(host)
