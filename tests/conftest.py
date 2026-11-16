"""Loopback fixtures: HTTP, TLS and DNS servers on 127.0.0.1 for I/O tests.

Nothing here reaches the internet. Every server binds an ephemeral port on the
loopback interface and is shut down when the test ends.
"""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

Response = tuple[int, list[tuple[str, str]], bytes]


def response(status: int = 200, body: str | bytes = b"", headers=None) -> Response:
    data = body.encode() if isinstance(body, str) else body
    return status, list(headers or []), data


class _Handler(BaseHTTPRequestHandler):
    server: LoopbackHTTPServer

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        path = urlsplit(self.path).path
        self.server.hits.append(self.path)
        self.server.agents.append(self.headers.get("User-Agent", ""))
        status, headers, body = self.server.routes.get(path, self.server.default)
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, routes, default, tls: ssl.SSLContext | None = None) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.routes: dict[str, Response] = dict(routes)
        self.default: Response = default
        self.hits: list[str] = []
        self.agents: list[str] = []
        self.scheme = "https" if tls else "http"
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True)

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"


@pytest.fixture
def http_server() -> Iterator[Callable[..., LoopbackHTTPServer]]:
    """Factory: ``http_server(routes, default=..., tls=None)`` starts a server."""
    servers: list[LoopbackHTTPServer] = []

    def start(routes=None, default=None, tls=None) -> LoopbackHTTPServer:
        server = LoopbackHTTPServer(routes or {}, default or response(404, "not here"), tls)
        threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@dataclass
class CertFiles:
    cert: Path
    key: Path


def make_certificate(
    directory: Path,
    *,
    common_name: str = "localhost",
    dns_names: tuple[str, ...] = ("localhost",),
    ips: tuple[str, ...] = ("127.0.0.1",),
    valid_from: timedelta = timedelta(days=-1),
    valid_for: timedelta = timedelta(days=90),
    name: str = "cert",
) -> CertFiles:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "webrecon tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    start = datetime.now(timezone.utc) + valid_from
    alt_names = [x509.DNSName(n) for n in dns_names] + [
        x509.IPAddress(ip_address(i)) for i in ips
    ]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + valid_for)
    )
    if alt_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_path = directory / f"{name}.pem"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return CertFiles(cert_path, key_path)


def server_context(files: CertFiles) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(files.cert, files.key)
    return context


@pytest.fixture
def tls_server(tmp_path, http_server):
    """Factory: ``tls_server(**certificate options)`` starts an HTTPS server."""

    def start(routes=None, **cert_options) -> LoopbackHTTPServer:
        files = make_certificate(tmp_path, **cert_options)
        return http_server(routes or {"/": response(200, "<title>tls</title>")},
                           tls=server_context(files))

    return start


@dataclass
class FakeDNS:
    """A UDP DNS server answering from a dict, with optional wildcard and SERVFAIL names."""

    records: dict[tuple[str, str], list[str]]
    wildcard_suffix: str | None = None
    wildcard: dict[str, list[str]] = field(default_factory=dict)
    servfail: set[str] = field(default_factory=set)
    queries: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    def _answer(self, name: str, rtype: str) -> tuple[list[str] | None, bool]:
        values = self.records.get((name, rtype))
        known = any(n == name for n, _ in self.records)
        if self.wildcard_suffix and name.endswith("." + self.wildcard_suffix):
            known = True
            if values is None:
                values = self.wildcard.get(rtype)
        return values, known

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            query = dns.message.from_wire(data)
            reply = dns.message.make_response(query)
            question = query.question[0]
            name = question.name.to_text().rstrip(".").lower()
            rtype = dns.rdatatype.to_text(question.rdtype)
            self.queries.append((name, rtype))
            if name in self.servfail:
                reply.set_rcode(dns.rcode.SERVFAIL)
            else:
                values, known = self._answer(name, rtype)
                if values:
                    reply.answer.append(
                        dns.rrset.from_text_list(question.name, 60, "IN", rtype, values)
                    )
                elif not known:
                    reply.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(reply.to_wire(), addr)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def fake_dns() -> Iterator[Callable[..., FakeDNS]]:
    servers: list[FakeDNS] = []

    def start(records, **kwargs) -> FakeDNS:
        server = FakeDNS(records, **kwargs)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def free_port() -> int:
    """A port nothing listens on (bound then released)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
