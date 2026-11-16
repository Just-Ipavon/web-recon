"""TLS inspection against loopback servers with bad certificates (issue #4)."""

from __future__ import annotations

from datetime import timedelta

from conftest import free_port

from webrecon.modules import tls_info


class TestInspect:
    async def test_reports_a_self_signed_certificate_in_full(self, tls_server):
        server = tls_server()
        info = await tls_info.inspect("127.0.0.1", server.port, timeout=3)
        assert info.error is None
        assert "CN=localhost" in info.issuer
        assert info.san == ["127.0.0.1", "localhost"]
        assert info.valid is True
        assert info.trusted is False
        assert "self-signed" in info.verify_error or "self signed" in info.verify_error
        assert "self-signed certificate" in info.findings
        assert info.protocol and info.protocol.startswith("TLS")
        assert info.cipher

    async def test_reports_an_expired_certificate(self, tls_server):
        server = tls_server(valid_from=timedelta(days=-30), valid_for=timedelta(days=10))
        info = await tls_info.inspect("127.0.0.1", server.port, timeout=3)
        assert info.not_after is not None
        assert info.valid is False
        assert info.days_until_expiry < 0
        assert any("expired" in f for f in info.findings)

    async def test_reports_a_certificate_that_is_not_yet_valid(self, tls_server):
        server = tls_server(valid_from=timedelta(days=30))
        info = await tls_info.inspect("127.0.0.1", server.port, timeout=3)
        assert info.valid is False
        assert any("not valid until" in f for f in info.findings)

    async def test_reports_a_hostname_mismatch(self, tls_server):
        server = tls_server(common_name="other.test", dns_names=("other.test",), ips=())
        info = await tls_info.inspect("127.0.0.1", server.port, timeout=3)
        assert info.trusted is False
        assert info.san == ["other.test"]
        assert info.verify_error

    async def test_a_closed_port_is_an_error_entry(self):
        info = await tls_info.inspect("127.0.0.1", free_port(), timeout=1)
        assert info.error
        assert info.valid is False

    async def test_an_invalid_hostname_is_an_error_entry(self):
        info = await tls_info.inspect(f"{'a' * 64}.example", 443, timeout=1)
        assert info.error
