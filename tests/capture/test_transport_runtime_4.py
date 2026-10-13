from __future__ import annotations

import ssl
from typing import Any

import pytest

from robin.capture.live_transport import LiveTransportError, StrictHttpsTransport
from tests.capture.transport_fixtures import BASE, FakeConnection, FakeResponse, request


@pytest.mark.parametrize(
    ("variable", "expected"),
    (
        ("SSLKEYLOGFILE", "TLS_KEYLOG_FORBIDDEN"),
        ("SSL_CERT_FILE", "TLS_TRUST_ENV_FORBIDDEN"),
        ("SSL_CERT_DIR", "TLS_TRUST_ENV_FORBIDDEN"),
    ),
)
def test_tls_environment_overrides_are_rejected_before_context_or_connection(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
    expected: str,
) -> None:
    keylog = tmp_path / "tls-keys.log"
    monkeypatch.setenv(variable, str(keylog))
    context_calls = 0
    connection_calls = 0

    def context_factory() -> ssl.SSLContext:
        nonlocal context_calls
        context_calls += 1
        return ssl.create_default_context()

    def connection_factory(*_args: object) -> FakeConnection:
        nonlocal connection_calls
        connection_calls += 1
        return FakeConnection(FakeResponse())

    with pytest.raises(LiveTransportError, match=expected):
        StrictHttpsTransport(
            clock=lambda: BASE,
            connection_factory=connection_factory,
            ssl_context_factory=context_factory,
        ).preflight(request())
    assert context_calls == connection_calls == 0
    assert not keylog.exists()

