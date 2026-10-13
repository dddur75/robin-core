from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Any

import pytest

from robin.capture.contracts import CaptureContractError
from robin.capture.live_transport import (
    LiveTransportError,
    PublicProviderRequestV1,
    StrictHttpsTransport,
    _PinnedAddressHttpsConnection,
)
from tests.capture.transport_fixtures import (
    BASE,
    SECRET,
    FakeConnection,
    FakeResponse,
    FakeSocket,
    request,
)


@pytest.mark.parametrize(
    ("raw_peer", "wrapped_peer"),
    (
        ("8.8.8.8", "1.1.1.1"),
        ("1.1.1.1", "8.8.8.8"),
    ),
)
def test_pinned_connection_rejects_raw_or_tls_peer_ip_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    raw_peer: str,
    wrapped_peer: str,
) -> None:
    class SyntheticSocket:
        def __init__(self, peer: str) -> None:
            self.peer = peer
            self.close_calls = 0

        def settimeout(self, _value: float) -> None:
            pass

        def connect(self, _endpoint: tuple[object, ...]) -> None:
            pass

        def getpeername(self) -> tuple[str, int]:
            return self.peer, 443

        def close(self) -> None:
            self.close_calls += 1

    class SyntheticTlsContext:
        post_handshake_auth = False

        def __init__(self, wrapped: SyntheticSocket) -> None:
            self.wrapped = wrapped

        def wrap_socket(
            self,
            _raw_socket: SyntheticSocket,
            *,
            server_hostname: str | None,
        ) -> SyntheticSocket:
            assert server_hostname == "api.the-odds-api.com"
            return self.wrapped

    def forbidden_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("PINNED_CONNECTION_MUST_NOT_RESOLVE_OR_CREATE_BY_HOSTNAME")

    raw_socket = SyntheticSocket(raw_peer)
    wrapped_socket = SyntheticSocket(wrapped_peer)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_resolution)
    monkeypatch.setattr(socket, "create_connection", forbidden_resolution)
    monkeypatch.setattr(socket, "socket", lambda *_args: raw_socket)
    connection = _PinnedAddressHttpsConnection(
        host="api.the-odds-api.com",
        approved_ip_address="1.1.1.1",
        port=443,
        timeout=10.0,
        context=SyntheticTlsContext(wrapped_socket),
        monotonic=lambda: 0.0,
        started=0.0,
    )

    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_PEER_IP_MISMATCH"):
        connection.connect()

    if raw_peer != "1.1.1.1":
        assert raw_socket.close_calls == 1
        assert wrapped_socket.close_calls == 0
    else:
        assert raw_socket.close_calls == 0
        assert wrapped_socket.close_calls == 1
    assert connection.sock is None


def test_pinned_transport_keeps_canonical_host_header_before_rejecting_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("PINNED_TRANSPORT_MUST_NOT_RESOLVE_OR_CREATE_BY_HOSTNAME")

    connection = FakeConnection(FakeResponse())
    connection.sock = FakeSocket("8.8.8.8")
    factory_calls: list[tuple[str, str]] = []

    def factory(
        host: str,
        approved_ip_address: str,
        *_args: object,
    ) -> FakeConnection:
        factory_calls.append((host, approved_ip_address))
        return connection

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_resolution)
    monkeypatch.setattr(socket, "create_connection", forbidden_resolution)
    transport = StrictHttpsTransport(clock=lambda: BASE, connection_factory=factory)
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_PEER_IP_MISMATCH"):
        transport.dispatch(public_request, api_key=SECRET)

    assert factory_calls == [("api.the-odds-api.com", "1.1.1.1")]
    assert connection.requests[0][2]["Host"] == "api.the-odds-api.com"
    assert connection.close_calls == 1


def test_strict_transport_is_one_direct_tls_get_without_proxy_redirect_or_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic-proxy.invalid:9999")
    response = FakeResponse(
        status=302,
        payload=b"[]",
        headers=[
            ("Location", "https://malicious.invalid/redirect"),
            ("Authorization", "must-not-be-retained"),
            ("X-Requests-Last", "2"),
        ],
    )
    connection = FakeConnection(response)
    factory_calls: list[tuple[str, str, int, float, ssl.SSLContext, Any, float]] = []

    def factory(
        host: str,
        approved_ip_address: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
        monotonic: Any,
        started: float,
    ) -> FakeConnection:
        factory_calls.append(
            (host, approved_ip_address, port, timeout, context, monotonic, started)
        )
        return connection

    transport = StrictHttpsTransport(clock=lambda: BASE, connection_factory=factory)
    public_request = request()
    transport.preflight(public_request)
    result = transport.dispatch(public_request, api_key=SECRET)

    assert len(factory_calls) == 1
    host, approved_ip_address, port, timeout, context, _monotonic, started = factory_calls[0]
    assert (host, approved_ip_address, port, timeout) == (
        "api.the-odds-api.com",
        "1.1.1.1",
        443,
        10.0,
    )
    assert isinstance(started, float)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert len(connection.requests) == 1
    method, target, headers = connection.requests[0]
    assert method == "GET"
    assert target.startswith("/v4/sports/soccer_epl/odds?")
    assert "apiKey=" in target and SECRET not in result.headers.values()
    assert headers == {
        "Accept": "application/json",
        "Connection": "close",
        "Host": "api.the-odds-api.com",
    }
    assert result.http_status == 302
    assert result.headers == {"location": "PRESENT", "x-requests-last": "2"}
    assert result.retries == result.redirects == 0
    assert connection.close_calls == 1
    assert response.read_amounts == [1025]


def test_strict_transport_revalidates_constructed_requests_and_tls() -> None:
    forged = PublicProviderRequestV1.model_construct(
        **{
            **request().model_dump(),
            "host": "attacker.invalid",
            "port": 8443,
        }
    )
    calls = 0

    def factory(*_args: object) -> FakeConnection:
        nonlocal calls
        calls += 1
        return FakeConnection(FakeResponse())

    with pytest.raises(LiveTransportError, match="LIVE_PUBLIC_REQUEST_INVALID"):
        StrictHttpsTransport(clock=lambda: BASE, connection_factory=factory).preflight(forged)
    assert calls == 0

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(LiveTransportError, match="TLS_VERIFICATION_REQUIRED"):
        StrictHttpsTransport(
            clock=lambda: BASE,
            connection_factory=factory,
            ssl_context_factory=lambda: context,
        ).preflight(request())
    assert calls == 0


@pytest.mark.parametrize("value", (True, 10.0, "10"))
def test_public_request_integer_limits_are_never_coerced(value: object) -> None:
    material = request().model_dump(mode="json")
    material["timeout_seconds"] = value
    with pytest.raises(CaptureContractError):
        PublicProviderRequestV1.model_validate(material)


def test_transport_failure_is_not_retried_and_secret_echo_is_rejected() -> None:
    failing = FakeConnection(FakeResponse(), fail=True)
    factory_calls = 0

    def failing_factory(*_args: object) -> FakeConnection:
        nonlocal factory_calls
        factory_calls += 1
        return failing

    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=failing_factory,
    )
    public_request = request()
    transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_DISPATCH_FAILED"):
        transport.dispatch(public_request, api_key=SECRET)
    assert factory_calls == 1
    assert len(failing.requests) == 1

    echo = FakeConnection(FakeResponse(payload=f'{{"message":"apiKey={SECRET}"}}'.encode()))
    echo_transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: echo,
    )
    public_request = request()
    echo_transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match="LIVE_PROVIDER_SECRET_ECHO_REJECTED"):
        echo_transport.dispatch(public_request, api_key=SECRET)
    assert len(echo.requests) == 1


@pytest.mark.parametrize(
    ("headers", "secret", "expected"),
    [
        (
            [("X-Requests-Remaining", "1234567890123456")],
            "1234567890123456",
            "LIVE_PROVIDER_SECRET_ECHO_REJECTED",
        ),
        (
            [("Content-Encoding", "gzip")],
            SECRET,
            "LIVE_TRANSPORT_CONTENT_ENCODING_FORBIDDEN",
        ),
        (
            [
                ("X-Requests-Last", "2"),
                ("x-requests-last", "3"),
            ],
            SECRET,
            "LIVE_TRANSPORT_DUPLICATE_CONTROL_HEADER",
        ),
    ],
)
def test_transport_rejects_header_echo_compression_and_ambiguous_quota(
    headers: list[tuple[str, str]],
    secret: str,
    expected: str,
) -> None:
    connection = FakeConnection(FakeResponse(headers=headers))
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
    )
    public_request = request()
    transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match=expected):
        transport.dispatch(public_request, api_key=secret)
    assert len(connection.requests) == 1
    assert connection.close_calls == 1


@pytest.mark.parametrize(
    "control_header",
    ("X-Requests-Last", "X-Requests-Used", "X-Requests-Remaining"),
)
def test_transport_redacts_significant_secret_prefixes_from_control_headers(
    control_header: str,
) -> None:
    secret_prefix = SECRET[:15]
    connection = FakeConnection(
        FakeResponse(payload=b"[]", headers=[(control_header, secret_prefix)])
    )
    observed: list[tuple[bytes, bool, dict[str, str]]] = []
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
        on_response=lambda response, complete: observed.append(
            (response.payload, complete, dict(response.headers))
        ),
    )
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(LiveTransportError, match="LIVE_PROVIDER_SECRET_ECHO_REJECTED"):
        transport.dispatch(public_request, api_key=SECRET)

    assert observed == [
        (
            b"",
            False,
            {
                "x-robin-redacted-body-bytes": "2",
                "x-robin-redacted-body-sha256": hashlib.sha256(b"[]").hexdigest(),
                "x-robin-redaction-reason": "LIVE_PROVIDER_SECRET_ECHO_REJECTED",
            },
        )
    ]
    assert secret_prefix not in repr(observed)
    assert connection.close_calls == 1

