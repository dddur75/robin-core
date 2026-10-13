from __future__ import annotations

import http.client
import socket
from typing import Any

import pytest

from robin.capture.live_transport import (
    LiveTransportError,
    _DeadlineSocketAdapter,
    _PinnedAddressHttpsConnection,
    _remaining_dispatch_seconds,
)


@pytest.mark.parametrize(
    ("approved_ip_address", "expected_family", "expected_endpoint"),
    (
        ("1.1.1.1", socket.AF_INET, ("1.1.1.1", 443)),
        (
            "2606:4700:4700::1111",
            socket.AF_INET6,
            ("2606:4700:4700::1111", 443, 0, 0),
        ),
    ),
)
def test_pinned_connection_uses_direct_ip_socket_canonical_sni_and_deadline(
    monkeypatch: pytest.MonkeyPatch,
    approved_ip_address: str,
    expected_family: int,
    expected_endpoint: tuple[object, ...],
) -> None:
    class SyntheticSocket:
        def __init__(self, peer_ip_address: str) -> None:
            self.peer_ip_address = peer_ip_address
            self.timeouts: list[float] = []
            self.endpoints: list[tuple[object, ...]] = []
            self.close_calls = 0

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def connect(self, endpoint: tuple[object, ...]) -> None:
            self.endpoints.append(endpoint)

        def getpeername(self) -> tuple[str, int]:
            return self.peer_ip_address, 443

        def close(self) -> None:
            self.close_calls += 1

    class SyntheticTlsContext:
        post_handshake_auth = False

        def __init__(self, wrapped: SyntheticSocket) -> None:
            self.wrapped = wrapped
            self.wrap_calls: list[tuple[SyntheticSocket, str | None]] = []

        def wrap_socket(
            self,
            raw_socket: SyntheticSocket,
            *,
            server_hostname: str | None,
        ) -> SyntheticSocket:
            self.wrap_calls.append((raw_socket, server_hostname))
            return self.wrapped

    def forbidden_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("PINNED_CONNECTION_MUST_NOT_RESOLVE_OR_CREATE_BY_HOSTNAME")

    socket_calls: list[tuple[int, int, int]] = []
    raw_socket = SyntheticSocket(approved_ip_address)
    wrapped_socket = SyntheticSocket(approved_ip_address)

    def socket_factory(family: int, kind: int, protocol: int) -> SyntheticSocket:
        socket_calls.append((family, kind, protocol))
        return raw_socket

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_resolution)
    monkeypatch.setattr(socket, "create_connection", forbidden_resolution)
    monkeypatch.setattr(socket, "socket", socket_factory)
    context = SyntheticTlsContext(wrapped_socket)
    ticks = iter((1.0, 3.0, 6.0))
    connection = _PinnedAddressHttpsConnection(
        host="api.the-odds-api.com",
        approved_ip_address=approved_ip_address,
        port=443,
        timeout=10.0,
        context=context,
        monotonic=lambda: next(ticks),
        started=0.0,
    )

    connection.connect()

    assert socket_calls == [(expected_family, socket.SOCK_STREAM, socket.IPPROTO_TCP)]
    assert raw_socket.endpoints == [expected_endpoint]
    assert raw_socket.timeouts == [9.0, 7.0]
    assert wrapped_socket.timeouts == [4.0]
    assert context.wrap_calls == [(raw_socket, "api.the-odds-api.com")]
    assert getattr(connection.sock, "_network_socket") is wrapped_socket


def test_http_status_and_headers_share_one_absolute_recv_deadline() -> None:
    class SlowHeaderSocket:
        def __init__(self) -> None:
            self.payload = memoryview(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            self.offset = 0
            self.timeouts: list[float] = []

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def recv_into(self, buffer: Any) -> int:
            if self.offset >= len(self.payload):
                return 0
            buffer[:1] = self.payload[self.offset : self.offset + 1]
            self.offset += 1
            return 1

        def close(self) -> None:
            pass

    ticks = iter((0.0, 0.4, 0.8, 1.2))
    slow_socket = SlowHeaderSocket()
    adapter = _DeadlineSocketAdapter(
        slow_socket,
        lambda: _remaining_dispatch_seconds(
            started=0.0,
            timeout_seconds=1.0,
            monotonic=lambda: next(ticks),
        ),
    )
    response = http.client.HTTPResponse(adapter, method="GET")

    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED"):
        response.begin()

    assert slow_socket.offset == 3
    assert slow_socket.timeouts == pytest.approx([1.0, 0.6, 0.2])


def test_connection_close_keeps_socket_alive_until_http_response_reader_closes() -> None:
    body = b"x" * 20_000

    class SegmentedSocket:
        def __init__(self) -> None:
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Connection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )
            self.response = memoryview(response)
            self.offset = 0
            self.closed = False
            self.close_calls = 0
            self.timeouts: list[float] = []

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def sendall(self, _data: bytes, _flags: int = 0) -> None:
            if self.closed:
                raise OSError(9, "synthetic closed socket")

        def recv_into(self, buffer: Any) -> int:
            if self.closed:
                raise OSError(9, "synthetic closed socket")
            if self.offset == len(self.response):
                return 0
            amount = min(len(buffer), 8_192, len(self.response) - self.offset)
            buffer[:amount] = self.response[self.offset : self.offset + amount]
            self.offset += amount
            return amount

        def close(self) -> None:
            self.close_calls += 1
            self.closed = True

    network_socket = SegmentedSocket()
    adapter = _DeadlineSocketAdapter(network_socket, lambda: 10.0)
    connection = http.client.HTTPConnection("api.the-odds-api.com")
    connection.sock = adapter
    connection.request("GET", "/v4/sports/soccer_epl/odds")

    response = connection.getresponse()

    assert response.status == 200
    assert response.will_close is True
    assert connection.sock is None
    assert network_socket.closed is False
    assert response.read() == body
    response.close()
    assert network_socket.close_calls == 1


def test_socket_adapter_defers_final_close_until_every_file_lease_is_released() -> None:
    class LeaseSocket:
        def __init__(self) -> None:
            self.close_calls = 0

        def settimeout(self, _value: float) -> None:
            pass

        def recv_into(self, _buffer: Any) -> int:
            return 0

        def close(self) -> None:
            self.close_calls += 1

    network_socket = LeaseSocket()
    adapter = _DeadlineSocketAdapter(network_socket, lambda: 10.0)
    first = adapter.makefile("rb")
    second = adapter.makefile("rb")

    adapter.close()
    assert network_socket.close_calls == 0
    first.close()
    first.close()
    assert network_socket.close_calls == 0
    second.close()
    adapter.close()
    assert network_socket.close_calls == 1


def test_socket_adapter_retries_a_transient_final_close_before_confirming() -> None:
    class FlakyCloseSocket:
        def __init__(self) -> None:
            self.close_calls = 0
            self.closed = False

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError(9, "synthetic transient close failure")
            self.closed = True

    network_socket = FlakyCloseSocket()
    adapter = _DeadlineSocketAdapter(network_socket, lambda: 10.0)

    adapter.close()

    assert network_socket.close_calls == 2
    assert network_socket.closed is True
    assert adapter._network_closed is True

