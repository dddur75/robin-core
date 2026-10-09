from __future__ import annotations

import base64
import http.client

import pytest

from robin.capture.live_transport import (
    EnvironmentSecretReader,
    LiveTransportError,
    StrictHttpsTransport,
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
    ("headers", "expected"),
    (
        ([("Content-Length", "100")], "LIVE_TRANSPORT_CONTENT_LENGTH_MISMATCH"),
        ([("Content-Length", "1025")], "LIVE_TRANSPORT_RESPONSE_TOO_LARGE"),
        (
            [("Content-Length", "2"), ("content-length", "2")],
            "LIVE_TRANSPORT_CONTENT_LENGTH_INVALID",
        ),
    ),
)
def test_transport_journals_short_or_ambiguous_content_length_as_incomplete(
    headers: list[tuple[str, str]],
    expected: str,
) -> None:
    connection = FakeConnection(FakeResponse(payload=b"[]", headers=headers))
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

    with pytest.raises(LiveTransportError, match=expected):
        transport.dispatch(public_request, api_key=SECRET)

    assert observed == [(b"[]", False, {})]
    assert connection.close_calls == 1


@pytest.mark.parametrize(
    ("payload", "headers"),
    (
        (
            b'{"message":"synthetic-transport-sec\\u0072et-sentinel"}',
            [],
        ),
        (
            b'{"message":"%73%79%6E%74%68%65%74%69%63%2D%74%72%61%6E%73%70%6F%72%74%2D%73%65%63%72%65%74%2D%73%65%6E%74%69%6E%65%6C"}',
            [],
        ),
        (
            b"[]",
            [
                (
                    "X-Requests-Remaining",
                    "UTF-8''%73%79%6E%74%68%65%74%69%63%2D%74%72%61%6E%73%70%6F%72%74%2D%73%65%63%72%65%74%2D%73%65%6E%74%69%6E%65%6C",
                )
            ],
        ),
        (
            b'{"message":"' + base64.b64encode(SECRET.encode("ascii")) + b'"}',
            [],
        ),
        (
            b'{"message":"' + SECRET.encode("ascii").hex().encode("ascii") + b'"}',
            [],
        ),
        (SECRET.encode("utf-16-le"), []),
    ),
)
def test_transport_rejects_reversibly_encoded_secret_echoes(
    payload: bytes,
    headers: list[tuple[str, str]],
) -> None:
    connection = FakeConnection(FakeResponse(payload=payload, headers=headers))
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
    )
    public_request = request()
    transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match="LIVE_PROVIDER_SECRET_ECHO_REJECTED"):
        transport.dispatch(public_request, api_key=SECRET)
    assert len(connection.requests) == 1
    assert connection.close_calls == 1


def test_transport_enforces_a_total_body_deadline() -> None:
    class SlowResponse(FakeResponse):
        def read1(self, amount: int | None = None) -> bytes:
            self.read_amounts.append(amount)
            return b"["

    ticks = iter((0.0, 0.0, 0.0, 0.0, 11.0))
    connection = FakeConnection(SlowResponse())
    observed: list[tuple[bytes, bool]] = []
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
        monotonic=lambda: next(ticks),
        on_response=lambda response, complete: observed.append((response.payload, complete)),
    )
    public_request = request()
    transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED"):
        transport.dispatch(public_request, api_key=SECRET)
    assert connection.close_calls == 1
    assert observed == [(b"[", False)]


def test_transport_journals_fallback_body_when_final_read_exceeds_deadline() -> None:
    tick = [0.0]

    class SlowFallbackResponse(FakeResponse):
        def read(self, amount: int | None = None) -> bytes:
            self.read_amounts.append(amount)
            tick[0] = 11.0
            return self.payload[:amount]

    connection = FakeConnection(SlowFallbackResponse())
    observed: list[tuple[bytes, bool]] = []
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
        monotonic=lambda: tick[0],
        on_response=lambda response, complete: observed.append((response.payload, complete)),
    )
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(
        LiveTransportError,
        match="LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED",
    ):
        transport.dispatch(public_request, api_key=SECRET)

    assert observed == [(b"[]", False)]
    assert connection.close_calls == 1


def test_transport_journals_incomplete_read_tail_from_chunked_response() -> None:
    class IncompleteResponse(FakeResponse):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def read1(self, amount: int | None = None) -> bytes:
            self.read_amounts.append(amount)
            self.calls += 1
            if self.calls == 1:
                return b"head-"
            raise http.client.IncompleteRead(b"tail", 99)

    connection = FakeConnection(IncompleteResponse())
    observed: list[tuple[bytes, bool]] = []
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
        on_response=lambda response, complete: observed.append((response.payload, complete)),
    )
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_DISPATCH_FAILED"):
        transport.dispatch(public_request, api_key=SECRET)

    assert observed == [(b"head-tail", False)]
    assert connection.close_calls == 1


def test_transport_exposes_only_allowlisted_body_read_diagnostic() -> None:
    class BrokenResponse(FakeResponse):
        def read1(self, _amount: int | None = None) -> bytes:
            raise OSError(
                9,
                f"forbidden https://api.the-odds-api.com/path?apiKey={SECRET}",
            )

    response = BrokenResponse(status=200)
    connection = FakeConnection(response)
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
    )
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(LiveTransportError) as raised:
        transport.dispatch(public_request, api_key=SECRET)

    diagnostic = raised.value.diagnostic
    assert diagnostic is not None
    assert diagnostic.stage == "BODY_READ"
    assert diagnostic.code == "LIVE_TRANSPORT_DISPATCH_FAILED"
    assert diagnostic.exception_class == "OSError"
    assert diagnostic.errno == 9
    assert diagnostic.http_status == 200
    assert str(raised.value) == "LIVE_TRANSPORT_DISPATCH_FAILED"
    assert SECRET not in str(raised.value)
    assert "apiKey" not in str(raised.value)
    assert response.close_calls == 1
    assert connection.close_calls == 1


def test_transport_retries_transient_cleanup_and_returns_only_after_close() -> None:
    class FlakyCloseConnection(FakeConnection):
        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError(9, "synthetic transient connection close failure")

    response = FakeResponse(status=200, payload=b"[]")
    connection = FlakyCloseConnection(response)
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
    )
    public_request = request()
    transport.preflight(public_request)

    result = transport.dispatch(public_request, api_key=SECRET)

    assert result.http_status == 200
    assert response.close_calls == 1
    assert connection.close_calls == 2


def test_transport_fails_closed_when_final_cleanup_cannot_be_confirmed() -> None:
    class FailingCloseResponse(FakeResponse):
        def close(self) -> None:
            self.close_calls += 1
            raise OSError(9, "forbidden close detail")

    class FailingCloseConnection(FakeConnection):
        def close(self) -> None:
            self.close_calls += 1
            raise OSError(9, "forbidden close detail")

    response = FailingCloseResponse(status=200, payload=b"[]")
    connection = FailingCloseConnection(response)
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
    )
    public_request = request()
    transport.preflight(public_request)

    with pytest.raises(LiveTransportError) as raised:
        transport.dispatch(public_request, api_key=SECRET)

    diagnostic = raised.value.diagnostic
    assert raised.value.code == "LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED"
    assert diagnostic is not None
    assert diagnostic.stage == "CONNECTION_CLOSE"
    assert diagnostic.code == "LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED"
    assert diagnostic.exception_class == "OSError"
    assert diagnostic.errno == 9
    assert diagnostic.http_status == 200
    assert response.close_calls == 2
    assert connection.close_calls == 2
    assert "forbidden" not in str(raised.value)
    assert SECRET not in str(raised.value)


def test_complete_body_is_observed_before_duplicate_control_header_rejection() -> None:
    connection = FakeConnection(
        FakeResponse(
            payload=b"[]",
            headers=[("X-Requests-Last", "2"), ("x-requests-last", "3")],
        )
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
    with pytest.raises(LiveTransportError, match="LIVE_TRANSPORT_DUPLICATE_CONTROL_HEADER"):
        transport.dispatch(public_request, api_key=SECRET)
    assert observed == [(b"[]", True, {})]


def test_transport_tightens_socket_timeout_across_headers_and_body_chunks() -> None:
    class ChunkedResponse(FakeResponse):
        def __init__(self) -> None:
            super().__init__()
            self.chunks = iter((b"[", b"]", b""))

        def read1(self, amount: int | None = None) -> bytes:
            self.read_amounts.append(amount)
            return next(self.chunks)

    ticks = iter((0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0))
    connection = FakeConnection(ChunkedResponse())
    connection.sock = FakeSocket()
    transport = StrictHttpsTransport(
        clock=lambda: BASE,
        connection_factory=lambda *_args: connection,
        monotonic=lambda: next(ticks),
    )
    public_request = request()
    transport.preflight(public_request)

    result = transport.dispatch(public_request, api_key=SECRET)

    assert result.payload == b"[]"
    assert connection.sock.timeouts == [9.0, 8.0, 7.0, 5.0, 3.0]


@pytest.mark.parametrize(
    "value",
    ["unicode-é-secret-value", "x" * 129, "short", "has space sentinel"],
)
def test_environment_secret_reader_accepts_only_bounded_ascii_tokens(value: str) -> None:
    with pytest.raises(LiveTransportError, match="LIVE_PROVIDER_SECRET_INVALID"):
        EnvironmentSecretReader({"THE_ODDS_API_KEY": value}).read()


@pytest.mark.parametrize(
    "value",
    ["unicode-é-secret-value", "x" * 129, "short", "has space sentinel"],
)
def test_direct_transport_rejects_invalid_secret_before_connection(value: str) -> None:
    factory_calls = 0

    def factory(*_args: object) -> FakeConnection:
        nonlocal factory_calls
        factory_calls += 1
        return FakeConnection(FakeResponse())

    transport = StrictHttpsTransport(clock=lambda: BASE, connection_factory=factory)
    public_request = request()
    transport.preflight(public_request)
    with pytest.raises(LiveTransportError, match="LIVE_PROVIDER_SECRET_INVALID"):
        transport.dispatch(public_request, api_key=value)
    assert factory_calls == 0

