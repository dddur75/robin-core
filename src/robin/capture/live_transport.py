"""Strict, injectable HTTPS transport for the bounded Odds API canary."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import ipaddress
import os
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol, Self, cast
from urllib.parse import unquote_to_bytes, urlencode

from pydantic import Field, model_validator

from robin.capture.bootstrap_contracts import ProviderNetworkBindingV1
from robin.capture.contracts import (
    ALLOWED_PROVIDER_HOST,
    SECRET_ENV_NAME,
    CaptureContractError,
    FrozenContract,
    ProviderRequestSpec,
    canonical_json_bytes,
    ensure_utc,
)
from robin.capture.live_contracts import LIVE_ALLOWED_SPORT_KEYS, validate_provider_ip_address


@dataclass(frozen=True, slots=True)
class LiveTransportDiagnostic:
    """Allowlisted transport failure metadata safe for durable reporting."""

    stage: str
    code: str
    exception_class: str
    errno: int | None
    http_status: int | None


class LiveTransportError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        diagnostic: LiveTransportDiagnostic | None = None,
    ) -> None:
        self.code = code
        self.diagnostic = diagnostic
        super().__init__(code)


class _PartialResponseReadError(RuntimeError):
    def __init__(
        self,
        payload: bytes,
        *,
        code: str,
        exception_class: str,
        errno: int | None,
    ) -> None:
        self.payload = payload
        self.code = code
        self.exception_class = exception_class
        self.errno = errno
        super().__init__("LIVE_TRANSPORT_PARTIAL_RESPONSE_READ")


def _safe_exception_class(error: BaseException) -> str:
    name = type(error).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) is None:
        return "BaseException"
    return name


def _safe_errno(error: BaseException) -> int | None:
    value = getattr(error, "errno", None)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _safe_http_status(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return None


def _redacted_diagnostic(
    *,
    stage: str,
    code: str,
    error: BaseException,
    http_status: object,
) -> LiveTransportDiagnostic:
    if isinstance(error, _PartialResponseReadError):
        exception_class = error.exception_class
        error_number = error.errno
    else:
        exception_class = _safe_exception_class(error)
        error_number = _safe_errno(error)
    return LiveTransportDiagnostic(
        stage=stage,
        code=code,
        exception_class=exception_class,
        errno=error_number,
        http_status=_safe_http_status(http_status),
    )


class PublicProviderRequestV1(FrozenContract):
    schema_version: Literal["robin-public-provider-request-v1"] = "robin-public-provider-request-v1"
    scheme: Literal["https"] = "https"
    host: Literal["api.the-odds-api.com"] = "api.the-odds-api.com"
    port: Literal[443] = 443
    method: Literal["GET"] = "GET"
    endpoint: str
    sport_key: str
    region: Literal["eu"] = "eu"
    markets: tuple[Literal["h2h", "totals"], ...]
    odds_format: Literal["decimal"] = "decimal"
    date_format: Literal["iso"] = "iso"
    timeout_seconds: int = Field(ge=1, le=30)
    redirects: Literal[0] = 0
    retries: Literal[0] = 0
    certificate_verification_required: Literal[True] = True
    environment_proxy_allowed: Literal[False] = False
    maximum_response_bytes: int = Field(gt=0, le=10_485_760)
    approved_provider_ip_address: str

    @classmethod
    def from_spec(
        cls,
        spec: ProviderRequestSpec,
        *,
        maximum_response_bytes: int,
        approved_provider_ip_address: str,
    ) -> Self:
        return cls(
            endpoint=spec.endpoint,
            sport_key=spec.sport_key,
            region=spec.region,
            markets=spec.markets,
            odds_format=spec.odds_format,
            date_format=spec.date_format,
            timeout_seconds=spec.timeout_seconds,
            maximum_response_bytes=maximum_response_bytes,
            approved_provider_ip_address=approved_provider_ip_address,
        )

    @model_validator(mode="after")
    def validate_public_request(self) -> Self:
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("LIVE_PUBLIC_REQUEST_SPORT_FORBIDDEN")
        if self.endpoint != f"/v4/sports/{self.sport_key}/odds":
            raise ValueError("LIVE_PUBLIC_REQUEST_ENDPOINT_MISMATCH")
        validate_provider_ip_address(self.approved_provider_ip_address)
        return self

    def canonical_public_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class PublicProviderRequestV2(FrozenContract):
    """Successor request carrying the complete, immutable network binding."""

    schema_version: Literal["robin-public-provider-request-v2"] = "robin-public-provider-request-v2"
    scheme: Literal["https"] = "https"
    host: Literal["api.the-odds-api.com"] = "api.the-odds-api.com"
    port: Literal[443] = 443
    method: Literal["GET"] = "GET"
    endpoint: str
    sport_key: str
    region: Literal["eu"] = "eu"
    markets: tuple[Literal["h2h", "totals"], ...]
    odds_format: Literal["decimal"] = "decimal"
    date_format: Literal["iso"] = "iso"
    timeout_seconds: int = Field(ge=1, le=30)
    redirects: Literal[0] = 0
    retries: Literal[0] = 0
    certificate_verification_required: Literal[True] = True
    environment_proxy_allowed: Literal[False] = False
    maximum_response_bytes: int = Field(gt=0, le=10_485_760)
    provider_network_binding: ProviderNetworkBindingV1

    @classmethod
    def from_spec(
        cls,
        spec: ProviderRequestSpec,
        *,
        maximum_response_bytes: int,
        provider_network_binding: ProviderNetworkBindingV1,
    ) -> Self:
        return cls(
            endpoint=spec.endpoint,
            sport_key=spec.sport_key,
            region=spec.region,
            markets=spec.markets,
            odds_format=spec.odds_format,
            date_format=spec.date_format,
            timeout_seconds=spec.timeout_seconds,
            maximum_response_bytes=maximum_response_bytes,
            provider_network_binding=provider_network_binding,
        )

    @model_validator(mode="after")
    def validate_public_request(self) -> Self:
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("LIVE_PUBLIC_REQUEST_SPORT_FORBIDDEN")
        if self.endpoint != f"/v4/sports/{self.sport_key}/odds":
            raise ValueError("LIVE_PUBLIC_REQUEST_ENDPOINT_MISMATCH")
        if self.provider_network_binding.canonical_hostname != self.host:
            raise ValueError("LIVE_PUBLIC_REQUEST_NETWORK_HOST_MISMATCH")
        return self

    @property
    def approved_provider_ip_address(self) -> str:
        return self.provider_network_binding.selected_ip_address

    def canonical_public_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class LiveTransportResponse:
    http_status: int
    headers: Mapping[str, str]
    payload: bytes
    first_observed_at_utc: datetime
    network_calls: int = 1
    provider_calls: int = 1
    retries: int = 0
    redirects: int = 0


class LiveTransport(Protocol):
    def preflight(self, request: PublicProviderRequestV1) -> None: ...

    def dispatch(
        self,
        request: PublicProviderRequestV1,
        *,
        api_key: str,
    ) -> LiveTransportResponse: ...


class LiveTransportV2(Protocol):
    def preflight(self, request: PublicProviderRequestV2) -> None: ...

    def dispatch(
        self,
        request: PublicProviderRequestV2,
        *,
        api_key: str,
    ) -> LiveTransportResponse: ...


class SecretReader(Protocol):
    def read(self) -> str: ...


class EnvironmentSecretReader:
    """The sole production reader for THE_ODDS_API_KEY."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = os.environ if environment is None else environment

    def read(self) -> str:
        value = self._environment.get(SECRET_ENV_NAME)
        if value is None or not value.strip():
            raise LiveTransportError("LIVE_PROVIDER_SECRET_MISSING")
        return validate_provider_secret(value)


def validate_provider_secret(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value) is None:
        raise LiveTransportError("LIVE_PROVIDER_SECRET_INVALID")
    return value


def reject_secret_echo(payload: bytes, secret: str) -> None:
    """Reject reflected credentials before any response bytes can be persisted."""

    secret_bytes = secret.encode("ascii")
    encoded_secrets = {
        secret_bytes,
        secret_bytes.hex().encode("ascii"),
        secret_bytes.hex().upper().encode("ascii"),
        base64.b64encode(secret_bytes),
        base64.urlsafe_b64encode(secret_bytes),
        base64.b64encode(secret_bytes).rstrip(b"="),
        base64.urlsafe_b64encode(secret_bytes).rstrip(b"="),
        secret.encode("utf-16-be"),
        secret.encode("utf-16-le"),
    }
    normalized = payload
    # The provider token alphabet is ASCII.  Decode the reversible encodings most
    # commonly used by URLs, JSON strings, and RFC 5987 headers before comparing.
    # Three bounded passes cover mixed/double encodings without an unbounded parser.
    for _ in range(3):
        percent_decoded = unquote_to_bytes(normalized)
        json_decoded = re.sub(
            rb"\\u00([0-9a-fA-F]{2})",
            lambda match: bytes((int(match.group(1), 16),)),
            percent_decoded,
        )
        if any(encoded and encoded in json_decoded for encoded in encoded_secrets):
            raise LiveTransportError("LIVE_PROVIDER_SECRET_ECHO_REJECTED")
        if json_decoded == normalized:
            return
        normalized = json_decoded


def reject_partial_secret_echo(payload: bytes, secret: str) -> None:
    """Reject significant credential prefixes in an incomplete response body."""

    secret_bytes = secret.encode("ascii")
    encoded_secrets = {
        secret_bytes,
        secret_bytes.hex().encode("ascii"),
        secret_bytes.hex().upper().encode("ascii"),
        base64.b64encode(secret_bytes),
        base64.urlsafe_b64encode(secret_bytes),
        base64.b64encode(secret_bytes).rstrip(b"="),
        base64.urlsafe_b64encode(secret_bytes).rstrip(b"="),
        secret.encode("utf-16-be"),
        secret.encode("utf-16-le"),
    }
    normalized = payload
    for _ in range(3):
        percent_decoded = unquote_to_bytes(normalized)
        json_decoded = re.sub(
            rb"\\u00([0-9a-fA-F]{2})",
            lambda match: bytes((int(match.group(1), 16),)),
            percent_decoded,
        )
        if any(
            encoded[:prefix_length] in json_decoded
            for encoded in encoded_secrets
            for prefix_length in range(min(12, len(encoded)), len(encoded) + 1)
            if encoded
        ):
            raise LiveTransportError("LIVE_PROVIDER_SECRET_ECHO_REJECTED")
        if json_decoded == normalized:
            return
        normalized = json_decoded


def _reject_response_secret_material(
    payload: bytes,
    headers: Mapping[str, str] | list[tuple[str, str]],
    secret: str,
    *,
    body_complete: bool,
) -> None:
    pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
    header_values = "\n".join(str(value) for _name, value in pairs).encode(
        "utf-8",
        errors="replace",
    )
    if len(header_values) > 65_536:
        raise LiveTransportError("LIVE_TRANSPORT_HEADERS_TOO_LARGE")
    reject_secret_echo(payload, secret)
    if not body_complete:
        reject_partial_secret_echo(payload, secret)
    reject_secret_echo(header_values, secret)
    # Control headers are durable evidence too.  A long credential prefix in a
    # header is just as sensitive as the same prefix in a truncated body, even
    # when the HTTP body itself was read completely.
    reject_partial_secret_echo(header_values, secret)


def _reject_unsafe_response_framing(
    headers: Mapping[str, str] | list[tuple[str, str]],
) -> None:
    pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
    content_encoding = tuple(
        value.strip().casefold() for name, value in pairs if name.casefold() == "content-encoding"
    )
    if content_encoding and content_encoding != ("identity",):
        raise LiveTransportError("LIVE_TRANSPORT_CONTENT_ENCODING_FORBIDDEN")


def reject_unsafe_response(
    payload: bytes,
    headers: Mapping[str, str] | list[tuple[str, str]],
    secret: str,
) -> None:
    _reject_response_secret_material(payload, headers, secret, body_complete=True)
    _reject_unsafe_response_framing(headers)


class _HttpResponse(Protocol):
    status: int

    def getheaders(self) -> list[tuple[str, str]]: ...

    def read(self, amount: int | None = None) -> bytes: ...

    def read1(self, amount: int | None = None) -> bytes: ...


class _HttpsConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: object | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _HttpResponse: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[
    [
        str,
        str,
        int,
        float,
        ssl.SSLContext,
        Callable[[], float],
        float,
    ],
    _HttpsConnection,
]

ConnectionFactoryV2 = Callable[
    [
        str,
        str,
        int,
        float,
        ssl.SSLContext,
        Callable[[], float],
        float,
        Callable[[], None],
    ],
    _HttpsConnection,
]


def _close_resource_with_retry(resource: object) -> BaseException | None:
    close = getattr(resource, "close", None)
    if not callable(close):
        return RuntimeError("LIVE_TRANSPORT_CLOSE_UNAVAILABLE")
    last_error: BaseException | None = None
    for _attempt in range(2):
        try:
            close()
            return None
        except BaseException as error:
            last_error = error
    return last_error


def _close_transport_resources(
    response: _HttpResponse | None,
    connection: _HttpsConnection | None,
) -> BaseException | None:
    last_error: BaseException | None = None
    if response is not None:
        last_error = _close_resource_with_retry(response)
    if connection is not None:
        connection_error = _close_resource_with_retry(connection)
        if connection_error is not None:
            last_error = connection_error
    return last_error


class _DeadlineSocketRaw(io.RawIOBase):
    """Raw reader that reapplies one absolute deadline before every recv."""

    def __init__(
        self,
        network_socket: Any,
        remaining: Callable[[], float],
        release_file_lease: Callable[[], None],
    ) -> None:
        super().__init__()
        self._network_socket = network_socket
        self._remaining = remaining
        self._release_file_lease = release_file_lease
        self._file_lease_released = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int | None:
        self._network_socket.settimeout(self._remaining())
        received = self._network_socket.recv_into(buffer)
        if isinstance(received, bool) or not isinstance(received, int) or received < 0:
            raise LiveTransportError("LIVE_TRANSPORT_BODY_INVALID")
        return received

    def close(self) -> None:
        if self._file_lease_released:
            return
        try:
            super().close()
        finally:
            self._file_lease_released = True
            self._release_file_lease()


class _DeadlineSocketAdapter:
    """Socket facade used by http.client for deadline-aware headers and body."""

    def __init__(
        self,
        network_socket: Any,
        remaining: Callable[[], float],
    ) -> None:
        self._network_socket = network_socket
        self._remaining = remaining
        self._open_file_leases = 0
        self._owner_close_requested = False
        self._network_closed = False

    def _close_network_socket_once(self) -> None:
        if self._network_closed:
            return
        close_error = _close_resource_with_retry(self._network_socket)
        if close_error is not None:
            raise close_error
        self._network_closed = True

    def _release_file_lease(self) -> None:
        if self._open_file_leases <= 0:
            return
        self._open_file_leases -= 1
        if self._owner_close_requested and self._open_file_leases == 0:
            self._close_network_socket_once()

    def sendall(self, data: Any, flags: int = 0) -> None:
        self._network_socket.settimeout(self._remaining())
        if flags:
            self._network_socket.sendall(data, flags)
        else:
            self._network_socket.sendall(data)

    def makefile(
        self,
        mode: str = "r",
        buffering: int | None = None,
        *_args: Any,
        **_kwargs: Any,
    ) -> io.BufferedReader:
        if mode != "rb" or buffering == 0:
            raise LiveTransportError("LIVE_TRANSPORT_SOCKET_FILE_MODE_FORBIDDEN")
        buffer_size = io.DEFAULT_BUFFER_SIZE if buffering is None or buffering < 0 else buffering
        self._open_file_leases += 1
        raw = _DeadlineSocketRaw(
            self._network_socket,
            self._remaining,
            self._release_file_lease,
        )
        try:
            return io.BufferedReader(raw, buffer_size=buffer_size)
        except BaseException:
            raw.close()
            raise

    def settimeout(self, value: float) -> None:
        self._network_socket.settimeout(value)

    def getpeername(self) -> Any:
        return self._network_socket.getpeername()

    def close(self) -> None:
        self._owner_close_requested = True
        if self._open_file_leases == 0:
            self._close_network_socket_once()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._network_socket, name)


class _PinnedAddressHttpsConnection(http.client.HTTPSConnection):
    """HTTPS connection that never resolves a hostname or tries a second address."""

    def __init__(
        self,
        *,
        host: str,
        approved_ip_address: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
        monotonic: Callable[[], float],
        started: float,
        pre_connect_guard: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._approved_ip_address = approved_ip_address
        self._strict_context = context
        self._deadline_monotonic = monotonic
        self._deadline_started = started
        self._deadline_seconds = timeout
        self._pre_connect_guard = pre_connect_guard

    def _remaining(self) -> float:
        return _remaining_dispatch_seconds(
            started=self._deadline_started,
            timeout_seconds=self._deadline_seconds,
            monotonic=self._deadline_monotonic,
        )

    def connect(self) -> None:
        if getattr(self, "_tunnel_host", None) is not None:
            raise LiveTransportError("LIVE_TRANSPORT_TUNNEL_FORBIDDEN")
        if self._pre_connect_guard is not None:
            self._pre_connect_guard()
        address = ipaddress.ip_address(self._approved_ip_address)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        endpoint: tuple[object, ...] = (
            (str(address), self.port, 0, 0)
            if family == socket.AF_INET6
            else (str(address), self.port)
        )
        raw_socket = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        wrapped: Any | None = None
        try:
            raw_socket.settimeout(self._remaining())
            raw_socket.connect(endpoint)
            peer = ipaddress.ip_address(str(raw_socket.getpeername()[0]))
            if peer != address:
                raise LiveTransportError("LIVE_TRANSPORT_PEER_IP_MISMATCH")
            raw_socket.settimeout(self._remaining())
            wrapped = self._strict_context.wrap_socket(raw_socket, server_hostname=self.host)
            wrapped.settimeout(self._remaining())
            wrapped_peer = ipaddress.ip_address(str(wrapped.getpeername()[0]))
            if wrapped_peer != address:
                raise LiveTransportError("LIVE_TRANSPORT_PEER_IP_MISMATCH")
            self.sock = cast(Any, _DeadlineSocketAdapter(wrapped, self._remaining))
        except BaseException:
            cleanup_target = wrapped if wrapped is not None else raw_socket
            close_error = _close_resource_with_retry(cleanup_target)
            self.sock = None
            if close_error is not None:
                raise LiveTransportError(
                    "LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                    diagnostic=_redacted_diagnostic(
                        stage="CONNECTION_CLOSE",
                        code="LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                        error=close_error,
                        http_status=None,
                    ),
                ) from None
            raise


def _default_connection_factory(
    host: str,
    approved_ip_address: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    monotonic: Callable[[], float],
    started: float,
) -> _HttpsConnection:
    return cast(
        _HttpsConnection,
        _PinnedAddressHttpsConnection(
            host=host,
            approved_ip_address=approved_ip_address,
            port=port,
            timeout=timeout,
            context=context,
            monotonic=monotonic,
            started=started,
        ),
    )


def _default_connection_factory_v2(
    host: str,
    approved_ip_address: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    monotonic: Callable[[], float],
    started: float,
    pre_connect_guard: Callable[[], None],
) -> _HttpsConnection:
    return cast(
        _HttpsConnection,
        _PinnedAddressHttpsConnection(
            host=host,
            approved_ip_address=approved_ip_address,
            port=port,
            timeout=timeout,
            context=context,
            monotonic=monotonic,
            started=started,
            pre_connect_guard=pre_connect_guard,
        ),
    )


def _sanitized_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    allowed = {
        "x-requests-last",
        "x-requests-remaining",
        "x-requests-used",
    }
    for raw_name, raw_value in headers:
        name = raw_name.casefold()
        if name == "location" or name in allowed:
            if name in result:
                raise LiveTransportError("LIVE_TRANSPORT_DUPLICATE_CONTROL_HEADER")
        if name == "location":
            result[name] = "PRESENT"
        elif name in allowed:
            value = raw_value.strip()
            if len(value) > 64 or not value.isascii():
                result[name] = "INVALID"
            else:
                result[name] = value
    return result


def _best_effort_sanitized_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    try:
        return _sanitized_headers(headers)
    except LiveTransportError:
        return {}


def _validated_content_length(headers: list[tuple[str, str]]) -> int | None:
    values = [value.strip() for name, value in headers if name.casefold() == "content-length"]
    if not values:
        return None
    if len(values) != 1:
        raise LiveTransportError("LIVE_TRANSPORT_CONTENT_LENGTH_INVALID")
    value = values[0]
    if not value or len(value) > 20 or not value.isascii() or not value.isdecimal():
        raise LiveTransportError("LIVE_TRANSPORT_CONTENT_LENGTH_INVALID")
    declared = int(value)
    if declared > 2**63 - 1:
        raise LiveTransportError("LIVE_TRANSPORT_CONTENT_LENGTH_INVALID")
    return declared


def _read_response_with_deadline(
    response: _HttpResponse,
    *,
    maximum_bytes: int,
    timeout_seconds: float,
    monotonic: Callable[[], float],
    started: float,
    tighten_timeout: Callable[[float], None],
) -> bytes:
    """Bound the whole body read, not merely each individual socket operation."""

    read1 = getattr(response, "read1", None)
    if not callable(read1):
        tighten_timeout(
            _remaining_dispatch_seconds(
                started=started,
                timeout_seconds=timeout_seconds,
                monotonic=monotonic,
            )
        )
        try:
            payload = response.read(maximum_bytes + 1)
        except http.client.IncompleteRead as error:
            partial = bytes(error.partial)[: maximum_bytes + 1]
            raise _PartialResponseReadError(
                partial,
                code="LIVE_TRANSPORT_DISPATCH_FAILED",
                exception_class=_safe_exception_class(error),
                errno=_safe_errno(error),
            ) from None
        if not isinstance(payload, bytes):
            raise LiveTransportError("LIVE_TRANSPORT_BODY_INVALID")
        if monotonic() - started > timeout_seconds:
            raise _PartialResponseReadError(
                payload[: maximum_bytes + 1],
                code="LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED",
                exception_class="LiveTransportError",
                errno=None,
            ) from None
        return payload

    chunks: list[bytes] = []
    total = 0
    try:
        while total <= maximum_bytes:
            tighten_timeout(
                _remaining_dispatch_seconds(
                    started=started,
                    timeout_seconds=timeout_seconds,
                    monotonic=monotonic,
                )
            )
            chunk = read1(min(65_536, maximum_bytes + 1 - total))
            if not isinstance(chunk, bytes):
                raise LiveTransportError("LIVE_TRANSPORT_BODY_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if monotonic() - started > timeout_seconds:
                raise LiveTransportError("LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED")
    except BaseException as error:
        partial = b"".join(chunks)
        if isinstance(error, http.client.IncompleteRead):
            partial = (partial + bytes(error.partial))[: maximum_bytes + 1]
        raise _PartialResponseReadError(
            partial,
            code=(
                error.code
                if isinstance(error, LiveTransportError)
                else "LIVE_TRANSPORT_DISPATCH_FAILED"
            ),
            exception_class=_safe_exception_class(error),
            errno=_safe_errno(error),
        ) from None
    return b"".join(chunks)


def _remaining_dispatch_seconds(
    *,
    started: float,
    timeout_seconds: float,
    monotonic: Callable[[], float],
) -> float:
    remaining = timeout_seconds - (monotonic() - started)
    if remaining <= 0:
        raise LiveTransportError("LIVE_TRANSPORT_TOTAL_DEADLINE_EXCEEDED")
    return remaining


def _tighten_connection_timeout(connection: _HttpsConnection, timeout: float) -> None:
    network_socket = getattr(connection, "sock", None)
    setter = getattr(network_socket, "settimeout", None)
    if callable(setter):
        setter(timeout)


def _verify_connection_peer(connection: _HttpsConnection, expected_ip_address: str) -> None:
    network_socket = getattr(connection, "sock", None)
    get_peer_name = getattr(network_socket, "getpeername", None)
    if not callable(get_peer_name):
        raise LiveTransportError("LIVE_TRANSPORT_PEER_IDENTITY_UNAVAILABLE")
    try:
        peer = ipaddress.ip_address(str(get_peer_name()[0]))
        expected = ipaddress.ip_address(expected_ip_address)
    except (IndexError, TypeError, ValueError):
        raise LiveTransportError("LIVE_TRANSPORT_PEER_IDENTITY_INVALID") from None
    if peer != expected:
        raise LiveTransportError("LIVE_TRANSPORT_PEER_IP_MISMATCH")


class StrictHttpsTransport:
    """One direct TLS GET, with no proxy inheritance, redirect, or retry layer."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        connection_factory: ConnectionFactory = _default_connection_factory,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        monotonic: Callable[[], float] = time.monotonic,
        on_dispatch: Callable[[], None] | None = None,
        on_response: Callable[[LiveTransportResponse, bool], None] | None = None,
    ) -> None:
        self._clock = clock
        self._connection_factory = connection_factory
        self._ssl_context_factory = ssl_context_factory
        self._monotonic = monotonic
        self._on_dispatch = on_dispatch
        self._on_response = on_response
        self._prepared: tuple[PublicProviderRequestV1, ssl.SSLContext] | None = None

    @staticmethod
    def _validated_request(request: PublicProviderRequestV1) -> PublicProviderRequestV1:
        try:
            return PublicProviderRequestV1.model_validate(request.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveTransportError("LIVE_PUBLIC_REQUEST_INVALID") from None

    @staticmethod
    def _validate_tls_context(context: ssl.SSLContext) -> None:
        if (
            context.verify_mode != ssl.CERT_REQUIRED
            or not context.check_hostname
            or getattr(context, "keylog_filename", None) is not None
        ):
            raise LiveTransportError("LIVE_TRANSPORT_TLS_VERIFICATION_REQUIRED")

    def preflight(self, request: PublicProviderRequestV1) -> None:
        validated = self._validated_request(request)
        forbidden_tls_environment = {
            "SSLKEYLOGFILE": "LIVE_TRANSPORT_TLS_KEYLOG_FORBIDDEN",
            "SSL_CERT_FILE": "LIVE_TRANSPORT_TLS_TRUST_ENV_FORBIDDEN",
            "SSL_CERT_DIR": "LIVE_TRANSPORT_TLS_TRUST_ENV_FORBIDDEN",
        }
        for variable, code in forbidden_tls_environment.items():
            if variable in os.environ:
                raise LiveTransportError(code)
        context = self._ssl_context_factory()
        self._validate_tls_context(context)
        if self._prepared is not None:
            raise LiveTransportError("LIVE_TRANSPORT_ALREADY_PREFLIGHTED")
        self._prepared = (validated, context)

    def dispatch(
        self,
        request: PublicProviderRequestV1,
        *,
        api_key: str,
    ) -> LiveTransportResponse:
        connection: Any | None = None
        response: _HttpResponse | None = None
        status: object = None
        target = ""
        stage = "REQUEST_VALIDATION"
        dispatch_completed = False
        try:
            request = self._validated_request(request)
            if request.host != ALLOWED_PROVIDER_HOST:
                raise LiveTransportError("LIVE_TRANSPORT_HOST_FORBIDDEN")
            api_key = validate_provider_secret(api_key)
            if self._prepared is None or self._prepared[0] != request:
                raise LiveTransportError("LIVE_TRANSPORT_PREFLIGHT_REQUIRED")
            context = self._prepared[1]
            self._prepared = None
            self._validate_tls_context(context)
            timeout_seconds = float(request.timeout_seconds)
            started = self._monotonic()
            stage = "CONNECT"
            connection = self._connection_factory(
                request.host,
                request.approved_provider_ip_address,
                request.port,
                timeout_seconds,
                context,
                self._monotonic,
                started,
            )
            set_debug_level = getattr(connection, "set_debuglevel", None)
            if callable(set_debug_level):
                set_debug_level(0)
            if getattr(connection, "debuglevel", 0) != 0:
                raise LiveTransportError("LIVE_TRANSPORT_DEBUG_OUTPUT_FORBIDDEN")
            target = f"{request.endpoint}?{
                urlencode(
                    {
                        'regions': request.region,
                        'markets': ','.join(request.markets),
                        'oddsFormat': request.odds_format,
                        'dateFormat': request.date_format,
                        'apiKey': api_key,
                    }
                )
            }"
            if self._on_dispatch is not None:
                self._on_dispatch()
            stage = "REQUEST_SEND"
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "application/json",
                    "Connection": "close",
                    "Host": request.host,
                },
            )
            _verify_connection_peer(connection, request.approved_provider_ip_address)
            remaining = _remaining_dispatch_seconds(
                started=started,
                timeout_seconds=timeout_seconds,
                monotonic=self._monotonic,
            )
            _tighten_connection_timeout(connection, remaining)
            stage = "RESPONSE_HEADERS"
            response = connection.getresponse()
            remaining = _remaining_dispatch_seconds(
                started=started,
                timeout_seconds=timeout_seconds,
                monotonic=self._monotonic,
            )
            _tighten_connection_timeout(connection, remaining)
            observed = ensure_utc(self._clock(), field="transport_first_observed_at")
            status = response.status
            raw_headers = response.getheaders()
            stage = "BODY_READ"
            declared_length: int | None = None
            content_length_error: str | None = None
            try:
                declared_length = _validated_content_length(raw_headers)
            except LiveTransportError as error:
                # The bytes are still read and journaled as incomplete evidence
                # before the framing error becomes terminal.
                content_length_error = error.code
            observed_status = (
                status
                if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
                else 599
            )

            def notify_redacted(payload: bytes, reason: str) -> None:
                if self._on_response is None:
                    return
                # Once response material is classified as unsafe, retain only
                # derived metadata.  In particular, never pass supplier header
                # values to the durable response journal on this path.
                redacted_headers = {
                    "x-robin-redacted-body-bytes": str(len(payload)),
                    "x-robin-redacted-body-sha256": hashlib.sha256(payload).hexdigest(),
                    "x-robin-redaction-reason": reason,
                }
                self._on_response(
                    LiveTransportResponse(
                        http_status=observed_status,
                        headers=redacted_headers,
                        payload=b"",
                        first_observed_at_utc=observed,
                    ),
                    False,
                )

            try:
                payload = _read_response_with_deadline(
                    response,
                    maximum_bytes=request.maximum_response_bytes,
                    timeout_seconds=timeout_seconds,
                    monotonic=self._monotonic,
                    started=started,
                    tighten_timeout=lambda remaining: _tighten_connection_timeout(
                        connection,
                        remaining,
                    ),
                )
            except _PartialResponseReadError as error:
                try:
                    _reject_response_secret_material(
                        error.payload,
                        raw_headers,
                        api_key,
                        body_complete=False,
                    )
                    _reject_unsafe_response_framing(raw_headers)
                except LiveTransportError as safety_error:
                    notify_redacted(error.payload, safety_error.code)
                    raise
                if self._on_response is not None:
                    self._on_response(
                        LiveTransportResponse(
                            http_status=observed_status,
                            headers=_best_effort_sanitized_headers(raw_headers),
                            payload=error.payload,
                            first_observed_at_utc=observed,
                        ),
                        False,
                    )
                raise LiveTransportError(
                    error.code,
                    diagnostic=_redacted_diagnostic(
                        stage="BODY_READ",
                        code=error.code,
                        error=error,
                        http_status=status,
                    ),
                ) from None
            stage = "RESPONSE_VALIDATE"
            declared_too_large = (
                declared_length is not None and declared_length > request.maximum_response_bytes
            )
            length_mismatch = declared_length is not None and declared_length != len(payload)
            body_complete = (
                len(payload) <= request.maximum_response_bytes
                and content_length_error is None
                and not declared_too_large
                and not length_mismatch
            )
            try:
                _reject_response_secret_material(
                    payload,
                    raw_headers,
                    api_key,
                    body_complete=body_complete,
                )
                _reject_unsafe_response_framing(raw_headers)
            except LiveTransportError as safety_error:
                notify_redacted(payload, safety_error.code)
                raise
            if self._on_response is not None:
                self._on_response(
                    LiveTransportResponse(
                        http_status=observed_status,
                        headers=_best_effort_sanitized_headers(raw_headers),
                        payload=payload,
                        first_observed_at_utc=observed,
                    ),
                    body_complete,
                )
            if not body_complete:
                if content_length_error is not None:
                    raise LiveTransportError(content_length_error)
                if declared_too_large or len(payload) > request.maximum_response_bytes:
                    raise LiveTransportError("LIVE_TRANSPORT_RESPONSE_TOO_LARGE")
                raise LiveTransportError("LIVE_TRANSPORT_CONTENT_LENGTH_MISMATCH")
            headers = _sanitized_headers(raw_headers)
            dispatch_completed = True
        except LiveTransportError as error:
            if error.diagnostic is not None:
                raise
            raise LiveTransportError(
                error.code,
                diagnostic=_redacted_diagnostic(
                    stage=stage,
                    code=error.code,
                    error=error,
                    http_status=status,
                ),
            ) from None
        except BaseException as error:
            raise LiveTransportError(
                "LIVE_TRANSPORT_DISPATCH_FAILED",
                diagnostic=_redacted_diagnostic(
                    stage=stage,
                    code="LIVE_TRANSPORT_DISPATCH_FAILED",
                    error=error,
                    http_status=status,
                ),
            ) from None
        finally:
            target = ""
            api_key = ""
            close_error = _close_transport_resources(response, connection)
            if close_error is not None and dispatch_completed:
                raise LiveTransportError(
                    "LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                    diagnostic=_redacted_diagnostic(
                        stage="CONNECTION_CLOSE",
                        code="LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                        error=close_error,
                        http_status=status,
                    ),
                ) from None
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            raise LiveTransportError("LIVE_TRANSPORT_STATUS_INVALID")
        return LiveTransportResponse(
            http_status=status,
            headers=headers,
            payload=payload,
            first_observed_at_utc=observed,
        )


class StrictHttpsTransportV2:
    """Direct TLS transport that treats binding freshness as a connect-time gate."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        connection_factory: ConnectionFactoryV2 = _default_connection_factory_v2,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._connection_factory = connection_factory
        self._ssl_context_factory = ssl_context_factory
        self._monotonic = monotonic
        self._prepared: tuple[PublicProviderRequestV2, ssl.SSLContext] | None = None

    @staticmethod
    def _validated_request(request: PublicProviderRequestV2) -> PublicProviderRequestV2:
        try:
            return PublicProviderRequestV2.model_validate(request.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveTransportError("LIVE_PUBLIC_REQUEST_INVALID") from None

    @staticmethod
    def _validate_tls_context(context: ssl.SSLContext) -> None:
        StrictHttpsTransport._validate_tls_context(context)

    def _assert_binding_current(self, request: PublicProviderRequestV2) -> None:
        try:
            request.provider_network_binding.assert_current(self._clock())
        except (CaptureContractError, TypeError, ValueError):
            raise LiveTransportError("LIVE_PROVIDER_NETWORK_BINDING_EXPIRED") from None

    def preflight(self, request: PublicProviderRequestV2) -> None:
        validated = self._validated_request(request)
        self._assert_binding_current(validated)
        forbidden_tls_environment = {
            "SSLKEYLOGFILE": "LIVE_TRANSPORT_TLS_KEYLOG_FORBIDDEN",
            "SSL_CERT_FILE": "LIVE_TRANSPORT_TLS_TRUST_ENV_FORBIDDEN",
            "SSL_CERT_DIR": "LIVE_TRANSPORT_TLS_TRUST_ENV_FORBIDDEN",
        }
        for variable, code in forbidden_tls_environment.items():
            if variable in os.environ:
                raise LiveTransportError(code)
        context = self._ssl_context_factory()
        self._validate_tls_context(context)
        self._assert_binding_current(validated)
        if self._prepared is not None:
            raise LiveTransportError("LIVE_TRANSPORT_ALREADY_PREFLIGHTED")
        self._prepared = (validated, context)

    def dispatch(
        self,
        request: PublicProviderRequestV2,
        *,
        api_key: str,
    ) -> LiveTransportResponse:
        connection: Any | None = None
        response: _HttpResponse | None = None
        status: object = None
        target = ""
        stage = "REQUEST_VALIDATION"
        dispatch_completed = False
        try:
            request = self._validated_request(request)
            if request.host != ALLOWED_PROVIDER_HOST:
                raise LiveTransportError("LIVE_TRANSPORT_HOST_FORBIDDEN")
            self._assert_binding_current(request)
            api_key = validate_provider_secret(api_key)
            self._assert_binding_current(request)
            if self._prepared is None or self._prepared[0] != request:
                raise LiveTransportError("LIVE_TRANSPORT_PREFLIGHT_REQUIRED")
            context = self._prepared[1]
            self._prepared = None
            self._validate_tls_context(context)
            timeout_seconds = float(request.timeout_seconds)
            started = self._monotonic()

            def guard_binding_at_connect() -> None:
                self._assert_binding_current(request)

            self._assert_binding_current(request)
            stage = "CONNECT"
            connection = self._connection_factory(
                request.host,
                request.approved_provider_ip_address,
                request.port,
                timeout_seconds,
                context,
                self._monotonic,
                started,
                guard_binding_at_connect,
            )
            set_debug_level = getattr(connection, "set_debuglevel", None)
            if callable(set_debug_level):
                set_debug_level(0)
            if getattr(connection, "debuglevel", 0) != 0:
                raise LiveTransportError("LIVE_TRANSPORT_DEBUG_OUTPUT_FORBIDDEN")
            target = f"{request.endpoint}?{
                urlencode(
                    {
                        'regions': request.region,
                        'markets': ','.join(request.markets),
                        'oddsFormat': request.odds_format,
                        'dateFormat': request.date_format,
                        'apiKey': api_key,
                    }
                )
            }"
            self._assert_binding_current(request)
            stage = "REQUEST_SEND"
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "application/json",
                    "Connection": "close",
                    "Host": request.host,
                },
            )
            _verify_connection_peer(connection, request.approved_provider_ip_address)
            remaining = _remaining_dispatch_seconds(
                started=started,
                timeout_seconds=timeout_seconds,
                monotonic=self._monotonic,
            )
            _tighten_connection_timeout(connection, remaining)
            stage = "RESPONSE_HEADERS"
            response = connection.getresponse()
            remaining = _remaining_dispatch_seconds(
                started=started,
                timeout_seconds=timeout_seconds,
                monotonic=self._monotonic,
            )
            _tighten_connection_timeout(connection, remaining)
            observed = ensure_utc(self._clock(), field="transport_first_observed_at")
            status = response.status
            raw_headers = response.getheaders()
            stage = "BODY_READ"
            payload = _read_response_with_deadline(
                response,
                maximum_bytes=request.maximum_response_bytes,
                timeout_seconds=timeout_seconds,
                monotonic=self._monotonic,
                started=started,
                tighten_timeout=lambda remaining: _tighten_connection_timeout(
                    connection,
                    remaining,
                ),
            )
            stage = "RESPONSE_VALIDATE"
            reject_unsafe_response(payload, raw_headers, api_key)
            headers = _sanitized_headers(raw_headers)
            dispatch_completed = True
        except LiveTransportError as error:
            if error.diagnostic is not None:
                raise
            raise LiveTransportError(
                error.code,
                diagnostic=_redacted_diagnostic(
                    stage=stage,
                    code=error.code,
                    error=error,
                    http_status=status,
                ),
            ) from None
        except BaseException as error:
            code = (
                error.code
                if isinstance(error, _PartialResponseReadError)
                else "LIVE_TRANSPORT_DISPATCH_FAILED"
            )
            raise LiveTransportError(
                code,
                diagnostic=_redacted_diagnostic(
                    stage=stage,
                    code=code,
                    error=error,
                    http_status=status,
                ),
            ) from None
        finally:
            target = ""
            api_key = ""
            close_error = _close_transport_resources(response, connection)
            if close_error is not None and dispatch_completed:
                raise LiveTransportError(
                    "LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                    diagnostic=_redacted_diagnostic(
                        stage="CONNECTION_CLOSE",
                        code="LIVE_TRANSPORT_CONNECTION_CLOSE_FAILED",
                        error=close_error,
                        http_status=status,
                    ),
                ) from None
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            raise LiveTransportError("LIVE_TRANSPORT_STATUS_INVALID")
        return LiveTransportResponse(
            http_status=status,
            headers=headers,
            payload=payload,
            first_observed_at_utc=observed,
        )
