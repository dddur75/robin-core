from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from robin.capture.contracts import ProviderRequestSpec
from robin.capture.live_transport import PublicProviderRequestV1

BASE = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
SECRET = "synthetic-transport-secret-sentinel"

class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        payload: bytes = b"[]",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.status = status
        self.payload = payload
        self.headers = headers or []
        self.read_amounts: list[int | None] = []
        self.close_calls = 0

    def read(self, amount: int | None = None) -> bytes:
        self.read_amounts.append(amount)
        return self.payload[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers

    def close(self) -> None:
        self.close_calls += 1


class FakeSocket:
    def __init__(self, peer_ip_address: str = "1.1.1.1") -> None:
        self.peer_ip_address = peer_ip_address
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def getpeername(self) -> tuple[str, int]:
        return self.peer_ip_address, 443


class FakeConnection:
    def __init__(self, response: FakeResponse, *, fail: bool = False) -> None:
        self.response = response
        self.fail = fail
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.close_calls = 0
        self.sock: Any = FakeSocket()

    def request(
        self,
        method: str,
        url: str,
        body: object | None = None,
        headers: Any = None,
    ) -> None:
        del body
        self.requests.append((method, url, dict(headers or {})))
        if self.fail:
            raise OSError("synthetic low-level failure")

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.close_calls += 1


def request(
    *,
    maximum_response_bytes: int = 1024,
    approved_provider_ip_address: str = "1.1.1.1",
) -> PublicProviderRequestV1:
    return PublicProviderRequestV1.from_spec(
        ProviderRequestSpec(
            endpoint="/v4/sports/soccer_epl/odds",
            sport_key="soccer_epl",
            markets=("h2h", "totals"),
        ),
        maximum_response_bytes=maximum_response_bytes,
        approved_provider_ip_address=approved_provider_ip_address,
    )

