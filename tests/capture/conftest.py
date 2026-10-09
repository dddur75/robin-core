from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest


class TestRealNetworkForbidden(AssertionError):
    """Tripwire raised before a capture test can reach the operating-system network."""

    code = "TEST_REAL_NETWORK_FORBIDDEN"

    def __init__(self) -> None:
        super().__init__(self.code)


_SESSION_NETWORK_COUNTS = {"unapproved": 0}


@dataclass(slots=True)
class CaptureNetworkGuard:
    attempts: int = 0
    expected_attempts: int = 0
    _expected_depth: int = 0

    def reject(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.attempts += 1
        if self._expected_depth:
            self.expected_attempts += 1
        else:
            _SESSION_NETWORK_COUNTS["unapproved"] += 1
        raise TestRealNetworkForbidden

    @contextmanager
    def expect_forbidden(self) -> Iterator[None]:
        """Mark one local negative-path tripwire as expected without enabling networking."""

        self._expected_depth += 1
        try:
            yield
        finally:
            self._expected_depth -= 1


def pytest_sessionstart(session: pytest.Session) -> None:
    del session
    _SESSION_NETWORK_COUNTS["unapproved"] = 0


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del exitstatus
    if _SESSION_NETWORK_COUNTS["unapproved"]:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: Any) -> None:
    terminalreporter.write_line(
        f"UNAPPROVED_NETWORK_ATTEMPTS = {_SESSION_NETWORK_COUNTS['unapproved']}"
    )


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> CaptureNetworkGuard:
    guard = CaptureNetworkGuard()

    class ForbiddenSocket:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def connect(self, *args: object, **kwargs: object) -> None:
            guard.reject(*args, **kwargs)

        def connect_ex(self, *args: object, **kwargs: object) -> None:
            guard.reject(*args, **kwargs)

        def close(self) -> None:
            return None

        def __enter__(self) -> ForbiddenSocket:
            return self

        def __exit__(self, *args: object) -> None:
            del args

    monkeypatch.setattr(socket, "socket", ForbiddenSocket)
    monkeypatch.setattr(socket, "create_connection", guard.reject)
    monkeypatch.setattr(socket, "getaddrinfo", guard.reject)
    monkeypatch.setattr(socket, "gethostbyname", guard.reject)
    monkeypatch.setattr(socket, "gethostbyname_ex", guard.reject)
    monkeypatch.setattr(socket, "gethostbyaddr", guard.reject)
    monkeypatch.setattr(socket, "getnameinfo", guard.reject)
    return guard


@pytest.fixture
def capture_network_guard(block_network: CaptureNetworkGuard) -> CaptureNetworkGuard:
    return block_network


@pytest.fixture(scope="session")
def synthetic_pack() -> dict[str, Any]:
    path = Path(__file__).parent / "fixtures" / "synthetic-odds-responses-v1.json"
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def no_network_counter() -> Iterator[dict[str, int]]:
    counter = {"network_calls": 0, "provider_calls": 0}
    yield counter
    assert counter == {"network_calls": 0, "provider_calls": 0}
