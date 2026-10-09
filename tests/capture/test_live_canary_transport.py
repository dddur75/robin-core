from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from robin.capture import (
    LIVE_ALLOWED_MARKET_SETS,
    LIVE_ALLOWED_SPORT_KEYS,
    ActivationEnvelopeV1,
    CaptureContractError,
    EnvironmentSecretReader,
    FixtureMapping,
    GitRepositoryStateReader,
    LivePlanItemV1,
    LivePlanV1,
    LiveTransportError,
    OwnerAuthorizationV1,
    ProviderRequestSpec,
    PublicProviderRequestV1,
    RepositoryStateV1,
    RequestFingerprint,
    StrictHttpsTransport,
    fixture_mappings_sha256,
)
from robin.capture.contracts import MappingStatus, canonical_json_bytes
from robin.capture.live_executor import LiveGuardError
from robin.capture.live_transport import (
    _DeadlineSocketAdapter,
    _PinnedAddressHttpsConnection,
    _remaining_dispatch_seconds,
)
from robin.capture.storage import capture_root_fingerprint, exclusive_local_directory_fingerprint

BASE = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
SECRET = "synthetic-transport-secret-sentinel"


def _synthetic_git_control(
    root: Path,
    *,
    origin: str = "https://github.com/dddur75/robin-stades-ng.git",
) -> tuple[Path, Path, Path]:
    repository = root / "repository"
    git_directory = repository / ".git"
    control = root / "control"
    git_directory.mkdir(parents=True)
    control.mkdir()
    (git_directory / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = false\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        '[remote "origin"]\n'
        f"\turl = {origin}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        encoding="utf-8",
    )
    index_body = b"DIRC" + struct.pack(">II", 2, 0)
    (git_directory / "index").write_bytes(
        index_body + hashlib.sha1(index_body, usedforsecurity=False).digest()
    )
    executable = control / "git"
    executable.write_bytes(b"synthetic-local-git")
    return repository, executable, control


def _git_reader(
    root: Path,
    executable: Path,
    control: Path,
) -> GitRepositoryStateReader:
    return GitRepositoryStateReader(
        root,
        git_executable=executable,
        git_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        control_temp_root=control,
        repository_root_fingerprint=exclusive_local_directory_fingerprint(root),
        control_temp_root_fingerprint=exclusive_local_directory_fingerprint(control),
    )


def _run_local_git(executable: Path, repository: Path, *arguments: str) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"THE_ODDS_API_KEY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"}
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    subprocess.run(  # noqa: S603 - absolute local Git is selected and network verbs are absent.
        [str(executable), *arguments],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def _load_live_canary_cli() -> ModuleType:
    repository_root = Path(__file__).parents[2]
    script = repository_root / "tools/data-sourcing/run_bounded_live_canary_v1.py"
    spec = importlib.util.spec_from_file_location("_robin_live_canary_cli_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _synthetic_cli_bundle(tmp_path: Path) -> dict[str, Any]:
    capture_root = tmp_path / "capture"
    control_temp_root = tmp_path / "git-control"
    executable_root = tmp_path / "git-executable"
    input_root = tmp_path / "inputs"
    for directory in (capture_root, control_temp_root, executable_root, input_root):
        directory.mkdir()
    git_executable = executable_root / ("git.exe" if os.name == "nt" else "git")
    git_executable.write_bytes(b"synthetic-offline-cli-git")
    git_sha256 = hashlib.sha256(git_executable.read_bytes()).hexdigest()
    repository_sha = "a" * 40
    current = datetime.now(UTC)
    request_spec = ProviderRequestSpec(
        endpoint="/v4/sports/soccer_epl/odds",
        sport_key="soccer_epl",
        markets=("h2h", "totals"),
    )
    mapping = FixtureMapping(
        provider_event_id="synthetic-cli-event-001",
        fixture_id="synthetic-cli-fixture-001",
        status=MappingStatus.MAPPED,
        candidate_fixture_ids=("synthetic-cli-fixture-001",),
        mapping_revision="synthetic-cli-mapping-v1",
    )
    mappings = (mapping,)
    authorization = OwnerAuthorizationV1.issue(
        authorization_id="synthetic-cli-owner-authorization-001",
        authorized_main_sha=repository_sha,
        issued_at_utc=current - timedelta(minutes=10),
        not_before_utc=current - timedelta(minutes=5),
        expires_at_utc=current + timedelta(hours=1),
        allowed_sport_keys=LIVE_ALLOWED_SPORT_KEYS,
        allowed_market_sets=LIVE_ALLOWED_MARKET_SETS,
        maximum_http_calls=1,
        maximum_credits=2,
        maximum_plan_items=1,
        approved_capture_root_fingerprint=capture_root_fingerprint(capture_root),
        approved_repository_root_fingerprint="d" * 64,
        approved_control_temp_root_fingerprint="e" * 64,
        approved_git_executable_sha256=git_sha256,
        approved_provider_ip_address="1.1.1.1",
        authorization_nonce="synthetic-cli-owner-authorization-nonce-001",
    )
    activation_material = {
        "activation_id": "synthetic-cli-activation-001",
        "authorization_id": authorization.authorization_id,
        "authorization_hash": authorization.canonical_authorization_hash,
        "repository_sha": repository_sha,
        "sport_key": request_spec.sport_key,
        "region": request_spec.region,
        "markets": request_spec.markets,
        "not_before_utc": current - timedelta(minutes=1),
        "expires_at_utc": current + timedelta(minutes=10),
        "maximum_http_calls": 1,
        "maximum_credits": 2,
        "activation_nonce": "synthetic-cli-activation-nonce-001",
    }
    preliminary_activation = ActivationEnvelopeV1.issue(
        plan_sha256="0" * 64,
        **activation_material,
    )
    item = LivePlanItemV1.issue(
        item_id="synthetic-cli-item-001",
        plan_id="synthetic-cli-plan-001",
        sequence=1,
        sport_key=request_spec.sport_key,
        region=request_spec.region,
        markets=request_spec.markets,
        provider_request_fingerprint=RequestFingerprint.create(request_spec).request_sha256,
        fixture_mappings_sha256=fixture_mappings_sha256(mappings),
        not_before_utc=current - timedelta(minutes=1),
        expires_at_utc=current + timedelta(minutes=10),
        maximum_credits=2,
        purpose="ENTIRELY_SYNTHETIC_OFFLINE_CLI_WIRING_PROOF",
        window_label="SYNTHETIC_CLI_WINDOW_001",
    )
    plan = LivePlanV1.issue(
        plan_id=item.plan_id,
        activation_id=preliminary_activation.activation_id,
        activation_hash=preliminary_activation.activation_scope_sha256,
        repository_sha=repository_sha,
        created_at_utc=current - timedelta(minutes=1),
        expires_at_utc=current + timedelta(minutes=10),
        items=(item,),
        maximum_http_calls=1,
        maximum_credits=2,
    )
    activation = ActivationEnvelopeV1.issue(
        plan_sha256=plan.canonical_plan_hash,
        **activation_material,
    )
    controls: dict[str, Any] = {
        "authorization": authorization,
        "activation": activation,
        "plan": plan,
        "request": request_spec,
        "fixture-mappings": list(mappings),
    }
    paths: dict[str, Path] = {}
    for name, value in controls.items():
        path = input_root / f"{name}.json"
        if isinstance(value, list):
            material = [entry.model_dump(mode="json") for entry in value]
        else:
            material = value.model_dump(mode="json")
        path.write_bytes(canonical_json_bytes(material) + b"\n")
        paths[name] = path
    return {
        "activation": activation,
        "authorization": authorization,
        "capture_root": capture_root,
        "control_temp_root": control_temp_root,
        "git_executable": git_executable,
        "git_sha256": git_sha256,
        "item": item,
        "paths": paths,
        "repository_root": Path(__file__).parents[2],
        "repository_sha": repository_sha,
    }


def _synthetic_cli_arguments(bundle: dict[str, Any], *, git_sha256: str) -> list[str]:
    paths = bundle["paths"]
    return [
        "run_bounded_live_canary_v1.py",
        "--mode",
        "LIVE_CANARY",
        "--repository-root",
        str(bundle["repository_root"]),
        "--git-executable",
        str(bundle["git_executable"]),
        "--git-executable-sha256",
        git_sha256,
        "--control-temp-root",
        str(bundle["control_temp_root"]),
        "--capture-root",
        str(bundle["capture_root"]),
        "--authorization",
        str(paths["authorization"]),
        "--owner-authorization-sha256",
        bundle["authorization"].canonical_authorization_hash,
        "--activation",
        str(paths["activation"]),
        "--plan",
        str(paths["plan"]),
        "--item-id",
        bundle["item"].item_id,
        "--request",
        str(paths["request"]),
        "--fixture-mappings",
        str(paths["fixture-mappings"]),
    ]


def _patch_cli_exclusive_roots(
    module: ModuleType,
    bundle: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "validate_exclusive_local_directory_identity",
        lambda path: Path(path).absolute(),
    )
    monkeypatch.setattr(
        module,
        "exclusive_local_directory_fingerprint",
        lambda path: (
            bundle["authorization"].approved_repository_root_fingerprint
            if Path(path).absolute() == bundle["repository_root"].absolute()
            else bundle["authorization"].approved_control_temp_root_fingerprint
        ),
    )


def test_live_canary_cli_wires_authorized_local_controls_without_external_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _synthetic_cli_bundle(tmp_path)
    module = _load_live_canary_cli()
    reader_arguments: dict[str, Any] = {}
    reader: object | None = None

    class SyntheticRepositoryReader:
        def __init__(
            self,
            repository_root: Path,
            *,
            git_executable: Path,
            git_executable_sha256: str,
            control_temp_root: Path,
            repository_root_fingerprint: str,
            control_temp_root_fingerprint: str,
        ) -> None:
            nonlocal reader
            reader = self
            reader_arguments.update(
                {
                    "repository_root": repository_root,
                    "git_executable": git_executable,
                    "git_executable_sha256": git_executable_sha256,
                    "control_temp_root": control_temp_root,
                    "repository_root_fingerprint": repository_root_fingerprint,
                    "control_temp_root_fingerprint": control_temp_root_fingerprint,
                }
            )
            self.reads = 0

        def read(self) -> RepositoryStateV1:
            self.reads += 1
            return RepositoryStateV1(
                head_sha=bundle["repository_sha"],
                main_sha=bundle["repository_sha"],
                worktree_clean=True,
                repository_root_fingerprint=(
                    bundle["authorization"].approved_repository_root_fingerprint
                ),
                control_temp_root_fingerprint=(
                    bundle["authorization"].approved_control_temp_root_fingerprint
                ),
            )

    def synthetic_offline_stop(executor: Any, **execution: Any) -> None:
        assert executor.repository_state_reader is reader
        assert executor.capture_store.root == bundle["capture_root"]
        assert execution["authorization"] == bundle["authorization"]
        assert execution["activation"] == bundle["activation"]
        raise LiveGuardError("SYNTHETIC_OFFLINE_CLI_STOP")

    def forbidden_external_process(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SYNTHETIC_CLI_MUST_NOT_START_AN_EXTERNAL_PROCESS")

    def forbidden_secret_read(_reader: object) -> str:
        raise AssertionError("SYNTHETIC_CLI_MUST_NOT_READ_A_PROVIDER_SECRET")

    def forbidden_dispatch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SYNTHETIC_CLI_MUST_NOT_DISPATCH_NETWORK_IO")

    monkeypatch.delenv("THE_ODDS_API_KEY", raising=False)
    _patch_cli_exclusive_roots(module, bundle, monkeypatch)
    monkeypatch.setattr(module, "GitRepositoryStateReader", SyntheticRepositoryReader)
    monkeypatch.setattr(module.BoundedLiveCanaryExecutor, "execute", synthetic_offline_stop)
    monkeypatch.setattr(module.EnvironmentSecretReader, "read", forbidden_secret_read)
    monkeypatch.setattr(module.StrictHttpsTransport, "dispatch", forbidden_dispatch)
    monkeypatch.setattr(subprocess, "run", forbidden_external_process)
    monkeypatch.setattr(
        sys,
        "argv",
        _synthetic_cli_arguments(bundle, git_sha256=bundle["git_sha256"]),
    )

    assert module.main() == 2

    captured = capsys.readouterr()
    assert captured.err == "LIVE_CANARY_FAILED:SYNTHETIC_OFFLINE_CLI_STOP\n"
    assert reader_arguments == {
        "repository_root": bundle["repository_root"],
        "git_executable": bundle["git_executable"],
        "git_executable_sha256": bundle["authorization"].approved_git_executable_sha256,
        "control_temp_root": bundle["control_temp_root"].resolve(),
        "repository_root_fingerprint": (
            bundle["authorization"].approved_repository_root_fingerprint
        ),
        "control_temp_root_fingerprint": (
            bundle["authorization"].approved_control_temp_root_fingerprint
        ),
    }
    assert isinstance(reader, SyntheticRepositoryReader)
    assert reader.reads == 1
    assert (bundle["capture_root"] / "raw/sha256").is_dir()


def test_live_canary_cli_rejects_unbound_git_pin_before_reader_or_store_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _synthetic_cli_bundle(tmp_path)
    module = _load_live_canary_cli()
    _patch_cli_exclusive_roots(module, bundle, monkeypatch)

    def forbidden_component(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("UNBOUND_GIT_PIN_MUST_FAIL_BEFORE_READER_OR_STORE")

    monkeypatch.setattr(module, "GitRepositoryStateReader", forbidden_component)
    monkeypatch.setattr(module, "CaptureStore", forbidden_component)
    monkeypatch.setattr(subprocess, "run", forbidden_component)
    monkeypatch.setattr(
        sys,
        "argv",
        _synthetic_cli_arguments(bundle, git_sha256="d" * 64),
    )

    assert module.main() == 2

    captured = capsys.readouterr()
    assert captured.err == ("LIVE_CANARY_FAILED:LIVE_GIT_EXECUTABLE_AUTHORIZATION_PIN_MISMATCH\n")
    assert tuple(bundle["capture_root"].iterdir()) == ()


def test_owner_authorization_hash_binds_approved_git_executable_pin(
    tmp_path: Path,
) -> None:
    bundle = _synthetic_cli_bundle(tmp_path)
    material = bundle["authorization"].model_dump(mode="json")
    material["approved_git_executable_sha256"] = "d" * 64

    with pytest.raises(CaptureContractError):
        OwnerAuthorizationV1.model_validate(material)
    reissue_material = bundle["authorization"].model_dump(exclude={"canonical_authorization_hash"})
    reissue_material["approved_git_executable_sha256"] = "d" * 64
    reissued = OwnerAuthorizationV1.issue(**reissue_material)
    assert (
        reissued.canonical_authorization_hash
        != bundle["authorization"].canonical_authorization_hash
    )


def test_live_canary_cli_rejects_control_temp_capture_overlap_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _synthetic_cli_bundle(tmp_path)
    module = _load_live_canary_cli()
    _patch_cli_exclusive_roots(module, bundle, monkeypatch)

    def forbidden_component(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("OVERLAPPING_CONTROL_ROOT_MUST_FAIL_BEFORE_READER_OR_STORE")

    arguments = _synthetic_cli_arguments(
        bundle,
        git_sha256=bundle["git_sha256"],
    )
    control_value = arguments.index("--control-temp-root") + 1
    arguments[control_value] = str(bundle["capture_root"])
    monkeypatch.setattr(module, "GitRepositoryStateReader", forbidden_component)
    monkeypatch.setattr(module, "CaptureStore", forbidden_component)
    monkeypatch.setattr(subprocess, "run", forbidden_component)
    monkeypatch.setattr(sys, "argv", arguments)

    assert module.main() == 2

    captured = capsys.readouterr()
    assert captured.err == "LIVE_CANARY_FAILED:LIVE_GIT_CONTROL_TEMP_CAPTURE_OVERLAP\n"
    assert tuple(bundle["capture_root"].iterdir()) == ()


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


@pytest.mark.parametrize(
    "provider_ip_address",
    (
        "10.0.0.1",
        "1.1.1.01",
        "2606:4700:4700:0:0:0:0:1111",
        "2606:4700:4700::1111%3",
        "ff02::1",
    ),
)
def test_owner_authorization_rejects_private_or_noncanonical_provider_ip(
    tmp_path: Path,
    provider_ip_address: str,
) -> None:
    bundle = _synthetic_cli_bundle(tmp_path)
    material = bundle["authorization"].model_dump(exclude={"canonical_authorization_hash"})
    material["approved_provider_ip_address"] = provider_ip_address

    with pytest.raises(CaptureContractError):
        OwnerAuthorizationV1.issue(**material)


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


def test_git_repository_preflight_strips_secret_proxy_and_optional_writes(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("THE_ODDS_API_KEY", SECRET)
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic-proxy.invalid")
    repository, executable, control = _synthetic_git_control(tmp_path)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    sha = "a" * 40

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((command, kwargs))
        if "rev-parse" in command:
            output = f"{sha}\n"
        else:
            output = ""
        return SimpleNamespace(stdout=output, returncode=0)

    monkeypatch.setattr("robin.capture.live_executor.subprocess.run", fake_run)
    state = _git_reader(repository, executable, control).read()

    assert state.head_sha == state.main_sha == sha
    assert len(calls) == 7
    for command, kwargs in calls:
        assert "--no-optional-locks" in command
        assert "core.fsmonitor=false" in command
        environment = kwargs["env"]
        assert "THE_ODDS_API_KEY" not in environment
        assert "HTTPS_PROXY" not in environment
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_git_repository_preflight_fails_closed_on_origin_or_dirty_state(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, executable, control = _synthetic_git_control(
        tmp_path,
        origin="https://attacker.invalid/repo.git",
    )
    calls = 0

    def forbidden_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(
        "robin.capture.live_executor.subprocess.run",
        forbidden_run,
    )
    with pytest.raises(LiveGuardError, match="LIVE_GIT_CONFIG_KEY_FORBIDDEN"):
        _git_reader(repository, executable, control).read()
    assert calls == 0


def test_git_repository_preflight_fails_closed_on_dirty_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, executable, control = _synthetic_git_control(tmp_path)

    def dirty_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            stdout=(
                "a" * 40 + "\n"
                if "rev-parse" in command
                else "dirty-untracked.txt\0"
                if "ls-files" in command
                else ""
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        "robin.capture.live_executor.subprocess.run",
        dirty_run,
    )
    with pytest.raises(LiveGuardError, match="LIVE_REPOSITORY_WORKTREE_NOT_CLEAN"):
        _git_reader(repository, executable, control).read()


def test_git_repository_preflight_rejects_unc_gitdir_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    control = tmp_path / "control"
    repository.mkdir()
    control.mkdir()
    executable = control / "git"
    executable.write_bytes(b"synthetic-local-git")
    (repository / ".git").write_text(
        "gitdir: \\\\synthetic.invalid\\share\\repo.git\n",
        encoding="utf-8",
    )
    calls = 0

    def forbidden_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr("robin.capture.live_executor.subprocess.run", forbidden_run)
    with pytest.raises(LiveGuardError, match="LIVE_GIT_METADATA_UNSAFE"):
        _git_reader(repository, executable, control).read()
    assert calls == 0


def test_git_control_temp_identity_swap_is_rejected_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, executable, control = _synthetic_git_control(tmp_path)
    executable_directory = tmp_path / "approved-executable"
    executable_directory.mkdir()
    approved_executable = executable_directory / executable.name
    executable.replace(approved_executable)
    reader = _git_reader(repository, approved_executable, control)
    displaced = tmp_path / "displaced-control"
    control.rename(displaced)
    control.mkdir()
    calls = 0

    def forbidden_run(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("GIT_SUBPROCESS_MUST_NOT_RUN_AFTER_CONTROL_ROOT_SWAP")

    monkeypatch.setattr("robin.capture.live_executor.subprocess.run", forbidden_run)
    with pytest.raises(LiveGuardError, match="LIVE_GIT_CONTROL_TEMP_IDENTITY_CHANGED"):
        reader.read()
    assert calls == 0


@pytest.mark.parametrize("index_flag", ("--assume-unchanged", "--skip-worktree"))
def test_git_reader_checks_real_nonempty_index_bytes_and_rejects_hidden_mutation(
    tmp_path: Path,
    index_flag: str,
) -> None:
    discovered = shutil.which("git")
    assert discovered is not None, "required local Git executable is unavailable"
    executable = Path(discovered).resolve()
    repository = tmp_path / "real-index-repository"
    repository.mkdir()
    control = tmp_path / "real-index-control"
    control.mkdir()
    _run_local_git(executable, repository, "init", "--initial-branch=main")
    _run_local_git(executable, repository, "config", "user.name", "Synthetic Test")
    _run_local_git(
        executable,
        repository,
        "config",
        "user.email",
        "synthetic@example.invalid",
    )
    tracked = repository / "tracked.txt"
    tracked.write_bytes(b"authorized bytes\n")
    _run_local_git(executable, repository, "add", "tracked.txt")
    _run_local_git(executable, repository, "commit", "-m", "synthetic baseline")
    _run_local_git(
        executable,
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/dddur75/robin-stades-ng.git",
    )
    _run_local_git(
        executable,
        repository,
        "update-ref",
        "refs/remotes/origin/main",
        "HEAD",
    )
    reader = GitRepositoryStateReader(
        repository,
        git_executable=executable,
        git_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        control_temp_root=control,
        repository_root_fingerprint=exclusive_local_directory_fingerprint(repository),
        control_temp_root_fingerprint=exclusive_local_directory_fingerprint(control),
    )
    state = reader.read()
    assert state.head_sha == state.main_sha

    tracked.write_bytes(b"authorized bytes\r\n")
    crlf_state = reader.read()
    assert crlf_state == state

    tracked.write_bytes(b"ordinary unauthorized mutation\r\n")
    with pytest.raises(LiveGuardError, match="LIVE_REPOSITORY_WORKTREE_NOT_CLEAN"):
        reader.read()

    _run_local_git(executable, repository, "update-index", index_flag, "tracked.txt")
    tracked.write_text("unauthorized bytes\n", encoding="utf-8")
    with pytest.raises(LiveGuardError, match="LIVE_GIT_INDEX_(FLAGS|FORMAT)_FORBIDDEN"):
        reader.read()
