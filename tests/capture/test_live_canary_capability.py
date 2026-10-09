from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing as mp
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from robin.capture import (
    CaptureBudget,
    CaptureContractError,
    CaptureHarness,
    CaptureMode,
    CaptureStore,
    FixtureMapping,
    InternalRetentionPolicy,
    ProviderRequestSpec,
    RequestFingerprint,
)
from robin.capture.contracts import MappingStatus, canonical_json_bytes, canonical_sha256
from robin.capture.live_contracts import (
    LIVE_ALLOWED_MARKET_SETS,
    LIVE_ALLOWED_SPORT_KEYS,
    ActivationEnvelopeV1,
    LiveExecutionReceiptV1,
    LivePlanItemV1,
    LivePlanV1,
    LiveTerminalDisposition,
    OwnerAuthorizationV1,
)
from robin.capture.live_executor import (
    BoundedLiveCanaryExecutor,
    LiveGuardError,
    PinnedOwnerAuthorizationVerifier,
    RepositoryStateV1,
    fixture_mappings_sha256,
)
from robin.capture.live_storage import LiveStateStore, LiveStorageError
from robin.capture.live_transport import (
    LiveTransportError,
    LiveTransportResponse,
    PublicProviderRequestV1,
)
from robin.capture.storage import CaptureStorageError

BASE = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
REPOSITORY_SHA = "a" * 40
REPOSITORY_ROOT_FINGERPRINT = "d" * 64
CONTROL_TEMP_ROOT_FINGERPRINT = "e" * 64
PROVIDER_IP_ADDRESS = "1.1.1.1"
SYNTHETIC_SECRET = "synthetic-secret-sentinel-never-real"


class TickingClock:
    def __init__(self, value: datetime = BASE) -> None:
        self.value = value

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


class StaticRepositoryReader:
    def __init__(self, sha: str = REPOSITORY_SHA) -> None:
        self.sha = sha

    def read(self) -> RepositoryStateV1:
        return RepositoryStateV1(
            head_sha=self.sha,
            main_sha=self.sha,
            worktree_clean=True,
            repository_root_fingerprint=REPOSITORY_ROOT_FINGERPRINT,
            control_temp_root_fingerprint=CONTROL_TEMP_ROOT_FINGERPRINT,
        )


class SequenceRepositoryReader:
    def __init__(self, *shas: str) -> None:
        self.shas = iter(shas)

    def read(self) -> RepositoryStateV1:
        sha = next(self.shas)
        return RepositoryStateV1(
            head_sha=sha,
            main_sha=sha,
            worktree_clean=True,
            repository_root_fingerprint=REPOSITORY_ROOT_FINGERPRINT,
            control_temp_root_fingerprint=CONTROL_TEMP_ROOT_FINGERPRINT,
        )


class SpySecretReader:
    def __init__(self, value: str = SYNTHETIC_SECRET) -> None:
        self.value = value
        self.reads = 0

    def read(self) -> str:
        self.reads += 1
        return self.value


class FakeTransport:
    def __init__(
        self,
        *,
        payload: bytes,
        status: int = 200,
        headers: dict[str, str] | None = None,
        error: str | None = None,
        preflight_error: str | None = None,
    ) -> None:
        self.payload = payload
        self.status = status
        self.headers = headers or {
            "x-requests-last": "2",
            "x-requests-used": "2",
            "x-requests-remaining": "998",
        }
        self.error = error
        self.preflight_error = preflight_error
        self.calls = 0
        self.preflights = 0
        self.public_requests: list[PublicProviderRequestV1] = []

    def preflight(self, request: PublicProviderRequestV1) -> None:
        self.preflights += 1
        self.public_requests.append(request)
        if self.preflight_error is not None:
            raise LiveTransportError(self.preflight_error)

    def dispatch(
        self,
        request: PublicProviderRequestV1,
        *,
        api_key: str,
    ) -> LiveTransportResponse:
        assert api_key == SYNTHETIC_SECRET
        self.calls += 1
        if self.error is not None:
            raise LiveTransportError(self.error)
        return LiveTransportResponse(
            http_status=self.status,
            headers=self.headers,
            payload=self.payload,
            first_observed_at_utc=BASE + timedelta(seconds=7),
        )


@dataclass(frozen=True, slots=True)
class Bundle:
    store: CaptureStore
    authorization: OwnerAuthorizationV1
    activation: ActivationEnvelopeV1
    plan: LivePlanV1
    item: LivePlanItemV1
    request: ProviderRequestSpec
    mappings: tuple[FixtureMapping, ...]


def payload_bytes(
    synthetic_pack: dict[str, Any],
    *,
    sport_key: str = "soccer_spain_la_liga",
) -> bytes:
    response = copy.deepcopy(synthetic_pack["responses"]["h2h_plus_totals"])
    for event in response:
        event["sport_key"] = sport_key
        event["bookmakers"] = [
            bookmaker for bookmaker in event["bookmakers"] if bookmaker["key"] == "synthetic-book-a"
        ]
    return json.dumps(
        response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def build_bundle(
    root: Path,
    *,
    sport_key: str = "soccer_spain_la_liga",
    markets: tuple[str, ...] = ("h2h", "totals"),
    allowed_sports: tuple[str, ...] = LIVE_ALLOWED_SPORT_KEYS,
    allowed_market_sets: tuple[tuple[str, ...], ...] = LIVE_ALLOWED_MARKET_SETS,
    authorization_not_before: datetime | None = None,
    authorization_expires: datetime | None = None,
    authorization_maximum_http_calls: int = 1,
    authorization_maximum_credits: int | None = None,
    authorization_maximum_plan_items: int = 1,
    activation_not_before: datetime | None = None,
    activation_expires: datetime | None = None,
    activation_maximum_http_calls: int = 1,
    activation_maximum_credits: int | None = None,
) -> Bundle:
    authorization_not_before = authorization_not_before or BASE - timedelta(minutes=5)
    authorization_expires = authorization_expires or BASE + timedelta(hours=1)
    activation_not_before = activation_not_before or BASE - timedelta(minutes=1)
    activation_expires = activation_expires or BASE + timedelta(minutes=10)
    authorization_maximum_credits = (
        len(markets) if authorization_maximum_credits is None else authorization_maximum_credits
    )
    activation_maximum_credits = (
        len(markets) if activation_maximum_credits is None else activation_maximum_credits
    )
    store = CaptureStore(root, InternalRetentionPolicy(), approved_local_root=root)
    request = ProviderRequestSpec(
        endpoint=f"/v4/sports/{sport_key}/odds",
        sport_key=sport_key,
        markets=markets,
    )
    mappings = (
        FixtureMapping(
            provider_event_id="synthetic-event-001",
            fixture_id="synthetic-fixture-001",
            status=MappingStatus.MAPPED,
            candidate_fixture_ids=("synthetic-fixture-001",),
            mapping_revision="synthetic-live-mapping-v1",
        ),
    )
    authorization = OwnerAuthorizationV1.issue(
        authorization_id="synthetic-owner-authorization-001",
        authorized_main_sha=REPOSITORY_SHA,
        issued_at_utc=authorization_not_before - timedelta(minutes=5),
        not_before_utc=authorization_not_before,
        expires_at_utc=authorization_expires,
        allowed_sport_keys=allowed_sports,
        allowed_market_sets=allowed_market_sets,
        maximum_http_calls=authorization_maximum_http_calls,
        maximum_credits=authorization_maximum_credits,
        maximum_plan_items=authorization_maximum_plan_items,
        approved_capture_root_fingerprint=store.capture_root_fingerprint(),
        approved_repository_root_fingerprint=REPOSITORY_ROOT_FINGERPRINT,
        approved_control_temp_root_fingerprint=CONTROL_TEMP_ROOT_FINGERPRINT,
        approved_git_executable_sha256="c" * 64,
        approved_provider_ip_address=PROVIDER_IP_ADDRESS,
        authorization_nonce="synthetic-authorization-nonce-001",
    )
    activation_data = {
        "activation_id": "synthetic-activation-001",
        "authorization_id": authorization.authorization_id,
        "authorization_hash": authorization.canonical_authorization_hash,
        "repository_sha": REPOSITORY_SHA,
        "sport_key": sport_key,
        "region": "eu",
        "markets": markets,
        "not_before_utc": activation_not_before,
        "expires_at_utc": activation_expires,
        "maximum_http_calls": activation_maximum_http_calls,
        "maximum_credits": activation_maximum_credits,
        "activation_nonce": "synthetic-activation-nonce-001",
    }
    preliminary = ActivationEnvelopeV1.issue(plan_sha256="0" * 64, **activation_data)
    item = LivePlanItemV1.issue(
        item_id="synthetic-item-001",
        plan_id="synthetic-plan-001",
        sequence=1,
        sport_key=sport_key,
        region="eu",
        markets=markets,
        provider_request_fingerprint=RequestFingerprint.create(request).request_sha256,
        fixture_mappings_sha256=fixture_mappings_sha256(mappings),
        not_before_utc=activation_not_before,
        expires_at_utc=activation_expires,
        maximum_credits=len(markets),
        purpose="synthetic capability proof only",
        window_label="SYNTHETIC-WINDOW-001",
    )
    plan = LivePlanV1.issue(
        plan_id=item.plan_id,
        activation_id=preliminary.activation_id,
        activation_hash=preliminary.activation_scope_sha256,
        repository_sha=REPOSITORY_SHA,
        created_at_utc=activation_not_before,
        expires_at_utc=activation_expires,
        items=(item,),
        maximum_http_calls=activation_maximum_http_calls,
        maximum_credits=activation_maximum_credits,
    )
    activation = ActivationEnvelopeV1.issue(
        plan_sha256=plan.canonical_plan_hash,
        **activation_data,
    )
    assert activation.activation_scope_sha256 == preliminary.activation_scope_sha256
    return Bundle(store, authorization, activation, plan, item, request, mappings)


def _bundle_wire(bundle: Bundle) -> dict[str, Any]:
    return {
        "authorization": bundle.authorization.model_dump(mode="json"),
        "activation": bundle.activation.model_dump(mode="json"),
        "plan": bundle.plan.model_dump(mode="json"),
        "item": bundle.item.model_dump(mode="json"),
        "request": bundle.request.model_dump(mode="json"),
        "mappings": [mapping.model_dump(mode="json") for mapping in bundle.mappings],
    }


def _issued_item(bundle: Bundle, **updates: Any) -> LivePlanItemV1:
    material = bundle.item.model_dump(exclude={"canonical_item_hash"})
    material.update(updates)
    return LivePlanItemV1.issue(**material)


def _bundle_with_plan(
    bundle: Bundle,
    *,
    items: tuple[LivePlanItemV1, ...],
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    maximum_http_calls: int | None = None,
    maximum_credits: int | None = None,
) -> Bundle:
    plan = LivePlanV1.issue(
        plan_id=bundle.plan.plan_id,
        activation_id=bundle.activation.activation_id,
        activation_hash=bundle.activation.activation_scope_sha256,
        repository_sha=bundle.activation.repository_sha,
        created_at_utc=created_at or bundle.plan.created_at_utc,
        expires_at_utc=expires_at or bundle.plan.expires_at_utc,
        items=items,
        maximum_http_calls=maximum_http_calls or bundle.plan.maximum_http_calls,
        maximum_credits=maximum_credits or bundle.plan.maximum_credits,
    )
    activation = ActivationEnvelopeV1.issue(
        **{
            **bundle.activation.model_dump(
                exclude={
                    "activation_scope_sha256",
                    "canonical_activation_hash",
                    "plan_sha256",
                }
            ),
            "plan_sha256": plan.canonical_plan_hash,
        }
    )
    return Bundle(
        bundle.store,
        bundle.authorization,
        activation,
        plan,
        items[0],
        bundle.request,
        bundle.mappings,
    )


def _bundle_from_wire(root: str, wire: dict[str, Any]) -> Bundle:
    path = Path(root)
    store = CaptureStore(path, InternalRetentionPolicy(), approved_local_root=path)
    return Bundle(
        store=store,
        authorization=OwnerAuthorizationV1.model_validate(wire["authorization"]),
        activation=ActivationEnvelopeV1.model_validate(wire["activation"]),
        plan=LivePlanV1.model_validate(wire["plan"]),
        item=LivePlanItemV1.model_validate(wire["item"]),
        request=ProviderRequestSpec.model_validate(wire["request"]),
        mappings=tuple(FixtureMapping.model_validate(value) for value in wire["mappings"]),
    )


def _deny_child_network() -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("CAPTURE_CHILD_PROCESS_NETWORK_FORBIDDEN")

    socket.socket = forbidden  # type: ignore[assignment]
    socket.create_connection = forbidden  # type: ignore[assignment]
    socket.getaddrinfo = forbidden  # type: ignore[assignment]
    socket.gethostbyname = forbidden  # type: ignore[assignment]
    socket.gethostbyname_ex = forbidden  # type: ignore[assignment]
    socket.gethostbyaddr = forbidden  # type: ignore[assignment]
    socket.getnameinfo = forbidden  # type: ignore[assignment]


def _process_state_contender(
    root: str,
    wire: dict[str, Any],
    operation: str,
    start: Any,
    results: Any,
) -> None:
    _deny_child_network()
    bundle = _bundle_from_wire(root, wire)
    state = LiveStateStore(bundle.store)
    start.wait(10)
    try:
        if operation == "lease":
            state.acquire_lease(
                authorization=bundle.authorization,
                activation=bundle.activation,
                plan=bundle.plan,
                item=bundle.item,
                acquired_at=BASE,
            )
        elif operation == "budget":
            state.reserve_budget(
                authorization=bundle.authorization,
                activation=bundle.activation,
                plan=bundle.plan,
                item=bundle.item,
                reserved_at=BASE,
            )
        else:
            raise AssertionError("UNKNOWN_SYNTHETIC_OPERATION")
    except BaseException as error:
        results.put(f"{type(error).__name__}:{error}")
    else:
        results.put("SUCCESS")


def _process_executor_crash(
    root: str,
    wire: dict[str, Any],
    payload: bytes,
    crash_stage: str,
    exit_code: int,
) -> None:
    _deny_child_network()
    bundle = _bundle_from_wire(root, wire)

    def crash(stage: str) -> None:
        if stage == crash_stage:
            os._exit(exit_code)

    transport: FakeTransport
    if crash_stage == "DURING_TRANSPORT_DISPATCH":

        class CrashDuringDispatch(FakeTransport):
            def dispatch(
                self,
                request: PublicProviderRequestV1,
                *,
                api_key: str,
            ) -> LiveTransportResponse:
                assert request.host == "api.the-odds-api.com"
                assert api_key == SYNTHETIC_SECRET
                os._exit(exit_code)

        transport = CrashDuringDispatch(payload=payload)
    else:
        transport = FakeTransport(payload=payload)
    run(
        bundle,
        executor(
            bundle,
            transport,
            SpySecretReader(),
            failure_injector=crash,
        ),
    )
    os._exit(120)


def _process_offline_replay(root: str, snapshot_id: str, results: Any) -> None:
    _deny_child_network()
    os.environ.pop("THE_ODDS_API_KEY", None)
    from robin.capture.live_transport import EnvironmentSecretReader

    def forbidden_secret_read(_self: object) -> str:
        raise AssertionError("CAPTURE_REPLAY_SECRET_READ_FORBIDDEN")

    EnvironmentSecretReader.read = forbidden_secret_read  # type: ignore[method-assign]
    path = Path(root)
    store = CaptureStore(path, InternalRetentionPolicy(), approved_local_root=path)
    try:
        replay = store.replay(snapshot_id)
    except BaseException as error:
        results.put(f"{type(error).__name__}:{error}")
    else:
        results.put(
            {
                "verdict": replay.verdict,
                "network_calls": replay.network_calls,
                "provider_calls": replay.provider_calls,
                "secret_reads_count": replay.secret_reads_count,
            }
        )


def _process_executor_contender(
    root: str,
    wire: dict[str, Any],
    payload: bytes,
    start: Any,
    secret_reads: Any,
    dispatches: Any,
    results: Any,
) -> None:
    _deny_child_network()
    bundle = _bundle_from_wire(root, wire)

    class SharedSecretReader:
        def read(self) -> str:
            with secret_reads.get_lock():
                secret_reads.value += 1
            return SYNTHETIC_SECRET

    class SharedFakeTransport:
        def preflight(self, _request: PublicProviderRequestV1) -> None:
            return

        def dispatch(
            self,
            _request: PublicProviderRequestV1,
            *,
            api_key: str,
        ) -> LiveTransportResponse:
            if api_key != SYNTHETIC_SECRET:
                raise AssertionError("SYNTHETIC_SECRET_MISMATCH")
            with dispatches.get_lock():
                dispatches.value += 1
            return LiveTransportResponse(
                http_status=200,
                headers={
                    "x-requests-last": "2",
                    "x-requests-used": "2",
                    "x-requests-remaining": "998",
                },
                payload=payload,
                first_observed_at_utc=BASE + timedelta(seconds=7),
            )

    start.wait(10)
    try:
        receipt = run(
            bundle,
            BoundedLiveCanaryExecutor(
                capture_store=bundle.store,
                repository_state_reader=StaticRepositoryReader(),
                owner_authorization_verifier=PinnedOwnerAuthorizationVerifier(
                    bundle.authorization.canonical_authorization_hash
                ),
                secret_reader=SharedSecretReader(),
                transport=SharedFakeTransport(),
                clock=TickingClock(),
            ),
        )
    except BaseException as error:
        results.put(f"{type(error).__name__}:{error}")
    else:
        results.put(receipt.terminal_disposition.value)


def _process_executor_blocked_in_dispatch(
    root: str,
    wire: dict[str, Any],
    payload: bytes,
    entered_dispatch: Any,
    release_dispatch: Any,
    secret_reads: Any,
    dispatches: Any,
    results: Any,
) -> None:
    _deny_child_network()
    bundle = _bundle_from_wire(root, wire)

    class SharedSecretReader:
        def read(self) -> str:
            with secret_reads.get_lock():
                secret_reads.value += 1
            return SYNTHETIC_SECRET

    class BlockingFakeTransport:
        def preflight(self, _request: PublicProviderRequestV1) -> None:
            return

        def dispatch(
            self,
            _request: PublicProviderRequestV1,
            *,
            api_key: str,
        ) -> LiveTransportResponse:
            if api_key != SYNTHETIC_SECRET:
                raise AssertionError("SYNTHETIC_SECRET_MISMATCH")
            with dispatches.get_lock():
                dispatches.value += 1
            entered_dispatch.set()
            if not release_dispatch.wait(20):
                raise AssertionError("SYNTHETIC_DISPATCH_RELEASE_TIMEOUT")
            return LiveTransportResponse(
                http_status=200,
                headers={
                    "x-requests-last": "2",
                    "x-requests-used": "2",
                    "x-requests-remaining": "998",
                },
                payload=payload,
                first_observed_at_utc=BASE + timedelta(seconds=7),
            )

    try:
        receipt = run(
            bundle,
            BoundedLiveCanaryExecutor(
                capture_store=bundle.store,
                repository_state_reader=StaticRepositoryReader(),
                owner_authorization_verifier=PinnedOwnerAuthorizationVerifier(
                    bundle.authorization.canonical_authorization_hash
                ),
                secret_reader=SharedSecretReader(),
                transport=BlockingFakeTransport(),
                clock=TickingClock(),
            ),
        )
    except BaseException as error:
        results.put(f"{type(error).__name__}:{error}")
    else:
        results.put(receipt.terminal_disposition.value)


def executor(
    bundle: Bundle,
    transport: FakeTransport,
    secret: SpySecretReader,
    *,
    clock: TickingClock | None = None,
    stages: list[str] | None = None,
    failure_injector: Any = None,
    repository_sha: str = REPOSITORY_SHA,
    authorization_pin: str | None = None,
    repository_reader: Any = None,
    maximum_payload_bytes: int = 1_048_576,
) -> BoundedLiveCanaryExecutor:
    return BoundedLiveCanaryExecutor(
        capture_store=bundle.store,
        repository_state_reader=repository_reader or StaticRepositoryReader(repository_sha),
        owner_authorization_verifier=PinnedOwnerAuthorizationVerifier(
            authorization_pin or bundle.authorization.canonical_authorization_hash
        ),
        secret_reader=secret,
        transport=transport,
        clock=clock or TickingClock(),
        stage_observer=(stages.append if stages is not None else None),
        failure_injector=failure_injector,
        maximum_payload_bytes=maximum_payload_bytes,
    )


def run(bundle: Bundle, instance: BoundedLiveCanaryExecutor):
    return instance.execute(
        mode=CaptureMode.LIVE_CANARY,
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=bundle.item,
        request=bundle.request,
        mappings=bundle.mappings,
    )


def test_synthetic_live_flow_is_one_shot_receipt_backed_and_replayable(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    stages: list[str] = []

    receipt = run(bundle, executor(bundle, transport, secret, stages=stages))

    assert receipt.terminal_disposition is LiveTerminalDisposition.SUCCESS
    assert receipt.network_calls == receipt.provider_calls == 1
    assert receipt.secret_reads_count == secret.reads == 1
    assert receipt.retries == receipt.redirects == 0
    assert receipt.secret_retained is False
    assert receipt.offline_replay_verdict == "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"
    assert transport.calls == 1
    assert transport.preflights == 1
    manifest = bundle.store.load_manifest(receipt.manifest_id or "")
    assert manifest.mode == "LIVE_CANARY"
    assert manifest.live_canary_authorized is True
    assert manifest.network_calls == manifest.provider_calls == 1
    assert bundle.store.replay(manifest.snapshot_id).deterministic is True
    assert not bundle.store.budget_ledger.exists()
    budget_events = [
        json.loads(line)
        for line in (bundle.store.root / "live-budget-ledger.jsonl").read_text("utf-8").splitlines()
    ]
    assert [event["event"] for event in budget_events] == [
        "RESERVED",
        "DISPATCH_ARMED",
        "RECONCILED",
    ]
    assert (
        stages.index("RAW_SHA256_COMPUTED")
        < stages.index("INTAKE_RECEIPT_DURABLE")
        < stages.index("RAW_CONTENT_ADDRESSED_DURABLE")
        < stages.index("PARSE_STARTED")
    )
    assert stages.index("FINAL_RECEIPT_DURABLE") < stages.index("MANIFEST_DURABLE")
    assert (
        stages.index("27_LIVE_EXECUTION_ATTEMPT_RECEIPT_DURABLE")
        < stages.index("28_OFFLINE_REPLAY_PROVEN")
        < stages.index("PLAN_ITEM_TERMINALIZED")
    )
    outputs = b"".join(path.read_bytes() for path in bundle.store.root.rglob("*") if path.is_file())
    assert SYNTHETIC_SECRET.encode() not in outputs


def test_response_intake_claim_is_one_shot_and_required_by_replay_lineage(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "response-intake-claim")
    payload = payload_bytes(synthetic_pack)
    result = run(
        bundle,
        executor(bundle, FakeTransport(payload=payload), SpySecretReader()),
    )
    assert result.manifest_id is not None
    assert result.execution_attempt_id is not None
    assert result.response_intake_claim_sha256 is not None

    claim_path = (
        bundle.store.root
        / "live"
        / "response-intake-claimed"
        / f"{bundle.item.canonical_item_hash}.json"
    )
    claim_bytes = claim_path.read_bytes()
    claim = json.loads(claim_bytes)
    lineage = json.loads(
        (bundle.store.root / "live" / "capture-lineage" / f"{result.manifest_id}.json").read_bytes()
    )
    attempt = json.loads(
        (
            bundle.store.root
            / "live"
            / "execution-attempts"
            / f"{result.execution_attempt_id}.json"
        ).read_bytes()
    )
    assert claim["canonical_intake_claim_sha256"] == result.response_intake_claim_sha256
    assert lineage["response_intake_claim"] == claim
    assert attempt["response_intake_claim_sha256"] == result.response_intake_claim_sha256
    assert bundle.store.replay(result.manifest_id).secret_reads_count == 0

    started = LiveStateStore(bundle.store).load_dispatch_started(bundle.item.canonical_item_hash)
    assert started is not None
    harness = CaptureHarness(
        bundle.store,
        CaptureBudget(maximum_requests=1, maximum_credits=2),
    )

    def ingest_again() -> None:
        harness.record_live_response(
            bundle.request,
            expected_request_fingerprint_sha256=(bundle.item.provider_request_fingerprint),
            payload=payload,
            http_status=200,
            response_headers={
                "x-requests-last": "2",
                "x-requests-used": "2",
                "x-requests-remaining": "998",
            },
            mappings=bundle.mappings,
            admission_permit=started.admission_permit,
            first_observed_at=result.first_observed_at_utc,
            ingested_at=result.ingested_at_utc,
        )

    with pytest.raises(
        LiveStorageError,
        match="LIVE_RESPONSE_INTAKE_ALREADY_(CLAIMED|TERMINAL)_NO_RETRY",
    ):
        ingest_again()

    claim_path.write_bytes(b"{}\n")
    with pytest.raises((CaptureStorageError, LiveStorageError)):
        bundle.store.replay(result.manifest_id)
    claim_path.write_bytes(claim_bytes)
    claim_path.unlink()
    with pytest.raises((CaptureStorageError, LiveStorageError)):
        bundle.store.replay(result.manifest_id)
    with pytest.raises(
        LiveStorageError,
        match="LIVE_RESPONSE_INTAKE_ALREADY_TERMINAL_NO_RETRY",
    ):
        ingest_again()


def test_phase_anchors_block_permit_reuse_after_primary_marker_deletion(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "phase-anchor-reuse")
    payload = payload_bytes(synthetic_pack)
    result = run(
        bundle,
        executor(bundle, FakeTransport(payload=payload), SpySecretReader()),
    )
    state = LiveStateStore(bundle.store)
    started = state.load_dispatch_started(bundle.item.canonical_item_hash)
    assert started is not None
    assert result.first_observed_at_utc is not None
    assert result.ingested_at_utc is not None
    item_hash = bundle.item.canonical_item_hash
    admission = bundle.store.root / "live" / "admission-consumed" / f"{item_hash}.json"
    admission_anchor = (
        bundle.store.root / "live" / "admission-consumed-anchors" / f"{item_hash}.json"
    )
    dispatch_started = bundle.store.root / "live" / "dispatch-started" / f"{item_hash}.json"
    dispatch_started_anchor = (
        bundle.store.root / "live" / "dispatch-started-anchors" / f"{item_hash}.json"
    )
    claim = bundle.store.root / "live" / "response-intake-claimed" / f"{item_hash}.json"
    claim_anchor = bundle.store.root / "live" / "response-intake-anchors" / f"{item_hash}.json"
    terminal = bundle.store.root / "live" / "terminal" / f"{item_hash}.json"
    assert admission.read_bytes() == admission_anchor.read_bytes()
    assert dispatch_started.read_bytes() == dispatch_started_anchor.read_bytes()
    assert claim.read_bytes() == claim_anchor.read_bytes()

    admission_bytes = admission.read_bytes()
    admission.unlink()
    with pytest.raises(LiveStorageError, match="ALREADY_CONSUMED_NO_RETRY"):
        state.verify_armed_permit(started.admission_permit)
    with pytest.raises(LiveStorageError, match="ALREADY_CONSUMED_NO_RETRY"):
        state.verify_admission_permit(started.admission_permit, consume=True)
    admission.write_bytes(admission_bytes)

    claim_bytes = claim.read_bytes()
    claim.unlink()
    claim_anchor.unlink()
    terminal.unlink()
    dispatch_bytes = dispatch_started.read_bytes()
    dispatch_started.unlink()
    with pytest.raises(LiveStorageError, match="ALREADY_STARTED_NO_RETRY"):
        state.mark_dispatch_started(
            started.admission_permit,
            dispatch_started_at=started.dispatch_started_at_utc,
        )
    dispatch_started.write_bytes(dispatch_bytes)

    claim_anchor.write_bytes(claim_bytes)
    with pytest.raises(LiveStorageError, match="ALREADY_CLAIMED_NO_RETRY"):
        state.claim_live_response_intake(
            started.admission_permit,
            payload_sha256=result.payload_sha256 or "",
            payload_byte_length=result.payload_byte_length or 0,
            first_observed_at=result.first_observed_at_utc,
            ingested_at=result.ingested_at_utc,
        )


@pytest.mark.parametrize("rollback", ("last_line", "ledger_absent", "old_prefix"))
def test_live_budget_events_restore_rollback_without_reopening_dispatch(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    rollback: str,
) -> None:
    bundle = build_bundle(tmp_path / rollback)
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    ledger = bundle.store.root / "live-budget-ledger.jsonl"
    complete = ledger.read_bytes()
    lines = complete.splitlines(keepends=True)
    assert len(lines) == 3
    assert len(tuple((bundle.store.root / "live" / "budget-events").glob("*.json"))) == 3
    if rollback == "ledger_absent":
        ledger.unlink()
    elif rollback == "last_line":
        ledger.write_bytes(b"".join(lines[:-1]))
    else:
        ledger.write_bytes(lines[0])

    restarted = CaptureStore(
        bundle.store.root,
        InternalRetentionPolicy(),
        approved_local_root=bundle.store.root,
    )
    assert restarted.replay(receipt.manifest_id).deterministic is True
    assert ledger.read_bytes() == complete

    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, transport, secret))
    assert secret.reads == 0
    assert transport.calls == 0


def test_live_budget_rehashed_divergent_entry_is_fail_closed_before_replay(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "rehashed-budget")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    ledger = bundle.store.root / "live-budget-ledger.jsonl"
    entries = [json.loads(line) for line in ledger.read_text("utf-8").splitlines()]
    entries[0]["reserved_requests"] = 0
    identity = {key: value for key, value in entries[0].items() if key != "entry_sha256"}
    entries[0]["entry_sha256"] = canonical_sha256(identity)
    ledger.write_bytes(b"".join(canonical_json_bytes(entry) + b"\n" for entry in entries))

    restarted = CaptureStore(
        bundle.store.root,
        InternalRetentionPolicy(),
        approved_local_root=bundle.store.root,
    )
    with pytest.raises(
        LiveStorageError,
        match="LIVE_BUDGET_LEDGER_ROLLBACK_DETECTED",
    ):
        restarted.replay(receipt.manifest_id)


def test_live_budget_partial_tail_is_audited_and_restored_without_dispatch(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "live-budget-partial-tail")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    ledger = bundle.store.root / "live-budget-ledger.jsonl"
    complete = ledger.read_bytes()
    lines = complete.splitlines(keepends=True)
    ledger.write_bytes(b"".join(lines[:-1]) + lines[-1][: len(lines[-1]) // 2])

    restarted = CaptureStore(
        bundle.store.root,
        InternalRetentionPolicy(),
        approved_local_root=bundle.store.root,
    )
    assert restarted.replay(receipt.manifest_id).deterministic is True
    assert ledger.read_bytes() == complete
    recoveries = tuple((bundle.store.root / "live" / "budget-tail-recovery").glob("*.json"))
    assert len(recoveries) == 1

    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, transport, secret))
    assert secret.reads == 0
    assert transport.calls == 0


def test_live_offline_replay_succeeds_in_fresh_process_without_secret_or_network(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "fresh-replay")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    context = mp.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_process_offline_replay,
        args=(str(bundle.store.root), receipt.manifest_id, results),
    )
    process.start()
    process.join(20)

    assert process.exitcode == 0
    assert results.get(timeout=5) == {
        "verdict": "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN",
        "network_calls": 0,
        "provider_calls": 0,
        "secret_reads_count": 0,
    }


@pytest.mark.parametrize(
    ("target", "delete"),
    (
        ("admission", True),
        ("admission", False),
        ("admission_anchor", True),
        ("admission_anchor", False),
        ("authorization_binding", True),
        ("authorization_binding", False),
        ("activation_binding", True),
        ("activation_binding", False),
        ("lineage", False),
        ("attempt_primary", False),
        ("attempt", False),
        ("terminal_receipt_primary", False),
        ("terminal_receipt", True),
        ("terminal_receipt", False),
        ("terminal_marker", False),
        ("lease", True),
        ("lease", False),
        ("dispatch_marker", True),
        ("dispatch_marker", False),
        ("dispatch_started", True),
        ("dispatch_started", False),
        ("dispatch_started_anchor", True),
        ("dispatch_started_anchor", False),
        ("response_claim_anchor", True),
        ("response_claim_anchor", False),
        ("budget_event", True),
        ("budget_event", False),
        ("budget_ledger", False),
    ),
)
def test_live_replay_rejects_each_tampered_or_missing_durable_lineage_edge(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    target: str,
    delete: bool,
) -> None:
    bundle = build_bundle(tmp_path / f"{target}-{delete}")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    assert receipt.execution_attempt_id is not None
    dispatch_started_record = json.loads(
        (
            bundle.store.root
            / "live"
            / "dispatch-started"
            / f"{bundle.item.canonical_item_hash}.json"
        ).read_bytes()
    )
    dispatch_budget_entry_sha256 = dispatch_started_record["admission_permit"][
        "budget_dispatch_entry_sha256"
    ]
    paths = {
        "admission": bundle.store.root
        / "live"
        / "admission-consumed"
        / f"{bundle.item.canonical_item_hash}.json",
        "admission_anchor": bundle.store.root
        / "live"
        / "admission-consumed-anchors"
        / f"{bundle.item.canonical_item_hash}.json",
        "authorization_binding": bundle.store.root
        / "live"
        / "authority-bindings"
        / (
            "authorization-"
            + canonical_sha256({"authorization_nonce": bundle.authorization.authorization_nonce})
            + ".json"
        ),
        "activation_binding": bundle.store.root
        / "live"
        / "authority-bindings"
        / (
            "activation-"
            + canonical_sha256({"activation_nonce": bundle.activation.activation_nonce})
            + ".json"
        ),
        "lineage": bundle.store.root / "live" / "capture-lineage" / f"{receipt.manifest_id}.json",
        "attempt": bundle.store.root
        / "live"
        / "execution-attempts"
        / "by-manifest"
        / f"{receipt.manifest_id}.json",
        "attempt_primary": bundle.store.root
        / "live"
        / "execution-attempts"
        / f"{receipt.execution_attempt_id}.json",
        "terminal_receipt": bundle.store.root
        / "live"
        / "execution-receipts"
        / "by-manifest"
        / f"{receipt.manifest_id}.json",
        "terminal_receipt_primary": bundle.store.root
        / "live"
        / "execution-receipts"
        / f"{receipt.execution_receipt_id}.json",
        "terminal_marker": bundle.store.root
        / "live"
        / "terminal"
        / f"{bundle.item.canonical_item_hash}.json",
        "lease": bundle.store.root / "live" / "leases" / f"{bundle.item.canonical_item_hash}.json",
        "dispatch_marker": bundle.store.root
        / "live"
        / "dispatch-armed"
        / f"{bundle.item.canonical_item_hash}.json",
        "dispatch_started": bundle.store.root
        / "live"
        / "dispatch-started"
        / f"{bundle.item.canonical_item_hash}.json",
        "dispatch_started_anchor": bundle.store.root
        / "live"
        / "dispatch-started-anchors"
        / f"{bundle.item.canonical_item_hash}.json",
        "response_claim_anchor": bundle.store.root
        / "live"
        / "response-intake-anchors"
        / f"{bundle.item.canonical_item_hash}.json",
        "budget_event": bundle.store.root
        / "live"
        / "budget-events"
        / f"{dispatch_budget_entry_sha256}.json",
        "budget_ledger": bundle.store.root / "live-budget-ledger.jsonl",
    }
    path = paths[target]
    if delete:
        path.unlink()
    else:
        path.write_bytes(b"{}\n")

    with pytest.raises((CaptureStorageError, LiveStorageError)):
        bundle.store.replay(receipt.manifest_id)


def test_live_replay_requires_canonical_bytes_for_every_control_edge(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "canonical-control-edges")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    assert receipt.execution_attempt_id is not None
    started = LiveStateStore(bundle.store).load_dispatch_started(bundle.item.canonical_item_hash)
    assert started is not None
    permit = started.admission_permit
    root = bundle.store.root
    paths = (
        root / "live" / "leases" / f"{permit.item_hash}.json",
        root
        / "live"
        / "authority-bindings"
        / f"authorization-{permit.authorization_binding_key_sha256}.json",
        root / "live" / "dispatch-armed" / f"{permit.item_hash}.json",
        root / "live" / "admission-consumed" / f"{permit.item_hash}.json",
        root / "live" / "dispatch-started" / f"{permit.item_hash}.json",
        root / "live" / "response-intake-claimed" / f"{permit.item_hash}.json",
        root / "live" / "capture-lineage" / f"{receipt.manifest_id}.json",
        root / "live" / "execution-attempts" / "by-manifest" / f"{receipt.manifest_id}.json",
        root / "live" / "execution-receipts" / "by-manifest" / f"{receipt.manifest_id}.json",
        root / "live" / "terminal" / f"{permit.item_hash}.json",
        root / "live" / "budget-events" / f"{permit.budget_dispatch_entry_sha256}.json",
    )
    for path in paths:
        original = path.read_bytes()
        reformatted = (
            json.dumps(json.loads(original), ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        )
        assert reformatted != original
        path.write_bytes(reformatted)
        with pytest.raises((CaptureStorageError, LiveStorageError)):
            bundle.store.replay(receipt.manifest_id)
        path.write_bytes(original)
    assert bundle.store.replay(receipt.manifest_id).deterministic is True


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("lease_hash", "f" * 64),
        ("reserved_requests", 0),
        ("dispatch_started_at_utc", None),
        ("offline_replay_verdict", "NOT_POSSIBLE"),
        ("observed_quota", None),
    ),
)
def test_live_execution_receipt_rejects_semantically_incomplete_success(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    field: str,
    value: Any,
) -> None:
    bundle = build_bundle(tmp_path / field)
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    material = receipt.model_dump(exclude={"execution_receipt_id"})
    material["observed_quota"] = receipt.observed_quota
    material[field] = value
    with pytest.raises(CaptureContractError):
        LiveExecutionReceiptV1.issue(**material)


def test_live_replay_cross_checks_rehashed_terminal_semantics_against_attempt(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "semantic-terminal-tamper")
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.manifest_id is not None
    assert receipt.payload_byte_length is not None
    material = receipt.model_dump(exclude={"execution_receipt_id"})
    material["observed_quota"] = receipt.observed_quota
    material["payload_byte_length"] = receipt.payload_byte_length + 1
    tampered = LiveExecutionReceiptV1.issue(**material)
    payload = canonical_json_bytes(tampered.model_dump(mode="json")) + b"\n"
    primary = (
        bundle.store.root / "live" / "execution-receipts" / f"{tampered.execution_receipt_id}.json"
    )
    alias = (
        bundle.store.root
        / "live"
        / "execution-receipts"
        / "by-manifest"
        / f"{receipt.manifest_id}.json"
    )
    primary.write_bytes(payload)
    alias.write_bytes(payload)
    marker_path = (
        bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
    )
    marker = json.loads(marker_path.read_bytes())
    marker["execution_receipt_id"] = tampered.execution_receipt_id
    marker_path.write_bytes(canonical_json_bytes(marker) + b"\n")

    with pytest.raises(CaptureStorageError, match="LINEAGE_MISMATCH"):
        bundle.store.replay(receipt.manifest_id)


@pytest.mark.parametrize(
    ("source_disposition", "tampered_disposition"),
    (
        (
            LiveTerminalDisposition.SUCCESS,
            LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED,
        ),
        (
            LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED,
            LiveTerminalDisposition.SUCCESS,
        ),
    ),
)
def test_live_replay_binds_terminal_disposition_to_budget_reconciliation(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    source_disposition: LiveTerminalDisposition,
    tampered_disposition: LiveTerminalDisposition,
) -> None:
    bundle = build_bundle(tmp_path / source_disposition.value)
    if source_disposition is LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED:

        def fail_reconciliation(*_args: object, **_kwargs: object) -> None:
            raise LiveStorageError("SYNTHETIC_RECONCILIATION_FAILURE")

        monkeypatch.setattr(LiveStateStore, "reconcile_budget", fail_reconciliation)
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )
    assert receipt.terminal_disposition is source_disposition
    assert receipt.manifest_id is not None

    material = receipt.model_dump(exclude={"execution_receipt_id"})
    material["observed_quota"] = receipt.observed_quota
    material["terminal_disposition"] = tampered_disposition
    tampered = LiveExecutionReceiptV1.issue(**material)
    payload = canonical_json_bytes(tampered.model_dump(mode="json")) + b"\n"
    primary = (
        bundle.store.root / "live" / "execution-receipts" / f"{tampered.execution_receipt_id}.json"
    )
    alias = (
        bundle.store.root
        / "live"
        / "execution-receipts"
        / "by-manifest"
        / f"{receipt.manifest_id}.json"
    )
    primary.write_bytes(payload)
    alias.write_bytes(payload)
    marker_path = (
        bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
    )
    marker = json.loads(marker_path.read_bytes())
    marker["execution_receipt_id"] = tampered.execution_receipt_id
    marker["terminal_disposition"] = tampered.terminal_disposition.value
    marker_path.write_bytes(canonical_json_bytes(marker) + b"\n")

    with pytest.raises(
        CaptureStorageError,
        match="LIVE_EXECUTION_RECEIPT_BUDGET_LINEAGE_MISMATCH",
    ):
        bundle.store.replay(receipt.manifest_id)


def test_offline_replay_failure_still_produces_one_durable_terminal_receipt(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_bundle(tmp_path / "offline-replay-failure")

    def fail_replay(_snapshot_id: str) -> None:
        raise CaptureStorageError("SYNTHETIC_OFFLINE_REPLAY_FAILURE")

    monkeypatch.setattr(bundle.store, "_replay_preterminal_live", fail_replay)
    receipt = run(
        bundle,
        executor(
            bundle,
            FakeTransport(payload=payload_bytes(synthetic_pack)),
            SpySecretReader(),
        ),
    )

    assert receipt.terminal_disposition is LiveTerminalDisposition.OFFLINE_REPLAY_FAILED
    assert receipt.offline_replay_verdict == "FAILED"
    assert receipt.manifest_id is not None
    state = LiveStateStore(bundle.store)
    state.verify_terminal_budget_state(receipt)
    assert state.terminal_marker_exists(bundle.item.canonical_item_hash)
    terminal_path = (
        bundle.store.root / "live" / "execution-receipts" / f"{receipt.execution_receipt_id}.json"
    )
    assert LiveExecutionReceiptV1.model_validate_json(terminal_path.read_bytes()) == receipt


@pytest.mark.parametrize("sport_key", LIVE_ALLOWED_SPORT_KEYS)
def test_every_exact_allowed_sport_can_complete_the_synthetic_flow(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    sport_key: str,
) -> None:
    bundle = build_bundle(tmp_path / sport_key, sport_key=sport_key)
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack, sport_key=sport_key))

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.SUCCESS
    assert transport.public_requests[0].sport_key == sport_key


@pytest.mark.parametrize(
    "sport_key",
    (
        "soccer_*",
        "soccer",
        "soccer_usa_mls",
        "soccer_spain_la_liga*",
        "",
        " ",
        "SOCCER_EPL",
    ),
)
def test_sport_allowlist_has_no_prefix_wildcard_case_or_whitespace_escape(
    sport_key: str,
) -> None:
    with pytest.raises(CaptureContractError):
        OwnerAuthorizationV1.issue(
            authorization_id="synthetic-invalid-sport",
            authorized_main_sha=REPOSITORY_SHA,
            issued_at_utc=BASE - timedelta(minutes=2),
            not_before_utc=BASE - timedelta(minutes=1),
            expires_at_utc=BASE + timedelta(minutes=30),
            allowed_sport_keys=(sport_key,),
            allowed_market_sets=(("h2h",),),
            maximum_http_calls=1,
            maximum_credits=1,
            maximum_plan_items=1,
            approved_capture_root_fingerprint="b" * 64,
            approved_repository_root_fingerprint=REPOSITORY_ROOT_FINGERPRINT,
            approved_control_temp_root_fingerprint=CONTROL_TEMP_ROOT_FINGERPRINT,
            approved_git_executable_sha256="c" * 64,
            approved_provider_ip_address=PROVIDER_IP_ADDRESS,
            authorization_nonce="synthetic-invalid-sport-nonce",
        )


def test_authorization_activation_plan_and_item_hash_mutations_fail_closed(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    contracts = (
        (bundle.authorization, OwnerAuthorizationV1, "maximum_credits"),
        (bundle.activation, ActivationEnvelopeV1, "maximum_credits"),
        (bundle.plan, LivePlanV1, "maximum_credits"),
        (bundle.item, LivePlanItemV1, "purpose"),
    )
    for contract, contract_type, field in contracts:
        material = copy.deepcopy(contract.model_dump(mode="json"))
        material[field] = (
            int(material[field]) + 1
            if isinstance(material[field], int)
            else f"{material[field]}-mutated"
        )
        with pytest.raises(CaptureContractError):
            contract_type.model_validate(material)


@pytest.mark.parametrize(
    "case",
    (
        "owner_expired",
        "owner_not_yet_valid",
        "activation_time_wider",
        "activation_sport_mismatch",
        "activation_market_mismatch",
        "activation_call_budget_escalation",
        "activation_credit_budget_escalation",
    ),
)
def test_owner_authority_and_activation_escalations_fail_before_secret(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    case: str,
) -> None:
    options: dict[str, Any] = {}
    if case == "owner_expired":
        options.update(
            authorization_not_before=BASE - timedelta(minutes=20),
            authorization_expires=BASE - timedelta(seconds=1),
        )
    elif case == "owner_not_yet_valid":
        options.update(
            authorization_not_before=BASE + timedelta(minutes=1),
            authorization_expires=BASE + timedelta(hours=1),
        )
    elif case == "activation_time_wider":
        options.update(authorization_expires=BASE + timedelta(minutes=5))
    elif case == "activation_sport_mismatch":
        options.update(allowed_sports=("soccer_epl",))
    elif case == "activation_market_mismatch":
        options.update(allowed_market_sets=(("h2h",),))
    elif case == "activation_call_budget_escalation":
        options.update(activation_maximum_http_calls=2)
    elif case == "activation_credit_budget_escalation":
        options.update(
            authorization_maximum_credits=1,
            activation_maximum_credits=2,
        )
    bundle = build_bundle(tmp_path / case, **options)
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))

    with pytest.raises(LiveGuardError):
        run(bundle, executor(bundle, transport, secret))

    assert secret.reads == 0
    assert transport.calls == 0


@pytest.mark.parametrize(
    "contract_name",
    ("authorization", "activation", "plan", "item", "request", "mapping"),
)
def test_executor_reparses_model_copy_and_model_construct_inputs(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    contract_name: str,
) -> None:
    bundle = build_bundle(tmp_path / contract_name)
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    kwargs: dict[str, Any] = {
        "mode": CaptureMode.LIVE_CANARY,
        "authorization": bundle.authorization,
        "activation": bundle.activation,
        "plan": bundle.plan,
        "item": bundle.item,
        "request": bundle.request,
        "mappings": bundle.mappings,
    }
    if contract_name == "authorization":
        kwargs[contract_name] = bundle.authorization.model_copy(update={"maximum_credits": 999})
    elif contract_name == "activation":
        kwargs[contract_name] = bundle.activation.model_copy(update={"region": "us"})
    elif contract_name == "plan":
        kwargs[contract_name] = bundle.plan.model_copy(update={"maximum_credits": 999})
    elif contract_name == "item":
        kwargs[contract_name] = bundle.item.model_copy(update={"sport_key": "soccer_usa_mls"})
    elif contract_name == "request":
        kwargs[contract_name] = ProviderRequestSpec.model_construct(
            **{
                **bundle.request.model_dump(),
                "endpoint": "/v4/sports/soccer_epl/odds?apiKey=forbidden",
            }
        )
    else:
        mapping_data = bundle.mappings[0].model_dump()
        mapping_data["provider_event_id"] = ""
        kwargs["mappings"] = (FixtureMapping.model_construct(**mapping_data),)

    with pytest.raises(LiveGuardError, match="LIVE_INPUT_CONTRACT_INVALID"):
        executor(bundle, transport, secret).execute(**kwargs)
    assert secret.reads == 0
    assert transport.calls == 0


def test_owner_authorization_requires_separate_matching_hash_pin(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "owner-pin")
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))

    with pytest.raises(LiveGuardError, match="LIVE_OWNER_AUTHORIZATION_PIN_MISMATCH"):
        run(
            bundle,
            executor(
                bundle,
                transport,
                secret,
                authorization_pin="f" * 64,
            ),
        )
    assert secret.reads == 0
    assert transport.calls == 0


def test_plan_rejects_duplicate_item_ids_and_noncanonical_reordering(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(
        tmp_path / "plan-structure",
        authorization_maximum_http_calls=2,
        authorization_maximum_credits=4,
        authorization_maximum_plan_items=2,
        activation_maximum_http_calls=2,
        activation_maximum_credits=4,
    )
    duplicate_id = _issued_item(bundle, sequence=2)
    with pytest.raises(CaptureContractError):
        LivePlanV1.issue(
            **{
                **bundle.plan.model_dump(exclude={"items", "canonical_plan_hash"}),
                "items": (bundle.item, duplicate_id),
            }
        )

    second = _issued_item(bundle, item_id="synthetic-item-002", sequence=2)
    with pytest.raises(CaptureContractError):
        LivePlanV1.issue(
            **{
                **bundle.plan.model_dump(exclude={"items", "canonical_plan_hash"}),
                "items": (second, bundle.item),
            }
        )


@pytest.mark.parametrize("case", ("expired_item", "outside_activation", "credit_escalation"))
def test_plan_item_temporal_and_credit_scope_fail_before_secret(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    case: str,
) -> None:
    bundle = build_bundle(tmp_path / case)
    if case == "expired_item":
        item = _issued_item(bundle, expires_at_utc=BASE)
        bundle = _bundle_with_plan(bundle, items=(item,))
    elif case == "outside_activation":
        outside = bundle.activation.expires_at_utc + timedelta(seconds=1)
        item = _issued_item(bundle, expires_at_utc=outside)
        bundle = _bundle_with_plan(bundle, items=(item,), expires_at=outside)
    else:
        activation_data = bundle.activation.model_dump(
            exclude={
                "activation_scope_sha256",
                "canonical_activation_hash",
                "plan_sha256",
            }
        )
        activation_data["maximum_credits"] = 1
        preliminary = ActivationEnvelopeV1.issue(plan_sha256="0" * 64, **activation_data)
        plan = LivePlanV1.issue(
            plan_id=bundle.plan.plan_id,
            activation_id=bundle.plan.activation_id,
            activation_hash=preliminary.activation_scope_sha256,
            repository_sha=bundle.plan.repository_sha,
            created_at_utc=bundle.plan.created_at_utc,
            expires_at_utc=bundle.plan.expires_at_utc,
            items=bundle.plan.items,
            maximum_http_calls=bundle.plan.maximum_http_calls,
            maximum_credits=bundle.plan.maximum_credits,
        )
        activation = ActivationEnvelopeV1.issue(
            plan_sha256=plan.canonical_plan_hash,
            **activation_data,
        )
        bundle = Bundle(
            bundle.store,
            bundle.authorization,
            activation,
            plan,
            bundle.item,
            bundle.request,
            bundle.mappings,
        )
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))

    with pytest.raises(LiveGuardError):
        run(bundle, executor(bundle, transport, secret))
    assert secret.reads == transport.calls == 0


@pytest.mark.parametrize(
    "failure",
    (
        "repository_sha",
        "expired_activation",
        "plan_mismatch",
        "capture_root",
        "dry_run",
        "budget_conflict",
    ),
)
def test_all_pre_dispatch_failures_leave_secret_and_transport_untouched(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    failure: str,
) -> None:
    bundle = build_bundle(tmp_path / failure)
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    stages: list[str] = []
    instance = executor(bundle, transport, secret, stages=stages)
    kwargs: dict[str, Any] = {
        "mode": CaptureMode.LIVE_CANARY,
        "authorization": bundle.authorization,
        "activation": bundle.activation,
        "plan": bundle.plan,
        "item": bundle.item,
        "request": bundle.request,
        "mappings": bundle.mappings,
    }
    if failure == "repository_sha":
        instance = executor(
            bundle,
            transport,
            secret,
            repository_sha="b" * 40,
            stages=stages,
        )
    elif failure == "expired_activation":
        instance = executor(
            bundle,
            transport,
            secret,
            clock=TickingClock(bundle.activation.expires_at_utc + timedelta(seconds=1)),
            stages=stages,
        )
    elif failure == "plan_mismatch":
        kwargs["activation"] = ActivationEnvelopeV1.issue(
            **{
                **bundle.activation.model_dump(
                    exclude={"activation_scope_sha256", "canonical_activation_hash"}
                ),
                "plan_sha256": "f" * 64,
            }
        )
    elif failure == "capture_root":
        displaced = tmp_path / "displaced-capture-root"
        bundle.store.root.rename(displaced)
        bundle.store.root.mkdir()
    elif failure == "dry_run":
        kwargs["mode"] = CaptureMode.DRY_RUN
    elif failure == "budget_conflict":
        LiveStateStore(bundle.store).reserve_budget(
            authorization=bundle.authorization,
            activation=bundle.activation,
            plan=bundle.plan,
            item=bundle.item,
            reserved_at=BASE,
        )

    try:
        result = instance.execute(**kwargs)
        assert result.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    except (LiveGuardError, LiveStorageError):
        pass
    assert secret.reads == 0
    assert transport.calls == 0
    if failure == "capture_root":
        assert stages == []
        assert not (bundle.store.root / "live" / "leases").exists()


def test_repository_drift_and_ttl_expiry_are_rechecked_immediately_before_secret(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    drift_bundle = build_bundle(tmp_path / "repo-drift")
    drift_secret = SpySecretReader()
    drift_transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    drift_receipt = run(
        drift_bundle,
        executor(
            drift_bundle,
            drift_transport,
            drift_secret,
            repository_reader=SequenceRepositoryReader(REPOSITORY_SHA, "b" * 40),
        ),
    )
    assert drift_receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    assert drift_secret.reads == drift_transport.calls == 0

    expiry_bundle = build_bundle(
        tmp_path / "ttl-drift",
        activation_expires=BASE + timedelta(seconds=4),
    )
    expiry_secret = SpySecretReader()
    expiry_transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    expiry_receipt = run(
        expiry_bundle,
        executor(expiry_bundle, expiry_transport, expiry_secret),
    )
    assert expiry_receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    assert expiry_secret.reads == expiry_transport.calls == 0


@pytest.mark.parametrize(
    "target",
    (
        "authorization_binding",
        "activation_binding",
        "lease",
        "dispatch",
        "budget",
        "admission",
    ),
)
def test_durable_permit_edges_are_revalidated_after_arm_and_before_secret(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    target: str,
) -> None:
    bundle = build_bundle(tmp_path / target)
    paths = {
        "authorization_binding": bundle.store.root
        / "live"
        / "authority-bindings"
        / (
            "authorization-"
            + canonical_sha256({"authorization_nonce": bundle.authorization.authorization_nonce})
            + ".json"
        ),
        "activation_binding": bundle.store.root
        / "live"
        / "authority-bindings"
        / (
            "activation-"
            + canonical_sha256({"activation_nonce": bundle.activation.activation_nonce})
            + ".json"
        ),
        "lease": bundle.store.root / "live" / "leases" / f"{bundle.item.canonical_item_hash}.json",
        "dispatch": bundle.store.root
        / "live"
        / "dispatch-armed"
        / f"{bundle.item.canonical_item_hash}.json",
        "budget": bundle.store.root / "live-budget-ledger.jsonl",
        "admission": bundle.store.root
        / "live"
        / "admission-consumed"
        / f"{bundle.item.canonical_item_hash}.json",
    }

    def tamper(stage: str) -> None:
        if stage == "AFTER_DISPATCH_ARMED":
            paths[target].parent.mkdir(parents=True, exist_ok=True)
            paths[target].write_bytes(b"{}\n")

    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    if target in {"lease", "budget"}:
        with pytest.raises(
            LiveStorageError,
            match=(
                "LIVE_LEASE_INVALID"
                if target == "lease"
                else "LIVE_BUDGET_LEDGER_ROLLBACK_DETECTED"
            ),
        ):
            run(
                bundle,
                executor(bundle, transport, secret, failure_injector=tamper),
            )
        assert not (
            bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
        ).exists()
        assert secret.reads == transport.calls == 0
        return

    receipt = run(
        bundle,
        executor(bundle, transport, secret, failure_injector=tamper),
    )

    assert receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    assert secret.reads == transport.calls == 0


def test_capture_root_identity_swap_between_gates_stops_without_secret_or_write_through(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "root-swap")
    displaced = tmp_path / "approved-root-displaced"
    swapped = False
    swap_blocked_by_os = False

    def swap(stage: str) -> None:
        nonlocal swap_blocked_by_os, swapped
        if stage == "10_PERSISTENT_BUDGET_RESERVED" and not swapped:
            try:
                bundle.store.root.rename(displaced)
                bundle.store.root.mkdir()
                swapped = True
            except OSError:
                swap_blocked_by_os = True

    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    instance = BoundedLiveCanaryExecutor(
        capture_store=bundle.store,
        repository_state_reader=StaticRepositoryReader(),
        owner_authorization_verifier=PinnedOwnerAuthorizationVerifier(
            bundle.authorization.canonical_authorization_hash
        ),
        secret_reader=secret,
        transport=transport,
        clock=TickingClock(),
        stage_observer=swap,
    )
    if os.name == "nt":
        result = run(bundle, instance)
        assert swap_blocked_by_os is True
        assert result.terminal_disposition is LiveTerminalDisposition.SUCCESS
    else:
        with pytest.raises((CaptureStorageError, LiveStorageError)) as captured:
            run(bundle, instance)
        assert captured.value.code in {
            "LIVE_CAPTURE_ROOT_FINGERPRINT_MISMATCH",
            "CAPTURE_WORKSPACE_IDENTITY_CHANGED",
            "CAPTURE_STORAGE_FILE_IDENTITY_UNAVAILABLE",
        }
        assert swapped is True
        assert secret.reads == transport.calls == 0
        assert list(bundle.store.root.iterdir()) == []


def test_capture_root_swap_after_response_cannot_write_provider_bytes_to_new_root(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "root-swap-after-response")
    displaced = tmp_path / "approved-root-after-response-displaced"
    swap_blocked_by_os = False

    def swap(stage: str) -> None:
        nonlocal swap_blocked_by_os
        if stage == "RAW_SHA256_COMPUTED":
            try:
                bundle.store.root.rename(displaced)
            except PermissionError:
                swap_blocked_by_os = True
                raise CaptureStorageError("CAPTURE_ROOT_SWAP_BLOCKED_BY_OS") from None
            bundle.store.root.mkdir()

    secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    try:
        receipt = run(bundle, executor(bundle, transport, secret, failure_injector=swap))
    except (CaptureStorageError, LiveStorageError) as error:
        assert error.code in {
            "CAPTURE_WORKSPACE_IDENTITY_CHANGED",
            "CAPTURE_STORAGE_FILE_IDENTITY_UNAVAILABLE",
        }
        assert swap_blocked_by_os is False
    else:
        assert swap_blocked_by_os is True
        assert receipt.terminal_disposition is LiveTerminalDisposition.PAYLOAD_REJECTED

    assert secret.reads == transport.calls == 1
    if swap_blocked_by_os:
        assert list((bundle.store.root / "raw" / "sha256").rglob("*.bin")) == []
    else:
        assert list(bundle.store.root.iterdir()) == []
        assert list((displaced / "raw" / "sha256").rglob("*.bin")) == []


def test_same_item_second_execution_never_reads_secret_or_dispatches_again(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    first_secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    assert run(bundle, executor(bundle, transport, first_secret)).terminal_disposition == "SUCCESS"
    second_secret = SpySecretReader()

    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, transport, second_secret))

    assert first_secret.reads == 1
    assert second_secret.reads == 0
    assert transport.calls == 1


@pytest.mark.parametrize(
    ("crash_point", "expected_dispatches"),
    (
        ("AFTER_LEASE", 0),
        ("AFTER_BUDGET_RESERVE", 0),
        ("AFTER_DISPATCH_ARMED", 0),
        ("AFTER_ADMISSION_CONSUMED", 0),
        ("AFTER_DISPATCH_STARTED", 0),
        ("AFTER_RESPONSE", 1),
        ("RAW_SHA256_COMPUTED", 1),
        ("INTAKE_RECEIPT_DURABLE", 1),
        ("RAW_CONTENT_ADDRESSED_DURABLE", 1),
        ("PARSE_STARTED", 1),
        ("SCHEMA_FINGERPRINT_COMPUTED", 1),
        ("NORMALIZATION_COMPLETED", 1),
        ("FINAL_RECEIPT_DURABLE", 1),
        ("LIVE_CAPTURE_LINEAGE_DURABLE", 1),
        ("MANIFEST_DURABLE", 1),
        ("AFTER_EXECUTION_ATTEMPT_PRIMARY", 1),
        ("AFTER_EXECUTION_ATTEMPT_ALIAS", 1),
        ("AFTER_OFFLINE_REPLAY_BEFORE_TERMINAL", 1),
        ("AFTER_TERMINAL_RECEIPT_PRIMARY", 1),
        ("AFTER_TERMINAL_RECEIPT_ALIAS", 1),
        ("AFTER_TERMINAL_MARKER", 1),
    ),
)
def test_crash_boundaries_burn_the_item_and_never_retry(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    crash_point: str,
    expected_dispatches: int,
) -> None:
    bundle = build_bundle(tmp_path / crash_point)
    first_secret = SpySecretReader()
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))

    def crash(stage: str) -> None:
        if stage == crash_point:
            raise SystemExit("synthetic abrupt process death")

    with pytest.raises(SystemExit):
        run(
            bundle,
            executor(bundle, transport, first_secret, failure_injector=crash),
        )
    second_secret = SpySecretReader()
    terminal_before_recovery = {
        "AFTER_LEASE",
        "AFTER_BUDGET_RESERVE",
        "AFTER_DISPATCH_ARMED",
        "AFTER_ADMISSION_CONSUMED",
        "AFTER_TERMINAL_MARKER",
    }
    if crash_point in terminal_before_recovery:
        with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
            run(bundle, executor(bundle, transport, second_secret))
    else:
        recovered = run(bundle, executor(bundle, transport, second_secret))
        expected = (
            LiveTerminalDisposition.SUCCESS
            if crash_point in {"AFTER_TERMINAL_RECEIPT_PRIMARY", "AFTER_TERMINAL_RECEIPT_ALIAS"}
            else LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN
        )
        assert recovered.terminal_disposition is expected

    assert transport.calls == expected_dispatches
    assert second_secret.reads == 0


def test_stale_lease_is_never_interpreted_as_retry_permission(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "capture")
    state = LiveStateStore(bundle.store)
    state.acquire_lease(
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=bundle.item,
        acquired_at=BASE,
    )

    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        state.acquire_lease(
            authorization=bundle.authorization,
            activation=bundle.activation,
            plan=bundle.plan,
            item=bundle.item,
            acquired_at=bundle.item.expires_at_utc + timedelta(days=1),
        )


def test_live_budget_ceiling_minus_one_exact_and_plus_one_are_fail_closed(
    tmp_path: Path,
) -> None:
    base = build_bundle(
        tmp_path / "live-budget-ceiling",
        authorization_maximum_http_calls=2,
        authorization_maximum_credits=4,
        authorization_maximum_plan_items=2,
        activation_maximum_http_calls=2,
        activation_maximum_credits=4,
    )
    second = _issued_item(base, item_id="synthetic-item-002", sequence=2)
    bundle = _bundle_with_plan(base, items=(base.item, second))
    state = LiveStateStore(bundle.store)

    first = state.reserve_budget(
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=bundle.item,
        reserved_at=BASE,
    )
    assert (first.reserved_requests, first.reserved_credits) == (1, 2)
    second_reservation = state.reserve_budget(
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=second,
        reserved_at=BASE + timedelta(seconds=1),
    )
    assert (second_reservation.maximum_requests, second_reservation.maximum_credits) == (
        2,
        4,
    )
    entries = [
        json.loads(line)
        for line in (bundle.store.root / "live-budget-ledger.jsonl").read_text("utf-8").splitlines()
    ]
    assert entries[-1]["reserved_requests"] == 2
    assert entries[-1]["reserved_credits"] == 4

    outside = _issued_item(base, item_id="synthetic-item-003", sequence=3)
    with pytest.raises(LiveStorageError, match="LIVE_BUDGET_ITEM_NOT_IN_PLAN"):
        state.reserve_budget(
            authorization=bundle.authorization,
            activation=bundle.activation,
            plan=bundle.plan,
            item=outside,
            reserved_at=BASE + timedelta(seconds=2),
        )
    assert (
        len((bundle.store.root / "live-budget-ledger.jsonl").read_text("utf-8").splitlines()) == 2
    )


def test_live_prior_lease_tombstone_blocks_double_deletion_budget_reset(
    tmp_path: Path,
) -> None:
    base = build_bundle(
        tmp_path / "live-budget-double-deletion",
        authorization_maximum_http_calls=2,
        authorization_maximum_credits=4,
        authorization_maximum_plan_items=2,
        activation_maximum_http_calls=2,
        activation_maximum_credits=4,
    )
    second = _issued_item(base, item_id="synthetic-item-002", sequence=2)
    bundle = _bundle_with_plan(base, items=(base.item, second))
    state = LiveStateStore(bundle.store)
    state.acquire_lease(
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=bundle.item,
        acquired_at=BASE,
    )
    reservation = state.reserve_budget(
        authorization=bundle.authorization,
        activation=bundle.activation,
        plan=bundle.plan,
        item=bundle.item,
        reserved_at=BASE,
    )
    (bundle.store.root / "live-budget-ledger.jsonl").unlink()
    (bundle.store.root / "live" / "budget-events" / f"{reservation.entry_sha256}.json").unlink()

    restarted = LiveStateStore(bundle.store)
    with pytest.raises(
        LiveStorageError,
        match="LIVE_BUDGET_TOMBSTONE_UNACCOUNTED",
    ):
        restarted.reserve_budget(
            authorization=bundle.authorization,
            activation=bundle.activation,
            plan=bundle.plan,
            item=second,
            reserved_at=BASE + timedelta(seconds=1),
        )
    assert not (bundle.store.root / "live-budget-ledger.jsonl").exists()


def test_two_threads_share_exactly_one_dispatch(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    secrets = (SpySecretReader(), SpySecretReader())
    outcomes: list[object] = []

    def worker(secret: SpySecretReader) -> None:
        try:
            outcomes.append(run(bundle, executor(bundle, transport, secret)))
        except LiveStorageError as error:
            outcomes.append(error)

    threads = [Thread(target=worker, args=(secret,)) for secret in secrets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert transport.calls == 1
    assert sum(secret.reads for secret in secrets) == 1
    assert len([value for value in outcomes if not isinstance(value, Exception)]) == 1
    assert len([value for value in outcomes if isinstance(value, LiveStorageError)]) == 1


@pytest.mark.parametrize(
    ("operation", "loser_code"),
    (
        ("lease", "LIVE_ITEM_ALREADY_LEASED_TERMINAL_NO_RETRY"),
        ("budget", "LIVE_BUDGET_ITEM_ALREADY_RESERVED"),
    ),
)
def test_two_spawned_os_processes_share_one_lease_or_budget_reservation(
    tmp_path: Path,
    operation: str,
    loser_code: str,
) -> None:
    bundle = build_bundle(tmp_path / operation)
    context = mp.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_state_contender,
            args=(str(bundle.store.root), _bundle_wire(bundle), operation, start, results),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(20)

    assert [process.exitcode for process in processes] == [0, 0]
    outcomes = sorted(results.get(timeout=5) for _index in range(2))
    assert outcomes.count("SUCCESS") == 1
    assert len([outcome for outcome in outcomes if loser_code in outcome]) == 1
    if operation == "budget":
        entries = (
            (bundle.store.root / "live-budget-ledger.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(entries) == 1
        assert json.loads(entries[0])["event"] == "RESERVED"


def test_two_spawned_executors_produce_exactly_one_secret_read_and_dispatch(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "executor-process-race")
    context = mp.get_context("spawn")
    start = context.Event()
    secret_reads = context.Value("i", 0)
    dispatches = context.Value("i", 0)
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_executor_contender,
            args=(
                str(bundle.store.root),
                _bundle_wire(bundle),
                payload_bytes(synthetic_pack),
                start,
                secret_reads,
                dispatches,
                results,
            ),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(30)

    assert [process.exitcode for process in processes] == [0, 0]
    outcomes = [results.get(timeout=5) for _index in range(2)]
    assert outcomes.count("SUCCESS") == 1
    assert len([value for value in outcomes if "TERMINAL_NO_RETRY" in value]) == 1
    assert secret_reads.value == 1
    assert dispatches.value == 1


def test_live_item_lock_prevents_recovery_while_dispatcher_is_still_alive(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "dispatcher-alive-lock")
    context = mp.get_context("spawn")
    entered_dispatch = context.Event()
    release_dispatch = context.Event()
    start_contender = context.Event()
    secret_reads = context.Value("i", 0)
    dispatches = context.Value("i", 0)
    results = context.Queue()
    payload = payload_bytes(synthetic_pack)
    first = context.Process(
        target=_process_executor_blocked_in_dispatch,
        args=(
            str(bundle.store.root),
            _bundle_wire(bundle),
            payload,
            entered_dispatch,
            release_dispatch,
            secret_reads,
            dispatches,
            results,
        ),
    )
    first.start()
    assert entered_dispatch.wait(20)

    second = context.Process(
        target=_process_executor_contender,
        args=(
            str(bundle.store.root),
            _bundle_wire(bundle),
            payload,
            start_contender,
            secret_reads,
            dispatches,
            results,
        ),
    )
    second.start()
    start_contender.set()
    second.join(1)
    assert second.is_alive()
    assert secret_reads.value == dispatches.value == 1
    assert not (
        bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
    ).exists()

    release_dispatch.set()
    first.join(30)
    second.join(30)
    assert first.exitcode == second.exitcode == 0
    outcomes = [results.get(timeout=5) for _index in range(2)]
    assert outcomes.count("SUCCESS") == 1
    assert len([value for value in outcomes if "TERMINAL_NO_RETRY" in value]) == 1
    assert secret_reads.value == dispatches.value == 1


@pytest.mark.parametrize(
    ("crash_stage", "exit_code", "expected_budget_events"),
    (
        ("AFTER_LEASE", 71, ()),
        ("AFTER_BUDGET_RESERVE", 72, ("RESERVED",)),
        ("AFTER_DISPATCH_ARMED", 73, ("RESERVED", "DISPATCH_ARMED")),
        ("AFTER_ADMISSION_CONSUMED", 76, ("RESERVED", "DISPATCH_ARMED")),
        ("AFTER_DISPATCH_STARTED", 83, ("RESERVED", "DISPATCH_ARMED")),
        ("DURING_TRANSPORT_DISPATCH", 84, ("RESERVED", "DISPATCH_ARMED")),
        ("AFTER_RESPONSE", 74, ("RESERVED", "DISPATCH_ARMED")),
        ("RAW_SHA256_COMPUTED", 85, ("RESERVED", "DISPATCH_ARMED")),
        ("INTAKE_RECEIPT_DURABLE", 86, ("RESERVED", "DISPATCH_ARMED")),
        ("RAW_CONTENT_ADDRESSED_DURABLE", 87, ("RESERVED", "DISPATCH_ARMED")),
        ("PARSE_STARTED", 88, ("RESERVED", "DISPATCH_ARMED")),
        ("SCHEMA_FINGERPRINT_COMPUTED", 89, ("RESERVED", "DISPATCH_ARMED")),
        ("NORMALIZATION_COMPLETED", 90, ("RESERVED", "DISPATCH_ARMED")),
        ("FINAL_RECEIPT_DURABLE", 75, ("RESERVED", "DISPATCH_ARMED")),
        ("LIVE_CAPTURE_LINEAGE_DURABLE", 91, ("RESERVED", "DISPATCH_ARMED")),
        ("MANIFEST_DURABLE", 92, ("RESERVED", "DISPATCH_ARMED")),
        (
            "AFTER_EXECUTION_ATTEMPT_PRIMARY",
            77,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
        (
            "AFTER_EXECUTION_ATTEMPT_ALIAS",
            78,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
        (
            "AFTER_OFFLINE_REPLAY_BEFORE_TERMINAL",
            79,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
        (
            "AFTER_TERMINAL_RECEIPT_PRIMARY",
            80,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
        (
            "AFTER_TERMINAL_RECEIPT_ALIAS",
            81,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
        (
            "AFTER_TERMINAL_MARKER",
            82,
            ("RESERVED", "DISPATCH_ARMED", "RECONCILED"),
        ),
    ),
)
def test_abrupt_child_process_exit_burns_item_without_automatic_retry(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    crash_stage: str,
    exit_code: int,
    expected_budget_events: tuple[str, ...],
) -> None:
    bundle = build_bundle(tmp_path / crash_stage)
    context = mp.get_context("spawn")
    process = context.Process(
        target=_process_executor_crash,
        args=(
            str(bundle.store.root),
            _bundle_wire(bundle),
            payload_bytes(synthetic_pack),
            crash_stage,
            exit_code,
        ),
    )
    process.start()
    process.join(30)

    assert process.exitcode == exit_code
    ledger = bundle.store.root / "live-budget-ledger.jsonl"
    observed_events = (
        tuple(json.loads(line)["event"] for line in ledger.read_text("utf-8").splitlines())
        if ledger.is_file()
        else ()
    )
    assert observed_events == expected_budget_events
    retry_secret = SpySecretReader()
    retry_transport = FakeTransport(payload=payload_bytes(synthetic_pack))
    no_recovery_marker = {
        "AFTER_LEASE",
        "AFTER_BUDGET_RESERVE",
        "AFTER_DISPATCH_ARMED",
        "AFTER_ADMISSION_CONSUMED",
        "AFTER_TERMINAL_MARKER",
    }
    if crash_stage in no_recovery_marker:
        with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
            run(bundle, executor(bundle, retry_transport, retry_secret))
    else:
        recovered = run(bundle, executor(bundle, retry_transport, retry_secret))
        expected = (
            LiveTerminalDisposition.SUCCESS
            if crash_stage in {"AFTER_TERMINAL_RECEIPT_PRIMARY", "AFTER_TERMINAL_RECEIPT_ALIAS"}
            else LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN
        )
        assert recovered.terminal_disposition is expected
    assert retry_secret.reads == 0
    assert retry_transport.calls == 0


def test_transport_failure_is_terminal_unknown_and_sanitized(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    secret = SpySecretReader()
    transport = FakeTransport(
        payload=payload_bytes(synthetic_pack),
        error=f"synthetic error containing {SYNTHETIC_SECRET}",
    )

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN
    assert receipt.http_status == "UNKNOWN"
    assert receipt.network_calls == receipt.provider_calls == 1
    assert receipt.secret_reads_count == 1
    assert SYNTHETIC_SECRET not in receipt.model_dump_json()
    assert transport.calls == 1


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("invalid_json", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("oversized", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("schema_drift", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("malicious_string", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("nan", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("nonfinite_exponent", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("int64_out_of_range", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("surrogate", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("deep_nesting", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("http_503", LiveTerminalDisposition.HTTP_REJECTED),
        ("http_302", LiveTerminalDisposition.HTTP_REJECTED),
        ("location", LiveTerminalDisposition.HTTP_REJECTED),
        ("quota_missing", LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED),
        ("quota_mismatch", LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED),
        ("sport_mismatch", LiveTerminalDisposition.PAYLOAD_REJECTED),
        ("unrequested_market", LiveTerminalDisposition.PAYLOAD_REJECTED),
    ),
)
def test_live_response_rejection_matrix_is_hashed_and_terminal(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    case: str,
    expected: LiveTerminalDisposition,
) -> None:
    markets = ("h2h",) if case == "unrequested_market" else ("h2h", "totals")
    bundle = build_bundle(tmp_path / case, markets=markets)
    payload = payload_bytes(synthetic_pack)
    status = 200
    headers = {
        "x-requests-last": str(len(markets)),
        "x-requests-used": str(len(markets)),
        "x-requests-remaining": "998",
    }
    maximum_payload_bytes = 1_048_576
    if case == "invalid_json":
        payload = b"{"
    elif case == "oversized":
        maximum_payload_bytes = 8
    elif case == "schema_drift":
        payload = b'{"unexpected":true}'
    elif case == "malicious_string":
        material = json.loads(payload)
        material[0]["bookmakers"][0]["markets"][0]["outcomes"][0]["name"] = "<script>" + (
            "x" * 5000
        )
        payload = json.dumps(material, separators=(",", ":")).encode()
    elif case == "nan":
        payload = b'[{"price":NaN}]'
    elif case == "nonfinite_exponent":
        payload = b'[{"price":1e999}]'
    elif case == "int64_out_of_range":
        payload = b'[{"price":9223372036854775808}]'
    elif case == "surrogate":
        payload = b'[{"name":"\\ud800"}]'
    elif case == "deep_nesting":
        payload = (b"[" * 1000) + b"0" + (b"]" * 1000)
    elif case == "http_503":
        status = 503
    elif case == "http_302":
        status = 302
    elif case == "location":
        headers["location"] = "PRESENT"
    elif case == "quota_missing":
        headers = {"content-type": "application/json"}
    elif case == "quota_mismatch":
        headers["x-requests-last"] = "1"
    elif case == "sport_mismatch":
        payload = payload_bytes(synthetic_pack, sport_key="soccer_epl")
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload, status=status, headers=headers)

    receipt = run(
        bundle,
        executor(
            bundle,
            transport,
            secret,
            maximum_payload_bytes=maximum_payload_bytes,
        ),
    )

    assert receipt.terminal_disposition is expected
    assert receipt.manifest_id is None
    assert receipt.execution_attempt_id is not None
    assert receipt.payload_sha256 == __import__("hashlib").sha256(payload).hexdigest()
    assert secret.reads == transport.calls == 1
    raw_files = list((bundle.store.root / "raw" / "sha256").rglob("*.bin"))
    assert bool(raw_files) is (case != "oversized")


@pytest.mark.parametrize("case", ("payload_echo", "header_echo", "compressed"))
def test_fake_transport_response_security_rejects_before_persistence(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    case: str,
) -> None:
    bundle = build_bundle(tmp_path / case)
    payload = payload_bytes(synthetic_pack)
    headers = {
        "x-requests-last": "2",
        "x-requests-used": "2",
        "x-requests-remaining": "998",
    }
    if case == "payload_echo":
        payload = f'{{"echo":"{SYNTHETIC_SECRET}"}}'.encode()
    elif case == "header_echo":
        headers["x-synthetic-echo"] = SYNTHETIC_SECRET
    else:
        headers["content-encoding"] = "gzip"
    secret = SpySecretReader()
    transport = FakeTransport(payload=payload, headers=headers)

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN
    assert receipt.manifest_id is receipt.payload_sha256 is None
    assert list((bundle.store.root / "raw" / "sha256").rglob("*.bin")) == []
    persisted = b"".join(
        path.read_bytes() for path in bundle.store.root.rglob("*") if path.is_file()
    )
    assert SYNTHETIC_SECRET.encode() not in persisted


def test_transport_preflight_failure_is_terminal_before_secret_and_no_retry(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "capture")
    secret = SpySecretReader()
    transport = FakeTransport(
        payload=payload_bytes(synthetic_pack),
        preflight_error="LIVE_TRANSPORT_TLS_TRUST_ENV_FORBIDDEN",
    )

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    assert receipt.network_calls == receipt.provider_calls == 0
    assert receipt.secret_reads_count == secret.reads == 0
    assert transport.preflights == 1
    assert transport.calls == 0
    retry_secret = SpySecretReader()
    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, transport, retry_secret))
    assert retry_secret.reads == 0


def test_invalid_secret_value_is_terminal_after_one_read_without_dispatch(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "invalid-secret")
    secret = SpySecretReader("unicode-é-invalid")
    transport = FakeTransport(payload=payload_bytes(synthetic_pack))

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED
    assert receipt.secret_reads_count == secret.reads == 1
    assert receipt.network_calls == transport.calls == 0
    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, transport, SpySecretReader()))


def test_out_of_int64_quota_counters_are_terminal_readable_and_never_retried(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "quota-out-of-int64")
    payload = payload_bytes(synthetic_pack)
    transport = FakeTransport(
        payload=payload,
        headers={
            "x-requests-last": "2",
            "x-requests-used": str(2**63),
            "x-requests-remaining": str(2**63),
        },
    )
    secret = SpySecretReader()

    receipt = run(bundle, executor(bundle, transport, secret))

    assert receipt.terminal_disposition is LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED
    assert receipt.execution_attempt_id is not None
    assert receipt.final_receipt_id is not None
    assert receipt.manifest_id is None
    assert receipt.observed_quota is None
    assert receipt.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert secret.reads == transport.calls == 1

    final_receipt = bundle.store.load_receipt(receipt.final_receipt_id)
    assert final_receipt.rejection_code == "CAPTURE_QUOTA_HEADERS_INVALID"
    assert final_receipt.quota is None
    attempt = LiveStateStore(bundle.store).load_execution_attempt(
        receipt.execution_attempt_id,
        manifest_id=None,
    )
    assert attempt.capture_receipt_id == final_receipt.receipt_id
    terminal_path = (
        bundle.store.root / "live" / "execution-receipts" / f"{receipt.execution_receipt_id}.json"
    )
    assert LiveExecutionReceiptV1.model_validate_json(terminal_path.read_bytes()) == receipt
    assert LiveStateStore(bundle.store).terminal_marker_exists(bundle.item.canonical_item_hash)

    retry_secret = SpySecretReader()
    retry_transport = FakeTransport(payload=payload)
    with pytest.raises(LiveStorageError, match="TERMINAL_NO_RETRY"):
        run(bundle, executor(bundle, retry_transport, retry_secret))
    assert retry_secret.reads == retry_transport.calls == 0
    assert transport.calls == 1


def test_terminal_store_refuses_self_consistent_receipt_without_durable_lease(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path / "forged-terminal-without-lease")
    lease_id = "d" * 64
    forged = LiveExecutionReceiptV1.issue(
        authorization_id=bundle.authorization.authorization_id,
        authorization_hash=bundle.authorization.canonical_authorization_hash,
        activation_id=bundle.activation.activation_id,
        activation_hash=bundle.activation.canonical_activation_hash,
        repository_sha=bundle.activation.repository_sha,
        plan_id=bundle.plan.plan_id,
        plan_hash=bundle.plan.canonical_plan_hash,
        item_id=bundle.item.item_id,
        item_hash=bundle.item.canonical_item_hash,
        lease_id=lease_id,
        lease_hash=lease_id,
        request_fingerprint_sha256=bundle.item.provider_request_fingerprint,
        terminal_at_utc=BASE,
        http_status="UNKNOWN",
        network_calls=0,
        provider_calls=0,
        reserved_requests=0,
        reserved_credits=0,
        offline_replay_verdict="NOT_POSSIBLE",
        secret_reads_count=0,
        terminal_disposition=LiveTerminalDisposition.PRE_DISPATCH_REJECTED,
    )
    state = LiveStateStore(bundle.store)

    with pytest.raises(LiveStorageError):
        state.store_terminal_receipt(forged)

    primary = (
        bundle.store.root / "live" / "execution-receipts" / f"{forged.execution_receipt_id}.json"
    )
    terminal = bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
    assert not primary.exists()
    assert not terminal.exists()


def test_terminal_store_refuses_rehashed_receipt_diverging_from_durable_attempt(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    bundle = build_bundle(tmp_path / "forged-terminal-attempt-mismatch")
    payload = payload_bytes(synthetic_pack)

    def stop_after_preterminal_replay(stage: str) -> None:
        if stage == "AFTER_OFFLINE_REPLAY_BEFORE_TERMINAL":
            raise SystemExit("synthetic stop after durable attempt")

    with pytest.raises(SystemExit, match="synthetic stop after durable attempt"):
        run(
            bundle,
            executor(
                bundle,
                FakeTransport(payload=payload),
                SpySecretReader(),
                failure_injector=stop_after_preterminal_replay,
            ),
        )

    manifest_paths = tuple((bundle.store.root / "manifests").glob("*.json"))
    attempt_paths = tuple((bundle.store.root / "live" / "execution-attempts").glob("*.json"))
    assert len(manifest_paths) == len(attempt_paths) == 1
    manifest = bundle.store.load_manifest(manifest_paths[0].stem)
    state = LiveStateStore(bundle.store)
    attempt = state.load_execution_attempt(
        attempt_paths[0].stem,
        manifest_id=manifest.snapshot_id,
    )
    assert attempt.capture_receipt_id is not None
    capture_receipt = bundle.store.load_receipt(attempt.capture_receipt_id)
    started = state.load_dispatch_started(bundle.item.canonical_item_hash)
    assert started is not None
    assert capture_receipt.intake_receipt_id is not None
    assert capture_receipt.quota is not None

    forged = LiveExecutionReceiptV1.issue(
        authorization_id=bundle.authorization.authorization_id,
        authorization_hash=bundle.authorization.canonical_authorization_hash,
        activation_id=bundle.activation.activation_id,
        activation_hash=bundle.activation.canonical_activation_hash,
        repository_sha=bundle.activation.repository_sha,
        plan_id=bundle.plan.plan_id,
        plan_hash=bundle.plan.canonical_plan_hash,
        item_id=bundle.item.item_id,
        item_hash=bundle.item.canonical_item_hash,
        lease_id=started.lease.lease_id,
        lease_hash=started.lease.lease_id,
        request_fingerprint_sha256=attempt.request_fingerprint_sha256,
        response_intake_claim_sha256=attempt.response_intake_claim_sha256,
        execution_attempt_id=attempt.execution_attempt_id,
        dispatch_started_at_utc=attempt.dispatch_started_at_utc,
        first_observed_at_utc=attempt.first_observed_at_utc,
        ingested_at_utc=attempt.ingested_at_utc,
        terminal_at_utc=attempt.prepared_at_utc + timedelta(seconds=1),
        http_status=attempt.http_status,
        network_calls=1,
        provider_calls=1,
        reserved_requests=1,
        reserved_credits=started.admission_permit.reserved_credits,
        observed_quota=capture_receipt.quota,
        payload_sha256=attempt.payload_sha256,
        payload_byte_length=attempt.payload_byte_length + 1,
        intake_receipt_id=capture_receipt.intake_receipt_id,
        final_receipt_id=capture_receipt.receipt_id,
        manifest_id=manifest.snapshot_id,
        manifest_hash=manifest.manifest_sha256,
        offline_replay_verdict="ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN",
        secret_reads_count=1,
        terminal_disposition=LiveTerminalDisposition.SUCCESS,
    )

    with pytest.raises(LiveStorageError, match="LIVE_TERMINAL_RECEIPT"):
        state.store_terminal_receipt(forged)

    primary = (
        bundle.store.root / "live" / "execution-receipts" / f"{forged.execution_receipt_id}.json"
    )
    alias = (
        bundle.store.root
        / "live"
        / "execution-receipts"
        / "by-manifest"
        / f"{manifest.snapshot_id}.json"
    )
    terminal = bundle.store.root / "live" / "terminal" / f"{bundle.item.canonical_item_hash}.json"
    assert not primary.exists()
    assert not alias.exists()
    assert not terminal.exists()
