from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from robin.capture.live_transport import LiveTransportResponse, PublicProviderRequestV1
from robin.capture.reprise_collecte import (
    NetworkResolution,
    PilotConfig,
    PilotError,
    run_reprise_collecte,
)
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalPutOutcome,
    ConditionalPutResult,
    ObservedObject,
)

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 10, 2, 18, 40, tzinfo=UTC)
SECRET = "test_provider_key_1234567890"
SAFETY_ENVIRONMENT = {
    "STORAGE_PAUSED": "true",
    "P3_P4_PAUSED": "true",
    "PRODUCTION_LOCKED": "true",
    "REAL_BETS": "false",
    "NO_BET_DEFAULT": "true",
    "PROMOTION_LOCKED": "true",
    "SOCIAL_PUBLISHING_ENABLED": "false",
    "DEMO_MODE_ENABLED": "false",
    "API_FOOTBALL_CALLS_ALLOWED": "0",
}


class ManualClock:
    def __init__(self, current: datetime = START) -> None:
        self.current = current
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += timedelta(seconds=seconds)


class FakeSecretReader:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reads = 0

    def read(self) -> str:
        self.reads += 1
        self.events.append("secret-read")
        return SECRET


class FakeStore:
    def __init__(
        self,
        events: list[str],
        *,
        forced_outcomes: Mapping[int, ConditionalPutOutcome] | None = None,
        corrupt_readback_suffix: str | None = None,
    ) -> None:
        self.events = events
        self.forced_outcomes = dict(forced_outcomes or {})
        self.corrupt_readback_suffix = corrupt_readback_suffix
        self.objects: dict[str, ObservedObject] = {}
        self.puts: list[str] = []
        self.gets: list[str] = []

    def put_if_absent(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult:
        on_dispatch()
        ordinal = len(self.puts) + 1
        self.puts.append(key)
        self.events.append(f"r2-put:{Path(key).name}")
        forced = self.forced_outcomes.get(ordinal)
        if forced is not None:
            return ConditionalPutResult(outcome=forced)
        if key in self.objects:
            return ConditionalPutResult(outcome=ConditionalPutOutcome.PRECONDITION_FAILED)
        self.objects[key] = ObservedObject(data=data, metadata=dict(metadata))
        return ConditionalPutResult(
            outcome=ConditionalPutOutcome.CREATED,
            request_id=f"put-{ordinal}",
            etag=f'"etag-{ordinal}"',
        )

    def get_object(self, key: str) -> ObservedObject | None:
        self.gets.append(key)
        self.events.append(f"r2-get:{Path(key).name}")
        observed = self.objects.get(key)
        if observed is None:
            return None
        if self.corrupt_readback_suffix and key.endswith(self.corrupt_readback_suffix):
            return ObservedObject(data=observed.data + b"corrupt", metadata=observed.metadata)
        return observed


class FakeTransportFactory:
    def __init__(
        self,
        events: list[str],
        clock: ManualClock,
        responses: list[tuple[bytes, Mapping[str, str], int]],
    ) -> None:
        self.events = events
        self.clock = clock
        self.responses = list(responses)
        self.dispatches = 0
        self.requests: list[PublicProviderRequestV1] = []

    def __call__(self, _clock: Callable[[], datetime]) -> FakeTransport:
        return FakeTransport(self)


class FakeTransport:
    def __init__(self, owner: FakeTransportFactory) -> None:
        self.owner = owner
        self.preflighted: PublicProviderRequestV1 | None = None

    def preflight(self, request: PublicProviderRequestV1) -> None:
        assert request.retries == 0
        assert request.redirects == 0
        assert request.markets == ("h2h",)
        self.preflighted = request

    def dispatch(
        self,
        request: PublicProviderRequestV1,
        *,
        api_key: str,
    ) -> LiveTransportResponse:
        assert self.preflighted == request
        assert api_key == SECRET
        payload, headers, status = self.owner.responses[self.owner.dispatches]
        self.owner.dispatches += 1
        self.owner.requests.append(request)
        self.owner.events.append(f"provider-get:{self.owner.dispatches}")
        return LiveTransportResponse(
            http_status=status,
            headers=headers,
            payload=payload,
            first_observed_at_utc=self.owner.clock(),
        )


def _payload(
    *,
    home: str = "<Arsenal>",
    away: str = "=Fulham",
    home_price: float = 1.61,
    draw_price: float = 4.2,
    away_price: float = 5.4,
    source_time: str = "2026-10-02T18:35:00Z",
) -> bytes:
    return json.dumps(
        [
            {
                "id": "event-1",
                "sport_key": "soccer_epl",
                "sport_title": "Premier League",
                "commence_time": "2026-10-10T14:00:00Z",
                "home_team": home,
                "away_team": away,
                "bookmakers": [
                    {
                        "key": "book-a",
                        "title": "Book A",
                        "last_update": source_time,
                        "markets": [
                            {
                                "key": "h2h",
                                "outcomes": [
                                    {"name": home, "price": home_price},
                                    {"name": "Draw", "price": draw_price},
                                    {"name": away, "price": away_price},
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
        separators=(",", ":"),
    ).encode()


def _headers(*, last: str = "1", remaining: str = "98", used: str = "2") -> dict[str, str]:
    return {
        "x-requests-last": last,
        "x-requests-remaining": remaining,
        "x-requests-used": used,
    }


def _config(tmp_path: Path, *, run_attempt: int = 1) -> PilotConfig:
    return PilotConfig(
        manifest_path=ROOT / "configs/execution/reprise-collecte-20261002.json",
        output_directory=tmp_path,
        repository_sha="a" * 40,
        github_run_id="424242",
        github_run_attempt=run_attempt,
        interval_seconds=120,
        safety_environment=SAFETY_ENVIRONMENT,
    )


def _dependencies(
    tmp_path: Path,
    *,
    responses: list[tuple[bytes, Mapping[str, str], int]],
    forced_outcomes: Mapping[int, ConditionalPutOutcome] | None = None,
    corrupt_readback_suffix: str | None = None,
) -> tuple[
    PilotConfig,
    ManualClock,
    FakeStore,
    FakeTransportFactory,
    FakeSecretReader,
    list[str],
    Callable[[], NetworkResolution],
]:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(
        events,
        forced_outcomes=forced_outcomes,
        corrupt_readback_suffix=corrupt_readback_suffix,
    )
    transports = FakeTransportFactory(events, clock, responses)
    secret_reader = FakeSecretReader(events)
    resolution_calls = 0

    def resolve() -> NetworkResolution:
        nonlocal resolution_calls
        resolution_calls += 1
        events.append(f"dns:{resolution_calls}")
        return NetworkResolution(
            selected_ip_address="1.1.1.1",
            resolved_ip_addresses=("1.1.1.1", "2606:4700:4700::1111"),
            observed_at_utc=clock(),
            expires_at_utc=clock() + timedelta(minutes=15),
            resolver_identity="TEST_RESOLVER",
            resolution_operations=1,
        )

    return _config(tmp_path), clock, store, transports, secret_reader, events, resolve


def test_two_real_shape_captures_are_persisted_replayed_and_rendered_without_public_odds(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies(
        tmp_path,
        responses=[
            (_payload(), _headers(last="1", remaining="98", used="2"), 200),
            (
                _payload(home_price=1.63, draw_price=4.1, away_price=5.2),
                _headers(last="1", remaining="97", used="3"),
                200,
            ),
        ],
    )
    config, clock, store, transports, secret_reader, events, resolver = dependencies

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "COLLECTE_REELLE_VERIFIEE"
    assert receipt["capture_count"] == 2
    assert receipt["provider_requests"] == 2
    assert receipt["credits_consumed"] == 2
    assert receipt["row_count"] == 2
    assert receipt["match_count"] == 1
    assert receipt["bookmaker_count"] == 1
    assert receipt["r2_put_requests"] == 5
    assert receipt["r2_get_requests"] == 3
    assert receipt["dns_resolutions"] == 1
    assert receipt["secret_reads"] == 1
    assert receipt["capture_times_utc"] == [
        "2026-10-02T18:40:00Z",
        "2026-10-02T18:42:00Z",
    ]
    assert clock.sleeps == [120]
    assert transports.dispatches == 2
    assert secret_reader.reads == 1
    assert {request.approved_provider_ip_address for request in transports.requests} == {"1.1.1.1"}
    assert len(store.puts) == 5
    assert len(store.gets) == 3
    assert events == [
        "r2-put:attempt-1-reservation.json",
        "dns:1",
        "secret-read",
        "provider-get:1",
        "r2-put:capture-1.json",
        "r2-get:capture-1.json",
        "r2-put:attempt-2-reservation.json",
        "provider-get:2",
        "r2-put:capture-2.json",
        "r2-get:capture-2.json",
        "r2-put:private-report.json",
        "r2-get:private-report.json",
    ]

    public_path = tmp_path / "public-receipt.json"
    private_path = tmp_path / "reprise-collecte-private.json"
    csv_path = tmp_path / "reprise-collecte.csv"
    html_path = tmp_path / "reprise-collecte.html"
    assert json.loads(public_path.read_text(encoding="utf-8")) == receipt
    public_text = public_path.read_text(encoding="utf-8")
    assert "Arsenal" not in public_text
    assert "Fulham" not in public_text
    assert '"odds_1"' not in public_text
    assert "private_report_r2_key" not in public_text
    assert "robin/reprise-collecte/" not in public_text

    private_report = json.loads(private_path.read_text(encoding="utf-8"))
    assert [row["odds_1"] for row in private_report["rows"]] == [1.61, 1.63]
    assert all(row["odds_n"] > 1 for row in private_report["rows"])
    assert all(row["odds_2"] > 1 for row in private_report["rows"])
    assert "raw_payload_base64" not in private_path.read_text(encoding="utf-8")
    csv_text = csv_path.read_text(encoding="utf-8")
    assert "'<Arsenal>" not in csv_text
    assert "'=Fulham" in csv_text
    html_text = html_path.read_text(encoding="utf-8")
    assert "&lt;Arsenal&gt;" in html_text
    assert "<script" not in html_text.casefold()

    for filename, key in (
        ("reprise-collecte-private.json", "private_json_sha256"),
        ("reprise-collecte.csv", "csv_sha256"),
        ("reprise-collecte.html", "html_sha256"),
    ):
        assert hashlib.sha256((tmp_path / filename).read_bytes()).hexdigest() == receipt[key]

    capture_keys = [key for key in store.objects if key.endswith("capture-1.json")]
    assert len(capture_keys) == 1
    envelope = json.loads(store.objects[capture_keys[0]].data)
    assert base64.b64decode(envelope["raw_payload_base64"]) == _payload()
    assert envelope["raw_payload_sha256"] == hashlib.sha256(_payload()).hexdigest()
    assert envelope["pre_storage_validation_status"] == "PASS"
    assert envelope["pre_storage_validation_error_code"] is None
    assert "audit_status" not in envelope
    assert "offline_replay_rows_sha256" not in envelope


def test_event_without_bookmakers_is_retained_raw_but_skipped_when_other_odds_exist(
    tmp_path: Path,
) -> None:
    valid_events = json.loads(_payload())
    empty_event = {
        "id": "event-empty",
        "sport_key": "soccer_epl",
        "sport_title": "Premier League",
        "commence_time": "2026-10-11T14:00:00Z",
        "home_team": "Chelsea",
        "away_team": "Liverpool",
        "bookmakers": [],
    }
    mixed_payload = json.dumps([empty_event, *valid_events], separators=(",", ":")).encode()
    config, clock, store, transports, secret_reader, _events, resolver = _dependencies(
        tmp_path,
        responses=[
            (mixed_payload, _headers(last="1", remaining="98", used="2"), 200),
            (mixed_payload, _headers(last="1", remaining="97", used="3"), 200),
        ],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "COLLECTE_REELLE_VERIFIEE"
    assert receipt["row_count"] == 2
    assert receipt["match_count"] == 1
    capture = next(value for key, value in store.objects.items() if key.endswith("capture-1.json"))
    assert base64.b64decode(json.loads(capture.data)["raw_payload_base64"]) == mixed_payload


def test_second_dispatch_failure_delivers_first_capture_as_explicit_partial(
    tmp_path: Path,
) -> None:
    config, clock, store, transports, secret_reader, _events, resolver = _dependencies(
        tmp_path,
        responses=[
            (_payload(), _headers(last="1", remaining="98", used="2"), 200),
        ],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_PROVIDER_DISPATCH_FAILED"
    assert receipt["validated_capture_count"] == 1
    assert receipt["provider_dispatch_attempts"] == 2
    assert receipt["credits_consumed"] is None
    assert receipt["credits_consumed_confirmed_minimum"] == 1
    assert receipt["credits_consumed_authorized_upper_bound"] == 4
    assert receipt["credit_accounting_status"] == "BOUNDED_UNKNOWN"
    assert receipt["private_report_r2_status"] == "NOT_ATTEMPTED_PARTIAL"
    assert len(store.puts) == 3
    assert len(store.gets) == 1
    assert transports.dispatches == 1
    assert {path.name for path in tmp_path.iterdir()} == {
        "public-receipt.json",
        "reprise-collecte-private.json",
        "reprise-collecte.csv",
        "reprise-collecte.html",
    }
    private = json.loads((tmp_path / "reprise-collecte-private.json").read_text("utf-8"))
    assert private["status"] == "PARTIEL"
    assert private["failure_stage"] == "CAPTURE_2_DISPATCH"
    assert private["failure_code"] == "REPRISE_PROVIDER_DISPATCH_FAILED"
    assert len(private["captures"]) == 1
    assert {row["capture_index"] for row in private["rows"]} == {1}
    assert "Arsenal" not in (tmp_path / "public-receipt.json").read_text("utf-8")


def test_second_invalid_payload_keeps_failed_raw_evidence_without_false_replay(
    tmp_path: Path,
) -> None:
    config, clock, store, transports, secret_reader, _events, resolver = _dependencies(
        tmp_path,
        responses=[
            (_payload(), _headers(last="1", remaining="98", used="2"), 200),
            (b"[]", _headers(last="1", remaining="97", used="3"), 200),
        ],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_NO_UPCOMING_ODDS"
    assert receipt["validated_capture_count"] == 1
    assert receipt["provider_dispatch_attempts"] == 2
    assert receipt["credits_consumed"] is None
    assert receipt["credits_consumed_confirmed_minimum"] == 2
    assert receipt["credit_accounting_status"] == "BOUNDED_UNKNOWN"
    assert len(receipt["raw_capture_object_sha256"]) == 2
    private = json.loads((tmp_path / "reprise-collecte-private.json").read_text("utf-8"))
    assert private["failed_capture"]["capture_index"] == 2
    assert private["failed_capture"]["readback_verified"] is True
    assert private["retention"]["offline_replay_verified"] is False
    assert len(store.puts) == 4
    assert len(store.gets) == 2


@pytest.mark.parametrize(
    "second_headers",
    [
        _headers(last="1", remaining="97", used="4"),
        _headers(last="1", remaining="96", used="3"),
    ],
)
def test_inexact_second_quota_sequence_is_partial_and_never_claimed_exact(
    tmp_path: Path,
    second_headers: Mapping[str, str],
) -> None:
    config, clock, store, transports, secret_reader, _events, resolver = _dependencies(
        tmp_path,
        responses=[
            (_payload(), _headers(last="1", remaining="98", used="2"), 200),
            (_payload(home_price=1.63), second_headers, 200),
        ],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_QUOTA_SEQUENCE_INVALID"
    assert receipt["validated_capture_count"] == 1
    assert receipt["provider_dispatch_attempts"] == 2
    assert receipt["credits_consumed"] is None
    assert receipt["credit_accounting_status"] == "BOUNDED_UNKNOWN"
    assert len(store.puts) == 4
    assert len(store.gets) == 2
    private = json.loads((tmp_path / "reprise-collecte-private.json").read_text("utf-8"))
    assert len(private["captures"]) == 1
    assert {row["capture_index"] for row in private["rows"]} == {1}


@pytest.mark.parametrize(
    ("forced_outcomes", "corrupt_readback_suffix", "expected_gets"),
    [
        ({5: ConditionalPutOutcome.PRECONDITION_FAILED}, None, 2),
        ({}, "private-report.json", 3),
    ],
)
def test_private_report_persistence_failure_delivers_two_capture_partial(
    tmp_path: Path,
    forced_outcomes: Mapping[int, ConditionalPutOutcome],
    corrupt_readback_suffix: str | None,
    expected_gets: int,
) -> None:
    config, clock, store, transports, secret_reader, _events, resolver = _dependencies(
        tmp_path,
        responses=[
            (_payload(), _headers(last="1", remaining="98", used="2"), 200),
            (_payload(home_price=1.63), _headers(last="1", remaining="97", used="3"), 200),
        ],
        forced_outcomes=forced_outcomes,
        corrupt_readback_suffix=corrupt_readback_suffix,
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["failure_stage"] == "PRIVATE_REPORT_PERSISTENCE"
    assert receipt["validated_capture_count"] == 2
    assert receipt["credits_consumed"] == 2
    assert receipt["credit_accounting_status"] == "EXACT"
    assert receipt["private_report_r2_status"] == "UNVERIFIED"
    assert receipt["private_report_r2_sha256"] is None
    assert len(store.puts) == 5
    assert len(store.gets) == expected_gets
    private = json.loads((tmp_path / "reprise-collecte-private.json").read_text("utf-8"))
    assert private["status"] == "PARTIEL"
    assert len(private["captures"]) == 2
    assert {row["capture_index"] for row in private["rows"]} == {1, 2}


@pytest.mark.parametrize(
    ("headers", "expected_code"),
    [
        ({"x-requests-last": "1", "x-requests-used": "2"}, "REPRISE_QUOTA_HEADERS_MISSING"),
        (_headers(last="3"), "REPRISE_CREDIT_COST_UNEXPECTED"),
        (_headers(last="2", used="1"), "REPRISE_QUOTA_HEADERS_INVALID"),
    ],
)
def test_invalid_first_quota_preserves_raw_and_forbids_the_second_call(
    tmp_path: Path,
    headers: Mapping[str, str],
    expected_code: str,
) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[(_payload(), headers, 200)],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == expected_code
    assert receipt["failure_stage"] == "CAPTURE_1_AUDIT"
    assert receipt["validated_capture_count"] == 0
    assert receipt["row_count"] == 0
    assert receipt["source_timestamp_min_utc"] is None
    assert receipt["source_timestamp_max_utc"] is None
    assert receipt["credits_consumed"] is None
    assert receipt["credits_consumed_confirmed_minimum"] == 0
    assert receipt["credit_accounting_status"] == "BOUNDED_UNKNOWN"
    assert transports.dispatches == 1
    assert len(store.puts) == 2
    assert len(store.gets) == 1
    assert clock.sleeps == []
    assert not any("attempt-2" in event for event in events)
    assert {path.name for path in tmp_path.iterdir()} == {
        "public-receipt.json",
        "reprise-collecte-private.json",
        "reprise-collecte.csv",
        "reprise-collecte.html",
    }
    capture = next(value for key, value in store.objects.items() if key.endswith("capture-1.json"))
    assert base64.b64decode(json.loads(capture.data)["raw_payload_base64"]) == _payload()


def test_global_reservation_conflict_prevents_dns_secret_and_provider_effects(
    tmp_path: Path,
) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[(_payload(), _headers(), 200)],
        forced_outcomes={1: ConditionalPutOutcome.PRECONDITION_FAILED},
    )

    with pytest.raises(PilotError, match="REPRISE_R2_RESERVATION_NOT_CREATED"):
        run_reprise_collecte(
            config,
            store=store,
            transport_factory=transports,
            secret_reader=secret_reader,
            resolver=resolver,
            clock=clock,
            monotonic=lambda: 10.0,
            sleeper=clock.sleep,
        )

    assert events == ["r2-put:attempt-1-reservation.json"]
    assert transports.dispatches == 0
    assert secret_reader.reads == 0
    assert store.gets == []


def test_changed_r2_readback_is_terminal_before_second_reservation(tmp_path: Path) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[(_payload(), _headers(), 200)],
        corrupt_readback_suffix="capture-1.json",
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_R2_READBACK_MISMATCH"
    assert receipt["failure_stage"] == "CAPTURE_1_REPLAY"
    assert receipt["validated_capture_count"] == 0
    assert transports.dispatches == 1
    assert len(store.puts) == 2
    assert len(store.gets) == 1
    assert not any("attempt-2" in event for event in events)


def test_empty_first_payload_is_durably_retained_but_never_scaled(tmp_path: Path) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[(b"[]", _headers(), 200)],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_NO_UPCOMING_ODDS"
    assert receipt["failure_stage"] == "CAPTURE_1_AUDIT"
    assert receipt["validated_capture_count"] == 0
    assert receipt["row_count"] == 0
    assert receipt["credits_consumed"] is None
    assert receipt["credits_consumed_confirmed_minimum"] == 1
    private = json.loads((tmp_path / "reprise-collecte-private.json").read_text("utf-8"))
    failed = private["failed_capture"]
    assert failed["capture_index"] == 1
    assert failed["readback_verified"] is True
    assert receipt["raw_capture_object_sha256"] == [failed["raw_object_sha256"]]
    public_text = (tmp_path / "public-receipt.json").read_text("utf-8")
    assert failed["raw_object_key"] not in public_text
    assert private["retention"]["offline_replay_verified"] is False
    csv_lines = (tmp_path / "reprise-collecte.csv").read_text("utf-8").splitlines()
    assert len(csv_lines) == 1
    assert "0 lignes vérifiées" in (tmp_path / "reprise-collecte.html").read_text("utf-8")
    assert transports.dispatches == 1
    assert len(store.puts) == 2
    assert len(store.gets) == 1
    assert not any("attempt-2" in event for event in events)


def test_stale_provider_timestamp_is_retained_but_never_scaled(tmp_path: Path) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[
            (
                _payload(source_time="2026-10-02T18:24:59Z"),
                _headers(),
                200,
            )
        ],
    )

    receipt = run_reprise_collecte(
        config,
        store=store,
        transport_factory=transports,
        secret_reader=secret_reader,
        resolver=resolver,
        clock=clock,
        monotonic=lambda: 10.0,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "PARTIEL"
    assert receipt["partial_reason_code"] == "REPRISE_SOURCE_TIMESTAMP_STALE"
    assert receipt["failure_stage"] == "CAPTURE_1_AUDIT"
    assert receipt["validated_capture_count"] == 0
    assert receipt["row_count"] == 0
    assert receipt["credits_consumed_confirmed_minimum"] == 1
    assert transports.dispatches == 1
    assert len(store.puts) == 2
    assert len(store.gets) == 1
    assert not any("attempt-2" in event for event in events)


def test_workflow_rerun_attempt_is_rejected_before_any_external_effect(tmp_path: Path) -> None:
    config, clock, store, transports, secret_reader, events, resolver = _dependencies(
        tmp_path,
        responses=[(_payload(), _headers(), 200)],
    )
    config = _config(tmp_path, run_attempt=2)

    with pytest.raises(PilotError, match="REPRISE_WORKFLOW_RERUN_FORBIDDEN"):
        run_reprise_collecte(
            config,
            store=store,
            transport_factory=transports,
            secret_reader=secret_reader,
            resolver=resolver,
            clock=clock,
            monotonic=lambda: 10.0,
            sleeper=clock.sleep,
        )

    assert events == []
    assert transports.dispatches == 0
    assert secret_reader.reads == 0
