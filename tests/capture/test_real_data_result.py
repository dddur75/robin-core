from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from robin.capture.live_transport import (
    LiveTransportDiagnostic,
    LiveTransportError,
    LiveTransportResponse,
    PublicProviderRequestV1,
)
from robin.capture.real_data_result import (
    MARKETS,
    OBJECT_PREFIX,
    SPORT_KEYS,
    NetworkResolution,
    ResultConfig,
    ResultError,
    _normalize_payload,
    _Quota,
    _render_csv,
    run_real_data_result,
)
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalPutOutcome,
    ConditionalPutResult,
    ObservedObject,
)

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 10, 3, 12, 10, tzinfo=UTC)
SECRET = "synthetic_result_provider_key_1234567890"
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
    def __init__(self) -> None:
        self.current = START
        self.sleeps: list[float] = []
        self.monotonic_value = 0.0

    def __call__(self) -> datetime:
        return self.current

    def monotonic(self) -> float:
        return self.monotonic_value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += timedelta(seconds=seconds)
        self.monotonic_value += seconds


class FakeSecretReader:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reads = 0

    def read(self) -> str:
        self.events.append("secret-read")
        self.reads += 1
        return SECRET


class FailingSecretReader:
    def read(self) -> str:
        raise AssertionError("provider secret must not be read for a complete R2 replay")


class FakeStore:
    def __init__(self, events: list[str]) -> None:
        self.events = events
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
        self.puts.append(key)
        self.events.append(f"r2-put:{key.rsplit('/', 1)[-1]}")
        if key in self.objects:
            return ConditionalPutResult(outcome=ConditionalPutOutcome.PRECONDITION_FAILED)
        self.objects[key] = ObservedObject(data=data, metadata=dict(metadata))
        return ConditionalPutResult(
            outcome=ConditionalPutOutcome.CREATED,
            request_id=f"put-{len(self.puts)}",
        )

    def get_object(self, key: str) -> ObservedObject | None:
        self.gets.append(key)
        self.events.append(f"r2-get:{key.rsplit('/', 1)[-1]}")
        return self.objects.get(key)


class MissingFirstRawReadStore(FakeStore):
    def get_object(self, key: str) -> ObservedObject | None:
        observed = super().get_object(key)
        if key.endswith("/raw-envelope.json"):
            return None
        return observed


def _payload(sport_key: str, ordinal: int, observed: datetime) -> bytes:
    kickoff = observed + timedelta(days=1)
    bookmaker_source = observed - timedelta(minutes=1)
    h2h_source = observed - timedelta(minutes=3)
    totals_source = observed - timedelta(minutes=2)
    return json.dumps(
        [
            {
                "id": f"event-{ordinal}",
                "sport_key": sport_key,
                "sport_title": sport_key,
                "commence_time": kickoff.isoformat().replace("+00:00", "Z"),
                "home_team": f"Home <{ordinal}>",
                "away_team": f"Away &{ordinal}",
                "bookmakers": [
                    {
                        "key": "book-a",
                        "title": "Book & A",
                        "last_update": bookmaker_source.isoformat().replace("+00:00", "Z"),
                        "markets": [
                            {
                                "key": "h2h",
                                "last_update": h2h_source.isoformat().replace("+00:00", "Z"),
                                "outcomes": [
                                    {"name": f"Home <{ordinal}>", "price": 1.8},
                                    {"name": "Draw", "price": 3.5},
                                    {"name": f"Away &{ordinal}", "price": 4.2},
                                ],
                            },
                            {
                                "key": "totals",
                                "last_update": totals_source.isoformat().replace("+00:00", "Z"),
                                "outcomes": [
                                    {"name": "Over", "price": 1.91, "point": 2.5},
                                    {"name": "Under", "price": 1.95, "point": 2.5},
                                ],
                            },
                        ],
                    }
                ],
            }
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class FakeTransportFactory:
    def __init__(
        self,
        events: list[str],
        clock: ManualClock,
        *,
        unavailable_ordinal: int | None = None,
        unavailable_sport: str | None = None,
        quota_headers: Mapping[str, str] | None = None,
        quota_headers_by_ordinal: Mapping[int, Mapping[str, str]] | None = None,
        failing_sport: str | None = None,
        preflight_failure_sport: str | None = None,
    ) -> None:
        self.events = events
        self.clock = clock
        self.unavailable_ordinal = unavailable_ordinal
        self.unavailable_sport = unavailable_sport
        self.quota_headers = quota_headers
        self.quota_headers_by_ordinal = quota_headers_by_ordinal
        self.failing_sport = failing_sport
        self.preflight_failure_sport = preflight_failure_sport
        self.requests: list[PublicProviderRequestV1] = []

    def __call__(self, _clock: Callable[[], datetime]) -> FakeTransport:
        return FakeTransport(self)


class FakeTransport:
    def __init__(self, owner: FakeTransportFactory) -> None:
        self.owner = owner
        self.preflighted: PublicProviderRequestV1 | None = None

    def preflight(self, request: PublicProviderRequestV1) -> None:
        assert request.markets == MARKETS
        assert request.retries == request.redirects == 0
        if request.sport_key == self.owner.preflight_failure_sport:
            raise LiveTransportError("LIVE_TRANSPORT_TLS_VERIFICATION_REQUIRED")
        self.preflighted = request

    def dispatch(
        self,
        request: PublicProviderRequestV1,
        *,
        api_key: str,
    ) -> LiveTransportResponse:
        assert request == self.preflighted
        assert api_key == SECRET
        self.owner.requests.append(request)
        ordinal = len(self.owner.requests)
        self.owner.events.append(f"provider-get:{ordinal}:{request.sport_key}")
        if request.sport_key == self.owner.failing_sport:
            raise LiveTransportError(
                "LIVE_TRANSPORT_DISPATCH_FAILED",
                diagnostic=LiveTransportDiagnostic(
                    stage="BODY_READ",
                    code="LIVE_TRANSPORT_DISPATCH_FAILED",
                    exception_class="OSError",
                    errno=9,
                    http_status=200,
                ),
            )
        status = (
            404
            if ordinal == self.owner.unavailable_ordinal
            or request.sport_key == self.owner.unavailable_sport
            else 200
        )
        payload = (
            b'{"message":"sport unavailable"}'
            if status == 404
            else _payload(
                request.sport_key,
                ordinal,
                self.owner.clock(),
            )
        )
        return LiveTransportResponse(
            http_status=status,
            headers=(
                self.owner.quota_headers_by_ordinal[ordinal]
                if self.owner.quota_headers_by_ordinal is not None
                and ordinal in self.owner.quota_headers_by_ordinal
                else {
                    "x-requests-remaining": str(1_000 - (ordinal * 2)),
                    "x-requests-used": str(100 + (ordinal * 2)),
                    "x-requests-last": "2",
                }
                if self.owner.quota_headers is None
                else self.owner.quota_headers
            ),
            payload=payload,
            first_observed_at_utc=self.owner.clock(),
        )


def _config(
    tmp_path: Path,
    *,
    github_run_id: str = "123456789",
    repository_sha: str = "a" * 40,
) -> ResultConfig:
    return ResultConfig(
        manifest_path=ROOT / "configs/execution/robin-real-data-result-20261003.json",
        output_directory=tmp_path,
        repository_sha=repository_sha,
        github_run_id=github_run_id,
        github_run_attempt=1,
        interval_seconds=60,
        safety_environment=SAFETY_ENVIRONMENT,
    )


def _resolution() -> NetworkResolution:
    return NetworkResolution(
        selected_ip_address="1.1.1.1",
        resolved_ip_addresses=("1.1.1.1",),
        observed_at_utc=START,
        expires_at_utc=START + timedelta(minutes=15),
        resolver_identity="synthetic-system-resolver",
    )


def test_three_cycles_flow_through_reservation_r2_replay_and_table(tmp_path: Path) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock)
    secret_reader = FakeSecretReader(events)

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret_reader,
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "REAL_DATA_COMPLETE"
    assert receipt["cycle_count"] == 3
    assert receipt["completed_cycle_count"] == 3
    assert receipt["completed_branch_count"] == 15
    assert receipt["incomplete_branch_count"] == 0
    assert receipt["validated_capture_count"] == 15
    assert receipt["provider_requests_new"] == 15
    assert receipt["provider_requests_cumulative"] == 16
    assert receipt["provider_credits_new_exact"] == 30
    assert receipt["provider_credits_cumulative_upper_bound"] == 34
    assert receipt["row_count"] == 75
    assert receipt["market_branch_coverage"] == {"h2h": 15, "totals": 15}
    assert receipt["sport_coverage"] == {sport: 3 for sport in SPORT_KEYS}
    assert clock.sleeps == [60.0, 60.0]
    assert secret_reader.reads == 1
    assert len(transport.requests) == 15
    assert {request.sport_key for request in transport.requests} == set(SPORT_KEYS)
    assert all(request.markets == MARKETS for request in transport.requests)
    assert len(store.puts) == 34
    assert len(store.gets) == 34
    first_provider = next(
        index for index, item in enumerate(events) if item.startswith("provider-get:")
    )
    assert events[first_provider - 1] == "r2-put:attempt-reservation.json"
    assert events[first_provider + 1] == "r2-put:raw-envelope.json"
    assert events[first_provider + 2] == "r2-get:raw-envelope.json"

    csv_text = (tmp_path / "robin-real-data.csv").read_text(encoding="utf-8")
    html_text = (tmp_path / "robin-real-data.html").read_text(encoding="utf-8")
    report = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    assert "soccer_epl" in csv_text
    assert "h2h" in csv_text and "totals" in csv_text
    assert "Home &lt;1&gt;" in html_text
    assert "Away &amp;1" in html_text
    assert "Branches avec H2H : 15/15" in html_text
    assert "Branches avec totals : 15/15" in html_text
    assert "capture_credits" not in csv_text
    assert "capture_credits" not in html_text
    assert report["rows"] and len(report["branches"]) == 15
    first_event_rows = [row for row in report["rows"] if row["event_id"] == "event-1"]
    assert {
        row["source_timestamp_utc"] for row in first_event_rows if row["market_key"] == "h2h"
    } == {"2026-10-03T12:07:00Z"}
    assert {
        row["source_timestamp_utc"] for row in first_event_rows if row["market_key"] == "totals"
    } == {"2026-10-03T12:08:00Z"}
    assert report["retention"]["raw_payloads"] == "R2_IMMUTABLE_PRIVATE_ONLY"


def test_dns_resolution_is_checked_against_time_after_the_resolver_returns(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock)

    def delayed_resolution() -> NetworkResolution:
        clock.current += timedelta(seconds=4)
        clock.monotonic_value += 4
        observed = clock()
        return NetworkResolution(
            selected_ip_address="1.1.1.1",
            resolved_ip_addresses=("1.1.1.1",),
            observed_at_utc=observed,
            expires_at_utc=observed + timedelta(minutes=15),
            resolver_identity="synthetic-delayed-system-resolver",
        )

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=delayed_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "REAL_DATA_COMPLETE"
    assert receipt["validated_capture_count"] == 15
    assert receipt["effect_accounting"]["dns_resolutions"] == 1
    assert len(transport.requests) == 15


def test_expired_dns_resolution_still_stops_before_secret_or_provider(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock)
    secret_reader = FakeSecretReader(events)

    def expired_resolution() -> NetworkResolution:
        return NetworkResolution(
            selected_ip_address="1.1.1.1",
            resolved_ip_addresses=("1.1.1.1",),
            observed_at_utc=START - timedelta(minutes=16),
            expires_at_utc=START - timedelta(minutes=1),
            resolver_identity="synthetic-expired-system-resolver",
        )

    try:
        run_real_data_result(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=secret_reader,
            resolver=expired_resolution,
            clock=clock,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    except ResultError as error:
        assert error.code == "RESULT_DNS_RESOLUTION_EXPIRED"
    else:  # pragma: no cover - explicit fail-closed assertion
        raise AssertionError("expired provider DNS resolution was accepted")

    assert secret_reader.reads == 0
    assert transport.requests == []


def test_r2_read_failure_preserves_only_typed_sanitized_diagnostic(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    secret_reader = FakeSecretReader(events)
    transport = FakeTransportFactory(events, clock)
    forbidden_detail = "https://storage.invalid/object?secret=forbidden-value"

    class SyntheticR2Error(OSError):
        def __init__(self) -> None:
            super().__init__(9, forbidden_detail)
            self.response = {"ResponseMetadata": {"HTTPStatusCode": 403}}

    class FailingReadStore(FakeStore):
        def get_object(self, key: str) -> ObservedObject | None:
            self.gets.append(key)
            raise SyntheticR2Error

    try:
        run_real_data_result(
            _config(tmp_path),
            store=FailingReadStore(events),
            transport_factory=transport,
            secret_reader=secret_reader,
            resolver=_resolution,
            clock=clock,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    except ResultError as error:
        assert error.code == "RESULT_R2_READBACK_FAILED"
        assert error.diagnostic == {
            "stage": "R2_READBACK",
            "code": "RESULT_R2_READBACK_FAILED",
            "exception_class": "SyntheticR2Error",
            "errno": 9,
            "http_status": 403,
        }
        assert forbidden_detail not in json.dumps(error.diagnostic)
    else:  # pragma: no cover - explicit fail-closed assertion
        raise AssertionError("R2 read failure was accepted")

    assert secret_reader.reads == 0
    assert transport.requests == []


def test_first_capture_must_be_read_back_before_any_later_provider_request(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = MissingFirstRawReadStore(events)
    transport = FakeTransportFactory(events, clock)

    try:
        run_real_data_result(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=FakeSecretReader(events),
            resolver=_resolution,
            clock=clock,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    except ResultError as error:
        assert error.code == "RESULT_R2_READBACK_MISSING"
    else:
        raise AssertionError("the missing first readback must stop the mission")

    assert len(transport.requests) == 1
    assert not any(tmp_path.iterdir())
    assert not any(event.startswith("provider-get:2:") for event in events)


def test_unavailable_branch_is_explicit_and_does_not_stop_other_branches(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock, unavailable_ordinal=3)

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "REAL_DATA_PARTIAL"
    assert receipt["completed_cycle_count"] == 3
    assert receipt["completed_branch_count"] == 14
    assert receipt["incomplete_branch_count"] == 1
    assert receipt["validated_capture_count"] == 14
    assert receipt["provider_requests_new"] == 15
    assert receipt["provider_credits_new_exact"] == 30
    assert len(transport.requests) == 15
    report = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    failure = report["branches"][2]
    assert failure["status"] == "INCOMPLETE"
    assert failure["diagnostic"] == {
        "stage": "RESPONSE_VALIDATE",
        "code": "RESULT_PROVIDER_HTTP_STATUS_INVALID",
        "exception_class": "ResultError",
        "errno": None,
        "http_status": 404,
    }
    html_text = (tmp_path / "robin-real-data.html").read_text(encoding="utf-8")
    assert "RESULT_PROVIDER_HTTP_STATUS_INVALID" in html_text
    assert "soccer_spain_la_liga" in html_text


def test_totals_market_requires_exactly_one_over_under_pair_at_one_point() -> None:
    payload = json.loads(_payload("soccer_epl", 1, START))
    totals = payload[0]["bookmakers"][0]["markets"][1]["outcomes"]
    totals.extend(
        [
            {"name": "Over", "price": 2.1, "point": 3.5},
            {"name": "Under", "price": 1.7, "point": 3.5},
        ]
    )

    rows, limitations = _normalize_payload(
        json.dumps(payload).encode("utf-8"),
        cycle_index=1,
        sport_key="soccer_epl",
        capture_time=START,
        quota=_Quota(remaining=100, used=10, last=2, observed_at_utc=START),
    )

    assert {row["market_key"] for row in rows} == {"h2h"}
    assert [limitation["code"] for limitation in limitations] == ["RESULT_TOTALS_INCOMPLETE"]


def test_missing_market_timestamp_uses_explicit_bookmaker_fallback() -> None:
    payload = json.loads(_payload("soccer_epl", 1, START))
    bookmaker = payload[0]["bookmakers"][0]
    bookmaker["markets"][0].pop("last_update")

    rows, limitations = _normalize_payload(
        json.dumps(payload).encode("utf-8"),
        cycle_index=1,
        sport_key="soccer_epl",
        capture_time=START,
        quota=_Quota(remaining=100, used=10, last=2, observed_at_utc=START),
    )

    assert limitations == ()
    h2h_rows = [row for row in rows if row["market_key"] == "h2h"]
    assert {row["source_timestamp_utc"] for row in h2h_rows} == {bookmaker["last_update"]}
    assert {row["source_timestamp_origin"] for row in h2h_rows} == {
        "BOOKMAKER_LAST_UPDATE_FALLBACK"
    }


def test_csv_neutralizes_provider_formula_prefixes_without_changing_rows() -> None:
    payload = json.loads(_payload("soccer_epl", 1, START))
    event = payload[0]
    event["home_team"] = '=HYPERLINK("https://invalid.example")'
    event["away_team"] = "@SUM(1+1)"
    bookmaker = event["bookmakers"][0]
    bookmaker["title"] = "+cmd"
    bookmaker["markets"][0]["outcomes"][0]["name"] = event["home_team"]
    bookmaker["markets"][0]["outcomes"][2]["name"] = event["away_team"]

    rows, _limitations = _normalize_payload(
        json.dumps(payload).encode("utf-8"),
        cycle_index=1,
        sport_key="soccer_epl",
        capture_time=START,
        quota=_Quota(remaining=100, used=10, last=2, observed_at_utc=START),
    )
    csv_rows = list(csv.DictReader(io.StringIO(_render_csv(rows).decode("utf-8"))))

    assert rows[0]["home_team"] == event["home_team"]
    assert all(row["home_team"].startswith("'=") for row in csv_rows)
    assert all(row["away_team"].startswith("'@") for row in csv_rows)
    assert all(row["bookmaker"].startswith("'+") for row in csv_rows)


def test_second_run_replays_fixed_slots_without_another_provider_request(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first_transport = FakeTransportFactory(first_events, first_clock)
    first = run_real_data_result(
        _config(first_output, github_run_id="111111111", repository_sha="a" * 40),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["status"] == "REAL_DATA_COMPLETE"

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(second_events, second_clock)
    second = run_real_data_result(
        _config(second_output, github_run_id="222222222", repository_sha="b" * 40),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second["status"] == "REAL_DATA_COMPLETE"
    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 16
    assert second["provider_credits_new_exact"] == 0
    assert second["provider_credits_cumulative_upper_bound"] == 34
    assert second_transport.requests == []
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    assert {branch["source"] for branch in report["branches"]} == {"REUSED_R2_CAPTURE"}
    assert all(branch["replay_verified"] is True for branch in report["branches"])
    assert report["repository_sha"] == "b" * 40
    assert {branch["capture_repository_sha"] for branch in report["branches"]} == {"a" * 40}
    assert {branch["capture_github_run_id"] for branch in report["branches"]} == {"111111111"}


def test_preflight_failure_still_replays_and_accounts_for_durable_prior_slots(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first_transport = FakeTransportFactory(first_events, first_clock)
    first = run_real_data_result(
        _config(first_output, github_run_id="211111111"),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["validated_capture_count"] == 15
    assert sum(key.endswith("/attempt-reservation.json") for key in store.objects) == 15

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(
        second_events,
        second_clock,
        preflight_failure_sport="soccer_epl",
    )
    second = run_real_data_result(
        _config(second_output, github_run_id="222222223"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second["status"] == "REAL_DATA_COMPLETE"
    assert second["validated_capture_count"] == 15
    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 16
    assert second["provider_credits_cumulative_upper_bound"] == 34
    assert second_transport.requests == []
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    assert {branch["source"] for branch in report["branches"]} == {"REUSED_R2_CAPTURE"}


def test_complete_r2_replay_does_not_require_provider_dns_or_secret(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first = run_real_data_result(
        _config(first_output, github_run_id="231111111"),
        store=store,
        transport_factory=FakeTransportFactory(first_events, first_clock),
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["validated_capture_count"] == 15

    second_events: list[str] = []
    second_clock = ManualClock()

    def forbidden_resolver() -> NetworkResolution:
        raise AssertionError("provider DNS must not run for a complete R2 replay")

    second = run_real_data_result(
        _config(second_output, github_run_id="232222222"),
        store=store,
        transport_factory=FakeTransportFactory(second_events, second_clock),
        secret_reader=FailingSecretReader(),
        resolver=forbidden_resolver,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second["status"] == "REAL_DATA_COMPLETE"
    assert second["provider_requests_new"] == 0
    assert second["effect_accounting"]["dns_resolutions"] == 0
    assert second["effect_accounting"]["secret_reads"] == 0


def test_replayed_quota_is_not_compared_as_a_new_live_quota_sequence(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first_transport = FakeTransportFactory(
        first_events,
        first_clock,
        preflight_failure_sport="soccer_epl",
    )
    first = run_real_data_result(
        _config(first_output, github_run_id="311111111"),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["provider_requests_new"] == 12
    assert first["validated_capture_count"] == 12

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(
        second_events,
        second_clock,
        quota_headers_by_ordinal={
            1: {
                "x-requests-remaining": "500",
                "x-requests-used": "500",
                "x-requests-last": "2",
            },
            2: {
                "x-requests-remaining": "498",
                "x-requests-used": "502",
                "x-requests-last": "2",
            },
            3: {
                "x-requests-remaining": "496",
                "x-requests-used": "504",
                "x-requests-last": "2",
            },
        },
    )
    second = run_real_data_result(
        _config(second_output, github_run_id="322222222"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second["status"] == "REAL_DATA_COMPLETE"
    assert second["terminal_safety_status"] == "PASS"
    assert second["global_stop_code"] is None
    assert second["validated_capture_count"] == 15
    assert second["provider_requests_new"] == 3
    assert second["provider_requests_cumulative"] == 16
    assert second["provider_credits_cumulative_upper_bound"] == 34
    assert [request.sport_key for request in second_transport.requests] == [
        "soccer_epl",
        "soccer_epl",
        "soccer_epl",
    ]
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    assert [branch["source"] for branch in report["branches"]] == [
        source
        for _cycle_index in range(3)
        for source in ["LIVE_R2_CAPTURE", *("REUSED_R2_CAPTURE" for _ in range(4))]
    ]


def test_replayed_low_quota_stops_before_any_new_provider_request(tmp_path: Path) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    low_quota = {
        "x-requests-remaining": "1",
        "x-requests-used": "102",
        "x-requests-last": "2",
    }
    first_transport = FakeTransportFactory(first_events, first_clock, quota_headers=low_quota)
    first = run_real_data_result(
        _config(first_output, github_run_id="555555551"),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["provider_requests_new"] == 1

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(second_events, second_clock)
    second = run_real_data_result(
        _config(second_output, github_run_id="555555552"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second_transport.requests == []
    assert second["provider_requests_new"] == 0
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    assert report["branches"][0]["source"] == "REUSED_R2_CAPTURE"
    assert report["branches"][1]["source"] == "NOT_ATTEMPTED_QUOTA_STOP"
    assert all(branch["source"] == "NOT_ATTEMPTED_GLOBAL_STOP" for branch in report["branches"][2:])


def test_full_inventory_finds_later_replayed_low_quota_before_any_new_call(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    low_quota = {
        "x-requests-remaining": "1",
        "x-requests-used": "102",
        "x-requests-last": "2",
    }
    first = run_real_data_result(
        _config(first_output, github_run_id="551111111"),
        store=store,
        transport_factory=FakeTransportFactory(
            first_events,
            first_clock,
            preflight_failure_sport="soccer_epl",
            quota_headers=low_quota,
        ),
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["provider_requests_new"] == 1
    assert first["validated_capture_count"] == 1

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(second_events, second_clock)
    second = run_real_data_result(
        _config(second_output, github_run_id="552222222"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second_transport.requests == []
    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 2
    assert second["provider_credits_cumulative_upper_bound"] == 6
    assert second["validated_capture_count"] == 1
    assert second["terminal_safety_status"] == "FAIL_CLOSED"
    assert second["global_stop_code"] == "RESULT_PROVIDER_QUOTA_INSUFFICIENT"


def test_inventory_uses_verified_quota_even_when_prior_payload_replay_fails(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    low_quota = {
        "x-requests-remaining": "1",
        "x-requests-used": "102",
        "x-requests-last": "2",
    }
    first = run_real_data_result(
        _config(first_output, github_run_id="553333333"),
        store=store,
        transport_factory=FakeTransportFactory(
            first_events,
            first_clock,
            unavailable_ordinal=1,
            quota_headers=low_quota,
        ),
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["provider_requests_new"] == 1
    assert first["validated_capture_count"] == 0

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(second_events, second_clock)
    second = run_real_data_result(
        _config(second_output, github_run_id="554444444"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second_transport.requests == []
    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 2
    assert second["provider_credits_cumulative_upper_bound"] == 6
    assert second["validated_capture_count"] == 0
    assert second["terminal_safety_status"] == "FAIL_CLOSED"
    assert second["global_stop_code"] == "RESULT_PROVIDER_QUOTA_INSUFFICIENT"


def test_low_live_quota_stops_new_calls_but_replays_every_durable_capture(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first = run_real_data_result(
        _config(first_output, github_run_id="561111111"),
        store=store,
        transport_factory=FakeTransportFactory(
            first_events,
            first_clock,
            preflight_failure_sport="soccer_epl",
        ),
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["validated_capture_count"] == 12

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(
        second_events,
        second_clock,
        quota_headers={
            "x-requests-remaining": "1",
            "x-requests-used": "502",
            "x-requests-last": "2",
        },
    )
    second = run_real_data_result(
        _config(second_output, github_run_id="562222222"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert len(second_transport.requests) == 1
    assert second["provider_requests_new"] == 1
    assert second["provider_requests_cumulative"] == 14
    assert second["provider_credits_cumulative_upper_bound"] == 30
    assert second["validated_capture_count"] == 13
    assert second["terminal_safety_status"] == "FAIL_CLOSED"
    assert second["global_stop_code"] == "RESULT_PROVIDER_QUOTA_INSUFFICIENT"
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    assert sum(branch["source"] == "REUSED_R2_CAPTURE" for branch in report["branches"]) == 12
    assert sum(branch["source"] == "LIVE_R2_CAPTURE" for branch in report["branches"]) == 1


def test_repeated_http_unavailability_stops_only_that_sport_before_third_call(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock, unavailable_sport="soccer_epl")

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "REAL_DATA_PARTIAL"
    assert receipt["provider_requests_new"] == 14
    assert sum(request.sport_key == "soccer_epl" for request in transport.requests) == 2
    report = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "LIVE_R2_CAPTURE",
        "LIVE_R2_CAPTURE",
        "NOT_ATTEMPTED_BRANCH_STOP",
    ]


def test_durable_repeated_failures_forbid_a_third_attempt_across_dispatches(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first_transport = FakeTransportFactory(
        first_events,
        first_clock,
        unavailable_sport="soccer_epl",
    )
    first = run_real_data_result(
        _config(first_output, github_run_id="571111111"),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert sum(request.sport_key == "soccer_epl" for request in first_transport.requests) == 2
    assert first["provider_requests_new"] == 14

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(second_events, second_clock)
    second = run_real_data_result(
        _config(second_output, github_run_id="572222222"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second_transport.requests == []
    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 15
    assert second["provider_credits_cumulative_upper_bound"] == 32
    assert second["validated_capture_count"] == 12
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "PRIOR_CAPTURE_REPLAY_FAILED",
        "PRIOR_CAPTURE_REPLAY_FAILED",
        "NOT_ATTEMPTED_BRANCH_STOP",
    ]


def test_two_ambiguous_prior_reservations_leave_third_sport_slot_available(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    for cycle_index in (1, 2):
        key = f"{OBJECT_PREFIX}/cycle-{cycle_index:02d}/soccer_epl/attempt-reservation.json"
        store.objects[key] = ObservedObject(
            data=b"{}",
            metadata={"kind": "reservation", "sha256": hashlib.sha256(b"{}").hexdigest()},
        )
    transport = FakeTransportFactory(events, clock)

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["provider_requests_new"] == 13
    assert receipt["provider_requests_cumulative"] == 16
    assert receipt["provider_credits_cumulative_upper_bound"] == 34
    assert sum(request.sport_key == "soccer_epl" for request in transport.requests) == 1
    report = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "PRIOR_ATTEMPT_AMBIGUOUS",
        "PRIOR_ATTEMPT_AMBIGUOUS",
        "LIVE_R2_CAPTURE",
    ]


def test_local_preflight_failure_never_consumes_a_provider_slot(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(
        events,
        clock,
        preflight_failure_sport="soccer_epl",
    )

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["provider_requests_new"] == 12
    assert receipt["provider_requests_cumulative"] == 13
    assert receipt["provider_credits_cumulative_upper_bound"] == 28
    assert all(request.sport_key != "soccer_epl" for request in transport.requests)
    assert not any("soccer_epl/attempt-reservation.json" in key for key in store.objects)
    report = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "LOCAL_PREFLIGHT_FAILURE",
        "LOCAL_PREFLIGHT_FAILURE",
        "LOCAL_PREFLIGHT_FAILURE",
    ]
    assert all(branch["provider_request_attempted"] is False for branch in epl)


def test_preflight_failure_accounts_for_ambiguous_prior_reservations(
    tmp_path: Path,
) -> None:
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    first_events: list[str] = []
    first_clock = ManualClock()
    store = FakeStore(first_events)
    first_transport = FakeTransportFactory(
        first_events,
        first_clock,
        failing_sport="soccer_epl",
    )
    first = run_real_data_result(
        _config(first_output, github_run_id="611111111"),
        store=store,
        transport_factory=first_transport,
        secret_reader=FakeSecretReader(first_events),
        resolver=_resolution,
        clock=first_clock,
        monotonic=first_clock.monotonic,
        sleeper=first_clock.sleep,
    )
    assert first["provider_requests_new"] == 14

    second_events: list[str] = []
    second_clock = ManualClock()
    second_transport = FakeTransportFactory(
        second_events,
        second_clock,
        preflight_failure_sport="soccer_epl",
    )
    second = run_real_data_result(
        _config(second_output, github_run_id="622222222"),
        store=store,
        transport_factory=second_transport,
        secret_reader=FakeSecretReader(second_events),
        resolver=_resolution,
        clock=second_clock,
        monotonic=second_clock.monotonic,
        sleeper=second_clock.sleep,
    )

    assert second["provider_requests_new"] == 0
    assert second["provider_requests_cumulative"] == 15
    assert second["provider_credits_cumulative_upper_bound"] == 32
    assert second_transport.requests == []
    report = json.loads((second_output / "robin-real-data.json").read_text(encoding="utf-8"))
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "PRIOR_ATTEMPT_AMBIGUOUS",
        "PRIOR_ATTEMPT_AMBIGUOUS",
        "LOCAL_PREFLIGHT_FAILURE",
    ]


def test_repeated_transport_failure_stops_only_the_affected_sport_branch(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(events, clock, failing_sport="soccer_epl")
    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert receipt["status"] == "REAL_DATA_PARTIAL"
    assert receipt["provider_requests_new"] == 14
    assert receipt["provider_requests_cumulative"] == 15
    assert receipt["provider_credits_new_exact"] is None
    assert receipt["provider_credits_cumulative_upper_bound"] == 32
    assert receipt["validated_capture_count"] == 12
    report_text = (tmp_path / "robin-real-data.json").read_text(encoding="utf-8")
    assert SECRET not in report_text
    report = json.loads(report_text)
    assert report["branches"][0]["diagnostic"] == {
        "stage": "BODY_READ",
        "code": "LIVE_TRANSPORT_DISPATCH_FAILED",
        "exception_class": "OSError",
        "errno": 9,
        "http_status": 200,
    }
    epl = [branch for branch in report["branches"] if branch["sport_key"] == "soccer_epl"]
    assert [branch["source"] for branch in epl] == [
        "LIVE_PROVIDER_FAILURE",
        "LIVE_PROVIDER_FAILURE",
        "NOT_ATTEMPTED_BRANCH_STOP",
    ]
    assert all(
        branch["replay_verified"] is True
        for branch in report["branches"]
        if branch["sport_key"] != "soccer_epl"
    )


def test_unverified_or_unexpected_quota_stops_before_a_second_request(tmp_path: Path) -> None:
    scenarios = (
        ({}, "RESULT_QUOTA_HEADERS_MISSING", None),
        (
            {
                "x-requests-remaining": "997",
                "x-requests-used": "103",
                "x-requests-last": "3",
            },
            "RESULT_CREDIT_COST_UNEXPECTED",
            7,
        ),
    )
    for ordinal, (headers, expected_code, expected_upper) in enumerate(scenarios, start=1):
        output = tmp_path / str(ordinal)
        output.mkdir()
        events: list[str] = []
        clock = ManualClock()
        store = FakeStore(events)
        transport = FakeTransportFactory(events, clock, quota_headers=headers)

        receipt = run_real_data_result(
            _config(output, github_run_id=f"33333333{ordinal}"),
            store=store,
            transport_factory=transport,
            secret_reader=FakeSecretReader(events),
            resolver=_resolution,
            clock=clock,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )

        assert receipt["status"] == "NO_REAL_CAPTURE"
        assert receipt["provider_requests_new"] == 1
        assert receipt["provider_requests_cumulative"] == 2
        assert receipt["provider_credits_cumulative_upper_bound"] == expected_upper
        report = json.loads((output / "robin-real-data.json").read_text(encoding="utf-8"))
        assert report["branches"][0]["diagnostic"]["code"] == expected_code
        assert all(
            branch["source"] == "NOT_ATTEMPTED_GLOBAL_STOP" for branch in report["branches"][1:]
        )

        replay_output = tmp_path / f"{ordinal}-replay"
        replay_output.mkdir()
        replay_events: list[str] = []
        replay_clock = ManualClock()
        replay_transport = FakeTransportFactory(replay_events, replay_clock)
        replay_receipt = run_real_data_result(
            _config(replay_output, github_run_id=f"44444444{ordinal}"),
            store=store,
            transport_factory=replay_transport,
            secret_reader=FakeSecretReader(replay_events),
            resolver=_resolution,
            clock=replay_clock,
            monotonic=replay_clock.monotonic,
            sleeper=replay_clock.sleep,
        )
        assert replay_transport.requests == []
        assert replay_receipt["provider_requests_new"] == 0
        assert replay_receipt["provider_credits_cumulative_upper_bound"] == expected_upper


def test_quota_loss_after_verified_capture_preserves_data_but_fails_closed(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    store = FakeStore(events)
    transport = FakeTransportFactory(
        events,
        clock,
        quota_headers_by_ordinal={2: {}},
    )

    receipt = run_real_data_result(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert len(transport.requests) == 2
    assert receipt["status"] == "REAL_DATA_PARTIAL"
    assert receipt["validated_capture_count"] == 1
    assert receipt["terminal_safety_status"] == "FAIL_CLOSED"
    assert receipt["global_stop_code"] == "RESULT_PROVIDER_QUOTA_UNVERIFIED"
    assert receipt["provider_credits_cumulative_upper_bound"] is None
    assert (tmp_path / "robin-real-data.html").is_file()


def test_last_response_quota_sequence_anomaly_can_never_report_complete(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    clock = ManualClock()
    transport = FakeTransportFactory(
        events,
        clock,
        quota_headers_by_ordinal={
            15: {
                "x-requests-remaining": "999",
                "x-requests-used": "50",
                "x-requests-last": "2",
            }
        },
    )

    receipt = run_real_data_result(
        _config(tmp_path),
        store=FakeStore(events),
        transport_factory=transport,
        secret_reader=FakeSecretReader(events),
        resolver=_resolution,
        clock=clock,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )

    assert len(transport.requests) == 15
    assert receipt["status"] == "REAL_DATA_PARTIAL"
    assert receipt["terminal_safety_status"] == "FAIL_CLOSED"
    assert receipt["global_stop_code"] == "RESULT_QUOTA_SEQUENCE_INVALID"
    html_text = (tmp_path / "robin-real-data.html").read_text(encoding="utf-8")
    assert "FAIL_CLOSED" in html_text
    assert "RESULT_QUOTA_SEQUENCE_INVALID" in html_text
