from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

import robin.capture.recurring_real_data as recurring
from robin.capture.contracts import canonical_json_bytes
from robin.capture.live_transport import (
    LiveTransportDiagnostic,
    LiveTransportError,
    LiveTransportResponse,
    PublicProviderRequestV1,
)
from robin.capture.real_data_result import MARKETS, SPORT_KEYS, _normalize_payload, _Quota
from robin.capture.recurring_real_data import (
    ACCOUNTING_HEAD_KEY,
    ACCOUNTING_INITIALIZED_KEY,
    LATEST_REPORT_KEY,
    MISSION_ID,
    RECURRING_CLAIM_IDS,
    SEED_CLAIM_IDS,
    RecurringConfig,
    RecurringError,
    _reserve_accounting_slot,
    classify_market_limitation,
    recover_latest_report,
    run_recurring_real_data,
    slot_start_utc,
)
from robin.capture.reprise_collecte import NetworkResolution
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalPutOutcome,
    ConditionalPutResult,
    ObservedObject,
)
from robin.prospective_observatory.chronos_r2 import LatestProjection

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 10, 4, 10, 17, tzinfo=UTC)
SECRET = "synthetic_recurring_provider_key_1234567890"
SAFETY = {
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


class FakeStore:
    def __init__(self) -> None:
        self.objects: dict[str, ObservedObject] = {}
        self.projections: dict[str, LatestProjection] = {}
        self.put_keys: list[str] = []
        self.latest_puts = 0
        self.ambiguous_suffix: str | None = None
        self.raise_once_suffix: str | None = None
        self.raise_get_after_put_suffix: str | None = None
        self.ambiguous_reconciliation_puts = 0
        self.before_next_cas: Callable[[FakeStore], None] | None = None

    def put_if_absent(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult:
        on_dispatch()
        self.put_keys.append(key)
        if self.raise_once_suffix and key.endswith(self.raise_once_suffix):
            self.raise_once_suffix = None
            raise RuntimeError("forbidden storage detail with secret-value")
        if self.ambiguous_suffix and key.endswith(self.ambiguous_suffix):
            self.ambiguous_suffix = None
            return ConditionalPutResult(outcome=ConditionalPutOutcome.AMBIGUOUS)
        if key in self.objects:
            return ConditionalPutResult(outcome=ConditionalPutOutcome.PRECONDITION_FAILED)
        self.objects[key] = ObservedObject(data=data, metadata=dict(metadata))
        return ConditionalPutResult(outcome=ConditionalPutOutcome.CREATED)

    def get_object(self, key: str) -> ObservedObject | None:
        if (
            self.raise_get_after_put_suffix
            and key.endswith(self.raise_get_after_put_suffix)
            and key in self.objects
        ):
            self.raise_get_after_put_suffix = None
            raise OSError(5, "forbidden readback detail with secret-value")
        return self.objects.get(key)

    def get_latest_projection(self, key: str) -> LatestProjection | None:
        return self.projections.get(key)

    def put_latest_projection(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        expected_etag: str | None,
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult:
        on_dispatch()
        self.latest_puts += 1
        if self.ambiguous_reconciliation_puts:
            decoded = json.loads(data)
            if "/accounting/reconciliations/" in decoded.get("node_key", ""):
                self.ambiguous_reconciliation_puts -= 1
                return ConditionalPutResult(outcome=ConditionalPutOutcome.AMBIGUOUS)
        if self.before_next_cas is not None:
            callback = self.before_next_cas
            self.before_next_cas = None
            callback(self)
        current = self.projections.get(key)
        current_etag = current.etag if current is not None else None
        if current_etag != expected_etag:
            return ConditionalPutResult(outcome=ConditionalPutOutcome.PRECONDITION_FAILED)
        etag = f'"etag-{self.latest_puts}"'
        self.projections[key] = LatestProjection(
            data=data,
            metadata=dict(metadata),
            etag=etag,
        )
        return ConditionalPutResult(
            outcome=ConditionalPutOutcome.CREATED,
            etag=etag,
        )


class FakeSecretReader:
    def __init__(self) -> None:
        self.reads = 0

    def read(self) -> str:
        self.reads += 1
        return SECRET


def _payload(sport_key: str, observed: datetime) -> bytes:
    return json.dumps(
        [
            {
                "id": f"event-{sport_key}",
                "sport_key": sport_key,
                "sport_title": sport_key,
                "commence_time": (observed + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "home_team": "Home",
                "away_team": "Away",
                "bookmakers": [
                    {
                        "key": "book-a",
                        "title": "Book A",
                        "last_update": (observed - timedelta(minutes=1))
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "markets": [
                            {
                                "key": "h2h",
                                "last_update": (observed - timedelta(minutes=2))
                                .isoformat()
                                .replace("+00:00", "Z"),
                                "outcomes": [
                                    {"name": "Home", "price": 1.8},
                                    {"name": "Draw", "price": 3.5},
                                    {"name": "Away", "price": 4.2},
                                ],
                            },
                            {
                                "key": "totals",
                                "last_update": (observed - timedelta(minutes=2))
                                .isoformat()
                                .replace("+00:00", "Z"),
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
    ).encode()


class FakeTransportFactory:
    def __init__(
        self,
        now: Callable[[], datetime],
        *,
        failing_sport: str | None = None,
        header_factory: Callable[[int], dict[str, str]] | None = None,
        payload_factory: Callable[[str, datetime], bytes] | None = None,
    ) -> None:
        self.now = now
        self.failing_sport = failing_sport
        self.header_factory = header_factory
        self.payload_factory = payload_factory
        self.requests: list[PublicProviderRequestV1] = []

    def __call__(self, _clock: Callable[[], datetime]) -> FakeTransport:
        return FakeTransport(self)


class FakeTransport:
    def __init__(self, owner: FakeTransportFactory) -> None:
        self.owner = owner
        self.request: PublicProviderRequestV1 | None = None

    def preflight(self, request: PublicProviderRequestV1) -> None:
        assert request.markets == MARKETS
        assert request.retries == 0
        assert request.redirects == 0
        self.request = request

    def dispatch(self, request: PublicProviderRequestV1, *, api_key: str) -> LiveTransportResponse:
        assert request is self.request
        assert api_key == SECRET
        self.owner.requests.append(request)
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
        ordinal = len(self.owner.requests)
        now = self.owner.now()
        headers = (
            self.owner.header_factory(ordinal)
            if self.owner.header_factory is not None
            else {
                "x-requests-remaining": str(19_969 - (ordinal * 2)),
                "x-requests-used": str(31 + (ordinal * 2)),
                "x-requests-last": "2",
            }
        )
        return LiveTransportResponse(
            http_status=200,
            headers=headers,
            network_calls=1,
            provider_calls=1,
            retries=0,
            redirects=0,
            payload=(
                self.owner.payload_factory(request.sport_key, now)
                if self.owner.payload_factory is not None
                else _payload(request.sport_key, now)
            ),
            first_observed_at_utc=now,
        )


def _config(tmp_path: Path, run_id: str = "40000000001") -> RecurringConfig:
    return RecurringConfig(
        manifest_path=ROOT / "configs/execution/robin-autonomous-lab-20261004.json",
        output_directory=tmp_path,
        repository_sha="b" * 40,
        github_run_id=run_id,
        github_run_attempt=1,
        relay_generation="1" * 64,
        relay_chain_id="39999999999",
        relay_parent_run_id="39999999998",
        relay_sequence=2,
        safety_environment=SAFETY,
    )


def _resolution(now: datetime) -> NetworkResolution:
    return NetworkResolution(
        selected_ip_address="1.1.1.1",
        resolved_ip_addresses=("1.1.1.1",),
        observed_at_utc=now,
        expires_at_utc=now + timedelta(minutes=15),
        resolver_identity="synthetic-system-resolver",
    )


def _now() -> datetime:
    return START


def test_two_hour_slot_identity_is_utc_and_deterministic() -> None:
    assert slot_start_utc(datetime(2026, 10, 4, 10, 17, tzinfo=UTC)) == datetime(
        2026, 10, 4, 10, 0, tzinfo=UTC
    )
    assert slot_start_utc(datetime(2026, 10, 4, 11, 59, tzinfo=UTC)) == datetime(
        2026, 10, 4, 10, 0, tzinfo=UTC
    )
    assert slot_start_utc(datetime(2026, 10, 4, 12, 0, tzinfo=UTC)) == datetime(
        2026, 10, 4, 12, 0, tzinfo=UTC
    )


def test_latest_recovery_checks_expiry_before_any_r2_mutation(tmp_path: Path) -> None:
    manifest = json.loads(
        (ROOT / "configs/execution/robin-autonomous-lab-20261004.json").read_text(encoding="utf-8")
    )
    manifest["expires_at"] = "2026-10-04T10:16:59Z"
    expired_manifest = tmp_path / "expired-manifest.json"
    expired_manifest.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    base = _config(tmp_path)
    config = RecurringConfig(
        manifest_path=expired_manifest,
        output_directory=base.output_directory,
        repository_sha=base.repository_sha,
        github_run_id=base.github_run_id,
        github_run_attempt=base.github_run_attempt,
        relay_generation=base.relay_generation,
        relay_chain_id=base.relay_chain_id,
        relay_parent_run_id=base.relay_parent_run_id,
        relay_sequence=base.relay_sequence,
        safety_environment=base.safety_environment,
    )
    store = FakeStore()

    with pytest.raises(RecurringError, match="RECURRING_AUTHORITY_EXPIRED"):
        recover_latest_report(config, store=store, clock=_now)

    assert store.latest_puts == 0
    assert store.put_keys == []
    assert store.objects == {}
    assert store.projections == {}


def test_latest_recovery_imports_verified_historical_captures_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_time = "2026-10-03T20:53:57Z"
    legacy_row = {
        "sport_key": "soccer_epl",
        "sport_title": "EPL",
        "capture_time_utc": capture_time,
        "source_timestamp_utc": "2026-10-03T20:53:42Z",
        "source_timestamp_origin": "MARKET_LAST_UPDATE",
        "event_id": "event-legacy",
        "match": "Home — Away",
        "home_team": "Home",
        "away_team": "Away",
        "kickoff_utc": "2026-10-10T11:30:00Z",
        "bookmaker_key": "book-a",
        "bookmaker": "Book A",
        "market_key": "h2h",
        "outcome": "Home",
        "point": None,
        "price": 1.8,
        "quota_remaining": 19_997,
        "cycle_index": 1,
    }
    legacy_report = {
        "schema_version": "robin-real-data-result-report-v1",
        "mission_id": "ROBIN_REAL_DATA_RESULT_20261003",
        "repository_sha": "0be96131d1c9c6d7337629f906ead3b282304293",
        "github_run_id": "37153158456",
        "status": "REAL_DATA_PARTIAL",
        "branches": [
            {
                "sport_key": "soccer_epl",
                "status": "PARTIAL",
                "row_count": 1,
                "capture_time_utc": capture_time,
                "limitations": [],
                "diagnostic": None,
                "raw_object_key": "private/raw.json",
            }
        ],
        "rows": [legacy_row],
        "row_count": 1,
        "validated_capture_count": 1,
        "incomplete_branch_count": 1,
        "capture_times_utc": [capture_time],
        "source_timestamp_min_utc": "2026-10-03T20:53:42Z",
        "source_timestamp_max_utc": "2026-10-03T20:53:42Z",
        "match_count": 1,
        "bookmaker_count": 1,
    }
    legacy_bytes = canonical_json_bytes(legacy_report)
    legacy_sha = hashlib.sha256(legacy_bytes).hexdigest()
    receipt = {
        "schema_version": "robin-real-data-result-public-receipt-v1",
        "mission_id": "ROBIN_REAL_DATA_RESULT_20261003",
        "repository_sha": "0be96131d1c9c6d7337629f906ead3b282304293",
        "github_run_id": "37153158456",
        "status": "REAL_DATA_PARTIAL",
        "private_report_r2_key": recurring.HISTORICAL_PRIVATE_REPORT_KEY,
        "private_report_r2_sha256": legacy_sha,
        "private_report_r2_status": "VERIFIED",
        "row_count": 1,
        "validated_capture_count": 1,
        "incomplete_branch_count": 1,
        "capture_times_utc": [capture_time],
        "source_timestamp_min_utc": "2026-10-03T20:53:42Z",
        "source_timestamp_max_utc": "2026-10-03T20:53:42Z",
        "match_count": 1,
        "bookmaker_count": 1,
        "provider_requests_cumulative": 16,
        "provider_credits_cumulative_upper_bound": 34,
    }
    receipt_bytes = canonical_json_bytes(receipt)
    receipt_path = tmp_path / "historical-receipt.json"
    receipt_path.write_bytes(receipt_bytes + b"\n")
    monkeypatch.setattr(
        recurring,
        "HISTORICAL_RECEIPT_SHA256",
        hashlib.sha256(receipt_bytes).hexdigest(),
    )
    monkeypatch.setattr(recurring, "HISTORICAL_PRIVATE_REPORT_SHA256", legacy_sha)
    bad_metadata_store = FakeStore()
    bad_metadata_store.objects[recurring.HISTORICAL_PRIVATE_REPORT_KEY] = ObservedObject(
        data=legacy_bytes,
        metadata={
            "sha256": legacy_sha,
            "mission": "robin_real_data_result_20261003",
            "kind": "wrong-kind",
        },
    )

    with pytest.raises(RecurringError, match="RECURRING_HISTORICAL_SEED_REPORT_INVALID"):
        recover_latest_report(
            _config(tmp_path),
            store=bad_metadata_store,
            clock=_now,
            historical_receipt_path=receipt_path,
        )

    assert bad_metadata_store.latest_puts == 0
    assert bad_metadata_store.put_keys == []
    store = FakeStore()
    store.objects[recurring.HISTORICAL_PRIVATE_REPORT_KEY] = ObservedObject(
        data=legacy_bytes,
        metadata={
            "sha256": legacy_sha,
            "mission": "robin_real_data_result_20261003",
            "kind": "private-normalized-report",
        },
    )

    recover_latest_report(
        _config(tmp_path),
        store=store,
        clock=_now,
        historical_receipt_path=receipt_path,
    )
    recover_latest_report(
        _config(tmp_path),
        store=store,
        clock=_now,
        historical_receipt_path=receipt_path,
    )

    pointer = store.projections[LATEST_REPORT_KEY]
    pointer_data = json.loads(pointer.data)
    adapter = store.objects[pointer_data["report_key"]]
    adapter_data = json.loads(adapter.data)
    assert pointer_data["last_usable"]["report_sha256"] == hashlib.sha256(adapter.data).hexdigest()
    assert adapter_data["rows"][0]["slot_start_utc"] == "2026-10-03T20:00:00Z"
    assert adapter_data["validated_capture_count"] == 1
    assert adapter_data["provider_requests_new"] == 0
    assert adapter_data["accounting"]["lifetime_requests"] == 16
    assert adapter_data["accounting"]["lifetime_credits"] == 34
    assert adapter_data["claim_ids"] == list(SEED_CLAIM_IDS)
    assert adapter_data["seed_provenance"]["private_report_sha256"] == legacy_sha
    assert "raw_object_key" not in adapter.data.decode("utf-8")
    assert store.latest_puts == 1


def test_five_leagues_are_captured_read_back_and_duplicate_run_replays(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    first_now = START + timedelta(minutes=20)
    second_now = START + timedelta(hours=1, minutes=20)
    transport = FakeTransportFactory(lambda: first_now)
    secret = FakeSecretReader()
    resolutions = 0

    def resolve() -> NetworkResolution:
        nonlocal resolutions
        resolutions += 1
        return _resolution(first_now)

    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=resolve,
        clock=lambda: first_now,
    )
    assert first["mission_id"] == MISSION_ID
    assert first["validated_capture_count"] == 5
    assert first["provider_requests_new"] == 5
    assert first["status"] == "REAL_DATA_COMPLETE"
    assert first["claim_ids"] == list(RECURRING_CLAIM_IDS)
    assert {request.sport_key for request in transport.requests} == set(SPORT_KEYS)
    assert secret.reads == resolutions == 1
    report_key = first["private_report_r2_key"]
    assert isinstance(report_key, str)
    report_object = store.objects[report_key]
    report = json.loads(report_object.data)
    assert report["row_count"] == 25
    assert len(report["branches"]) == 5
    assert report["claim_ids"] == list(RECURRING_CLAIM_IDS)
    assert report["accounting"]["rolling_24h_requests"] == 21
    for branch in report["branches"]:
        assert branch["provider_key"] == "THE_ODDS_API_V4"
        assert branch["settlement_period_key"] == "PROVIDER_DEFAULT_UNSPECIFIED"
        assert branch["acquisition_started_at_utc"] == first_now.isoformat().replace("+00:00", "Z")
        assert branch["acquisition_finished_at_utc"] == first_now.isoformat().replace("+00:00", "Z")
    for row in report["rows"]:
        assert row["provider_key"] == "THE_ODDS_API_V4"
        assert row["settlement_period_key"] == "PROVIDER_DEFAULT_UNSPECIFIED"
        assert row["acquisition_started_at_utc"] == first_now.isoformat().replace("+00:00", "Z")
        assert row["acquisition_finished_at_utc"] == first_now.isoformat().replace("+00:00", "Z")
    raw_key = report["branches"][0]["raw_object_key"]
    raw_envelope = json.loads(store.objects[raw_key].data)
    assert raw_envelope["schema_version"] == "robin-autonomous-raw-envelope-v2"
    assert raw_envelope["provider_key"] == "THE_ODDS_API_V4"
    assert raw_envelope["settlement_period_key"] == "PROVIDER_DEFAULT_UNSPECIFIED"
    assert raw_envelope["acquisition_started_at_utc"] == first_now.isoformat().replace(
        "+00:00", "Z"
    )
    assert raw_envelope["acquisition_finished_at_utc"] == first_now.isoformat().replace(
        "+00:00", "Z"
    )
    legacy_envelope = dict(raw_envelope)
    legacy_envelope["schema_version"] = "robin-autonomous-raw-envelope-v1"
    for field in (
        "provider_key",
        "settlement_period_key",
        "acquisition_started_at_utc",
        "acquisition_finished_at_utc",
    ):
        legacy_envelope.pop(field)
    legacy_payload = recurring._payload_from_readback(
        canonical_json_bytes(legacy_envelope),
        slot=datetime(2026, 10, 4, 10, tzinfo=UTC),
        sport_key=raw_envelope["sport_key"],
    )
    assert legacy_payload[7:] == (None, None, None, None)
    assert hashlib.sha256(report_object.data).hexdigest() == first["private_report_r2_sha256"]
    assert ACCOUNTING_HEAD_KEY in store.projections

    second = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=resolve,
        clock=lambda: second_now,
    )
    assert second["replayed_existing_slot"] is True
    assert second["provider_requests_new"] == 0
    assert second["slot_start_utc"] == first["slot_start_utc"] == "2026-10-04T10:00:00Z"
    assert second["private_report_r2_key"] == first["private_report_r2_key"]
    assert second["private_report_r2_sha256"] == first["private_report_r2_sha256"]
    assert second["rolling_24h_requests"] == first["rolling_24h_requests"]
    assert second["rolling_24h_credits"] == first["rolling_24h_credits"]
    assert len(transport.requests) == 5
    assert secret.reads == resolutions == 1


def test_dns_resolution_is_checked_with_time_observed_after_resolver_returns(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    ticks = 0

    def advancing_clock() -> datetime:
        nonlocal ticks
        observed = START + timedelta(milliseconds=ticks)
        ticks += 1
        return observed

    def resolve() -> NetworkResolution:
        return _resolution(advancing_clock())

    transport = FakeTransportFactory(advancing_clock)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=resolve,
        clock=advancing_clock,
    )

    assert receipt["status"] == "REAL_DATA_COMPLETE"
    assert receipt["validated_capture_count"] == 5
    assert receipt["provider_requests_new"] == 5
    assert len(transport.requests) == 5
    expected_lineage = {
        "generation": "1" * 64,
        "chain_id": "39999999999",
        "parent_run_id": "39999999998",
        "sequence": 2,
    }
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert receipt["relay_lineage"] == expected_lineage
    assert report["relay_lineage"] == expected_lineage


def test_truly_expired_dns_resolution_still_blocks_every_provider_request(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    secret = FakeSecretReader()
    transport = FakeTransportFactory(lambda: START)
    calls = 0

    def expired_resolution() -> NetworkResolution:
        nonlocal calls
        calls += 1
        return _resolution(START - timedelta(minutes=16))

    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=expired_resolution,
        clock=lambda: START,
    )

    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert receipt["status"] == "REAL_DATA_FAILED"
    assert calls == 1
    assert secret.reads == 0
    assert transport.requests == []
    assert {branch["diagnostic"]["code"] for branch in report["branches"]} == {
        "RECURRING_DNS_RESOLUTION_EXPIRED"
    }


def test_duplicate_replay_requires_private_report_metadata_digest(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    transport = FakeTransportFactory(_now)
    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=_now,
    )
    key = first["private_report_r2_key"]
    observed = store.objects[key]
    store.objects[key] = ObservedObject(
        data=observed.data,
        metadata=dict(observed.metadata) | {"sha256": "0" * 64},
    )

    with pytest.raises(RecurringError, match="RECURRING_REPORT_INVALID"):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=transport,
            secret_reader=FakeSecretReader(),
            resolver=lambda: _resolution(START),
            clock=_now,
        )
    assert len(transport.requests) == 5


def test_failed_branch_is_redacted_and_does_not_stop_siblings(tmp_path: Path) -> None:
    store = FakeStore()
    transport = FakeTransportFactory(_now, failing_sport=SPORT_KEYS[1])
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=_now,
    )
    assert receipt["provider_requests_new"] == 5
    assert receipt["validated_capture_count"] == 4
    assert receipt["status"] == "REAL_DATA_PARTIAL"
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    failed = next(branch for branch in report["branches"] if branch["sport_key"] == SPORT_KEYS[1])
    assert failed["diagnostic"] == {
        "stage": "BODY_READ",
        "code": "LIVE_TRANSPORT_DISPATCH_FAILED",
        "exception_class": "OSError",
        "errno": 9,
        "http_status": 200,
    }


def test_http_200_empty_lists_are_verified_empty_captures_not_failures(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    transport = FakeTransportFactory(
        _now,
        payload_factory=lambda _sport, _observed: b"[]",
    )
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=_now,
    )

    assert receipt["status"] == "REAL_DATA_COMPLETE"
    assert receipt["validated_capture_count"] == 5
    assert receipt["row_count"] == 0
    assert receipt["provider_requests_new"] == 5
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert all(branch["status"] == "COMPLETE" for branch in report["branches"])
    assert all(branch["data_availability"] == "VERIFIED_EMPTY" for branch in report["branches"])
    assert all(branch["readback_verified"] is True for branch in report["branches"])


@pytest.mark.parametrize(
    ("headers", "expected_floor"),
    [
        (
            {
                "x-requests-remaining": "0",
                "x-requests-used": "20000",
                "x-requests-last": "2",
            },
            0,
        ),
        (
            {
                "x-requests-remaining": "100",
                "x-requests-used": "19900",
                "x-requests-last": "4",
            },
            100,
        ),
        (
            {
                "x-requests-remaining": "100",
                "x-requests-used": "19900",
            },
            100,
        ),
    ],
)
def test_quota_or_cost_anomaly_stops_before_second_provider_request(
    headers: dict[str, str], expected_floor: int, tmp_path: Path
) -> None:
    store = FakeStore()
    transport = FakeTransportFactory(lambda: START, header_factory=lambda _n: headers)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert len(transport.requests) == 1
    assert receipt["provider_requests_new"] == 1
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert report["accounting"]["provider_remaining_floor"] == expected_floor
    assert report["branches"][1]["diagnostic"]["stage"] == "PROVIDER_CIRCUIT"


@pytest.mark.parametrize("storage_failure", ["ambiguous_put", "readback_exception"])
def test_raw_storage_failure_preserves_quota_circuit_and_bound(
    storage_failure: str, tmp_path: Path
) -> None:
    store = FakeStore()
    suffix = f"/{SPORT_KEYS[0]}/raw-envelope.json"
    if storage_failure == "ambiguous_put":
        store.ambiguous_suffix = suffix
    else:
        store.raise_get_after_put_suffix = suffix
    transport = FakeTransportFactory(
        lambda: START,
        header_factory=lambda _n: {
            "x-requests-remaining": "1",
            "x-requests-used": "19999",
            "x-requests-last": "3",
        },
    )

    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )

    assert len(transport.requests) == 1
    assert receipt["provider_requests_new"] == 1
    assert receipt["credit_bound_valid"] is False
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert report["accounting"]["provider_remaining_floor"] == 1
    assert report["branches"][0]["source"] == "LIVE_STORAGE_FAILURE"
    assert all(branch["source"] == "PROVIDER_CIRCUIT_OPEN" for branch in report["branches"][1:])


def test_reconciliation_ambiguity_is_recovered_offline_without_new_call(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    store.ambiguous_reconciliation_puts = 3
    first_transport = FakeTransportFactory(
        lambda: START,
        header_factory=lambda _n: {
            "x-requests-remaining": "100",
            "x-requests-used": "19900",
            "x-requests-last": "4",
        },
    )
    with pytest.raises(RecurringError, match="RECURRING_ACCOUNTING_RECONCILIATION_FAILED"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=first_transport,
            secret_reader=FakeSecretReader(),
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert len(first_transport.requests) == 1
    open_head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    open_node = json.loads(store.objects[open_head["node_key"]].data)
    assert open_node["slot_state"] == "OPEN"

    later = START + timedelta(hours=2)
    second_transport = FakeTransportFactory(lambda: later)
    second_secret = FakeSecretReader()
    recovered = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=second_transport,
        secret_reader=second_secret,
        resolver=lambda: _resolution(later),
        clock=lambda: later,
    )
    assert recovered["slot_start_utc"] == "2026-10-04T10:00:00Z"
    assert recovered["provider_requests_new"] == 0
    assert second_transport.requests == []
    assert second_secret.reads == 0
    closed_head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    closed_node = json.loads(store.objects[closed_head["node_key"]].data)
    assert closed_node["slot_state"] == "CLOSED"
    assert closed_node["credit_bound_valid"] is False

    newest = START + timedelta(hours=4)
    third_transport = FakeTransportFactory(lambda: newest)
    third_secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_CREDIT_BOUND_UNVERIFIED"):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000003"),
            store=store,
            transport_factory=third_transport,
            secret_reader=third_secret,
            resolver=lambda: _resolution(newest),
            clock=lambda: newest,
        )
    assert third_transport.requests == []
    assert third_secret.reads == 0


def test_unverified_credit_bound_blocks_the_next_slot_before_secret(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    transport = FakeTransportFactory(
        lambda: START,
        header_factory=lambda _n: {
            "x-requests-remaining": "100",
            "x-requests-used": "19900",
        },
    )
    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert first["credit_bound_valid"] is False
    later = START + timedelta(hours=2)
    secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_CREDIT_BOUND_UNVERIFIED"):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=FakeTransportFactory(lambda: later),
            secret_reader=secret,
            resolver=lambda: _resolution(later),
            clock=lambda: later,
        )
    assert secret.reads == 0


def test_crash_after_admission_and_raw_writes_replays_without_provider(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    store.ambiguous_suffix = "/private-report.json"
    transport = FakeTransportFactory(lambda: START)
    secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_REPORT_WRITE_AMBIGUOUS"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert len(transport.requests) == 5

    recovered = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert recovered["validated_capture_count"] == 5
    assert recovered["provider_requests_new"] == 0
    assert len(transport.requests) == 5
    assert secret.reads == 1


def test_restart_replays_raw_and_never_retries_reserved_unknown_attempt(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    store.ambiguous_suffix = f"/{SPORT_KEYS[0]}/raw-envelope.json"
    transport = FakeTransportFactory(lambda: START)
    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    closure_head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    closure_node = json.loads(store.objects[closure_head["node_key"]].data)
    open_key = closure_node["previous_node_key"]
    open_sha = closure_node["previous_node_sha256"]
    open_node = json.loads(store.objects[open_key].data)
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-accounting-head-v1",
                "mission_id": MISSION_ID,
                "node_key": open_key,
                "node_sha256": open_sha,
                "slot_start_utc": open_node["slot_start_utc"],
                "lifetime_requests": open_node["lifetime_requests"],
                "lifetime_credits": open_node["lifetime_credits"],
                "provider_remaining_floor": open_node["provider_remaining_floor"],
                "credit_bound_valid": open_node["credit_bound_valid"],
                "slot_state": "OPEN",
            }
        ),
        metadata={"kind": "accounting-head"},
        etag='"reopened-for-crash-recovery"',
    )
    del store.objects[first["private_report_r2_key"]]
    del store.projections[LATEST_REPORT_KEY]

    recovered = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert recovered["provider_requests_new"] == 0
    assert recovered["validated_capture_count"] == 4
    assert len(transport.requests) == 5
    report = json.loads(store.objects[recovered["private_report_r2_key"]].data)
    assert report["branches"][0]["source"] == "PRIOR_ATTEMPT_NOT_RETRIED"


def test_dns_failure_is_cached_and_resolution_runs_once(tmp_path: Path) -> None:
    store = FakeStore()
    calls = 0
    secret = FakeSecretReader()

    def fail_resolution() -> NetworkResolution:
        nonlocal calls
        calls += 1
        raise OSError("resolver detail")

    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=secret,
        resolver=fail_resolution,
        clock=lambda: START,
    )
    assert receipt["status"] == "REAL_DATA_FAILED"
    assert calls == 1
    assert secret.reads == 0
    assert len([key for key in store.put_keys if key.endswith("attempt-reservation.json")]) == 5


def test_none_dns_resolution_is_a_stable_cached_failure(tmp_path: Path) -> None:
    store = FakeStore()
    secret = FakeSecretReader()
    transport = FakeTransportFactory(lambda: START)

    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=lambda: cast(NetworkResolution, None),
        clock=lambda: START,
    )

    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert receipt["status"] == "REAL_DATA_FAILED"
    assert secret.reads == 0
    assert transport.requests == []
    assert {branch["diagnostic"]["stage"] for branch in report["branches"]} == {"DNS_RESOLUTION"}
    assert {branch["diagnostic"]["code"] for branch in report["branches"]} == {
        "RECURRING_DNS_RESOLUTION_INVALID"
    }
    assert {branch["diagnostic"]["exception_class"] for branch in report["branches"]} == {
        "RecurringError"
    }


def test_sport_reservation_precedes_secret_and_secret_failure_is_cached(
    tmp_path: Path,
) -> None:
    store = FakeStore()

    class InspectingSecret:
        reads = 0

        def read(self) -> str:
            self.reads += 1
            assert any(
                key.endswith(f"/{SPORT_KEYS[0]}/attempt-reservation.json") for key in store.objects
            )
            raise ValueError("secret unavailable")

    secret = InspectingSecret()
    transport = FakeTransportFactory(lambda: START)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert receipt["status"] == "REAL_DATA_FAILED"
    assert secret.reads == 1
    assert transport.requests == []


def test_none_validated_provider_key_is_a_stable_cached_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore()
    secret = FakeSecretReader()
    transport = FakeTransportFactory(lambda: START)
    monkeypatch.setattr(
        recurring,
        "validate_provider_secret",
        lambda _value: cast(str, None),
    )

    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=secret,
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )

    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    assert receipt["status"] == "REAL_DATA_FAILED"
    assert secret.reads == 1
    assert transport.requests == []
    assert {branch["diagnostic"]["stage"] for branch in report["branches"]} == {"PROVIDER_SECRET"}
    assert {branch["diagnostic"]["code"] for branch in report["branches"]} == {
        "RECURRING_PROVIDER_SECRET_INVALID"
    }
    assert {branch["diagnostic"]["exception_class"] for branch in report["branches"]} == {
        "RecurringError"
    }


def test_branch_storage_exception_is_redacted_and_siblings_continue(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    store.raise_once_suffix = f"/{SPORT_KEYS[0]}/attempt-reservation.json"
    transport = FakeTransportFactory(lambda: START)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert receipt["provider_requests_new"] == 4
    assert len(transport.requests) == 4
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    failed = report["branches"][0]
    assert failed["diagnostic"] == {
        "stage": "BRANCH_RUNTIME",
        "code": "RECURRING_BRANCH_RUNTIME_FAILURE",
        "exception_class": "RuntimeError",
    }
    assert "secret-value" not in json.dumps(failed)


def test_ambiguous_sport_reservation_is_charged_but_never_dispatched(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    store.ambiguous_suffix = f"/{SPORT_KEYS[0]}/attempt-reservation.json"
    transport = FakeTransportFactory(_now)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=_now,
    )
    assert receipt["provider_requests_new"] == 4
    assert receipt["provider_requests_reserved"] == 5
    assert all(request.sport_key != SPORT_KEYS[0] for request in transport.requests)
    report = json.loads(store.objects[receipt["private_report_r2_key"]].data)
    branch = report["branches"][0]
    assert branch["diagnostic"]["code"] == "RECURRING_ATTEMPT_RESERVATION_AMBIGUOUS"


def _install_accounting_head(
    store: FakeStore,
    *,
    slot: datetime,
    requests: int,
    credits: int,
    etag: str = '"prior"',
) -> None:
    stamp = slot.isoformat().replace("+00:00", "Z")
    node_key = f"robin/autonomous-lab/{MISSION_ID}/accounting/fixtures/{requests}.json"
    node = {
        "schema_version": "robin-autonomous-accounting-node-v1",
        "mission_id": MISSION_ID,
        "node_kind": "ACCOUNTING_BASELINE",
        "slot_state": "CLOSED",
        "slot_start_utc": stamp,
        "github_run_id": "39999999999",
        "repository_sha": "a" * 40,
        "previous_node_key": None,
        "previous_node_sha256": None,
        "previous_head_etag": None,
        "entries": [
            {
                "slot_start_utc": stamp,
                "requests": requests,
                "credits": credits,
                "kind": "TEST_PRIOR",
            }
        ],
        "lifetime_requests": requests,
        "lifetime_credits": credits,
        "rolling_24h_requests": requests,
        "rolling_24h_credits": credits,
        "rolling_30d_requests": requests,
        "rolling_30d_credits": credits,
        "provider_remaining_floor": 19_969 - credits,
        "credit_bound_valid": True,
    }
    node_bytes = canonical_json_bytes(node)
    store.objects[node_key] = ObservedObject(
        data=node_bytes,
        metadata={
            "kind": "accounting-node",
            "sha256": hashlib.sha256(node_bytes).hexdigest(),
        },
    )
    marker = canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-accounting-initialized-v1",
            "mission_id": MISSION_ID,
            "root_node_key": node_key,
            "root_node_sha256": hashlib.sha256(node_bytes).hexdigest(),
        }
    )
    store.objects[ACCOUNTING_INITIALIZED_KEY] = ObservedObject(
        data=marker,
        metadata={"sha256": hashlib.sha256(marker).hexdigest()},
    )
    head = canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-accounting-head-v1",
            "mission_id": MISSION_ID,
            "node_key": node_key,
            "node_sha256": hashlib.sha256(node_bytes).hexdigest(),
            "slot_start_utc": stamp,
            "lifetime_requests": requests,
            "lifetime_credits": credits,
            "provider_remaining_floor": 19_969 - credits,
            "credit_bound_valid": True,
            "slot_state": "CLOSED",
        }
    )
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=head,
        metadata={"kind": "accounting-head"},
        etag=etag,
    )


def test_rolling_24h_request_and_credit_boundary_fails_before_provider(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    _install_accounting_head(
        store,
        slot=START - timedelta(hours=1),
        requests=136,
        credits=271,
    )
    transport = FakeTransportFactory(lambda: START)
    secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_ROLLING_24H_LIMIT"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert transport.requests == []
    assert secret.reads == 0


def test_rolling_30d_boundary_fails_before_provider(tmp_path: Path) -> None:
    store = FakeStore()
    _install_accounting_head(
        store,
        slot=START - timedelta(days=2),
        requests=3_996,
        credits=7_991,
    )
    transport = FakeTransportFactory(lambda: START)
    with pytest.raises(RecurringError, match="RECURRING_ROLLING_30D_LIMIT"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=FakeSecretReader(),
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert transport.requests == []


def test_older_slot_is_rejected_when_accounting_head_is_newer(tmp_path: Path) -> None:
    store = FakeStore()
    _install_accounting_head(
        store,
        slot=START + timedelta(hours=2),
        requests=5,
        credits=10,
    )
    secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_ACCOUNTING_SLOT_REGRESSION"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=FakeTransportFactory(lambda: START),
            secret_reader=secret,
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert secret.reads == 0


def test_admitted_slot_without_report_resumes_instead_of_reserving_again(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    first = _reserve_accounting_slot(_config(tmp_path), store=store, slot=START)
    resumed = _reserve_accounting_slot(
        _config(tmp_path, run_id="40000000002"), store=store, slot=START
    )
    assert resumed.node_key == first.node_key
    assert resumed.node_sha256 == first.node_sha256
    assert store.latest_puts == 1


def test_failed_attempt_advances_incident_without_losing_last_usable_report(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    later = START + timedelta(hours=2)

    def fail_resolution() -> NetworkResolution:
        raise OSError("resolver unavailable")

    failed = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=FakeTransportFactory(lambda: later),
        secret_reader=FakeSecretReader(),
        resolver=fail_resolution,
        clock=lambda: later,
    )
    assert failed["status"] == "REAL_DATA_FAILED"
    pointer = json.loads(store.projections[LATEST_REPORT_KEY].data)
    assert pointer["schema_version"] == "robin-autonomous-lab-latest-v2"
    assert pointer["report_key"] == failed["private_report_r2_key"]
    assert pointer["last_usable"]["report_key"] == first["private_report_r2_key"]
    assert pointer["last_usable"]["status"] == "REAL_DATA_COMPLETE"


def test_closed_report_repairs_missing_latest_before_next_failed_slot(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    first = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    del store.projections[LATEST_REPORT_KEY]
    later = START + timedelta(hours=2)

    def fail_resolution() -> NetworkResolution:
        raise OSError("resolver unavailable")

    failed = run_recurring_real_data(
        _config(tmp_path, run_id="40000000002"),
        store=store,
        transport_factory=FakeTransportFactory(lambda: later),
        secret_reader=FakeSecretReader(),
        resolver=fail_resolution,
        clock=lambda: later,
    )
    assert failed["status"] == "REAL_DATA_FAILED"
    pointer = json.loads(store.projections[LATEST_REPORT_KEY].data)
    assert pointer["report_key"] == failed["private_report_r2_key"]
    assert pointer["last_usable"]["report_key"] == first["private_report_r2_key"]
    assert pointer["last_usable"]["status"] == "REAL_DATA_COMPLETE"


def test_raw_write_ambiguity_keeps_provider_attempt_charged(tmp_path: Path) -> None:
    store = FakeStore()
    store.ambiguous_suffix = f"/{SPORT_KEYS[0]}/raw-envelope.json"
    transport = FakeTransportFactory(lambda: START)
    receipt = run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=transport,
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert len(transport.requests) == 5
    assert receipt["provider_requests_new"] == 5
    assert receipt["validated_capture_count"] == 4


def test_concurrent_last_capacity_cas_loser_refreshes_and_makes_no_call(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    _install_accounting_head(
        store,
        slot=START - timedelta(hours=2),
        requests=135,
        credits=270,
    )

    def competitor(target: FakeStore) -> None:
        _install_accounting_head(
            target,
            slot=START - timedelta(hours=2),
            requests=140,
            credits=280,
            etag='"competitor"',
        )

    store.before_next_cas = competitor
    transport = FakeTransportFactory(lambda: START)
    with pytest.raises(RecurringError, match="RECURRING_ROLLING_24H_LIMIT"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=transport,
            secret_reader=FakeSecretReader(),
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert transport.requests == []
    assert store.latest_puts == 1


def test_broken_accounting_predecessor_fails_closed_before_secret(tmp_path: Path) -> None:
    store = FakeStore()
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-accounting-head-v1",
                "mission_id": MISSION_ID,
                "node_key": "missing.json",
                "node_sha256": "0" * 64,
                "slot_start_utc": "2026-10-04T08:00:00Z",
                "lifetime_requests": 16,
                "lifetime_credits": 34,
                "provider_remaining_floor": 19_969,
            }
        ),
        metadata={"kind": "accounting-head"},
        etag='"broken"',
    )
    secret = FakeSecretReader()
    with pytest.raises(RecurringError, match="RECURRING_ACCOUNTING_PREDECESSOR_MISSING"):
        run_recurring_real_data(
            _config(tmp_path),
            store=store,
            transport_factory=FakeTransportFactory(lambda: START),
            secret_reader=secret,
            resolver=lambda: _resolution(START),
            clock=lambda: START,
        )
    assert secret.reads == 0


def test_missing_head_after_initialization_never_reseeds(tmp_path: Path) -> None:
    store = FakeStore()
    run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    assert ACCOUNTING_INITIALIZED_KEY in store.objects
    del store.projections[ACCOUNTING_HEAD_KEY]
    later = START + timedelta(hours=2)
    transport = FakeTransportFactory(lambda: later)
    secret = FakeSecretReader()

    with pytest.raises(
        RecurringError,
        match="RECURRING_ACCOUNTING_HEAD_MISSING_AFTER_INITIALIZATION",
    ):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(later),
            clock=lambda: later,
        )
    assert transport.requests == []
    assert secret.reads == 0


@pytest.mark.parametrize("failure", ["missing", "digest"])
def test_declared_accounting_predecessor_is_verified_before_provider(
    failure: str, tmp_path: Path
) -> None:
    store = FakeStore()
    run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    key = head["node_key"]
    node = json.loads(store.objects[key].data)
    if failure == "missing":
        node["previous_node_key"] = "missing-predecessor.json"
    node["previous_node_sha256"] = "0" * 64
    node_bytes = canonical_json_bytes(node)
    store.objects[key] = ObservedObject(data=node_bytes, metadata={})
    head["node_sha256"] = hashlib.sha256(node_bytes).hexdigest()
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=canonical_json_bytes(head), metadata={}, etag='"tampered"'
    )
    later = START + timedelta(hours=2)
    transport = FakeTransportFactory(lambda: later)
    secret = FakeSecretReader()

    with pytest.raises(
        RecurringError,
        match=(
            "RECURRING_ACCOUNTING_PREDECESSOR_MISSING"
            if failure == "missing"
            else "RECURRING_ACCOUNTING_PREDECESSOR_MISMATCH"
        ),
    ):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(later),
            clock=lambda: later,
        )
    assert transport.requests == []
    assert secret.reads == 0


def test_accounting_transition_totals_are_verified_before_provider(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    key = head["node_key"]
    node = json.loads(store.objects[key].data)
    node["lifetime_requests"] += 999
    node_bytes = canonical_json_bytes(node)
    store.objects[key] = ObservedObject(data=node_bytes, metadata={})
    head["node_sha256"] = hashlib.sha256(node_bytes).hexdigest()
    head["lifetime_requests"] = node["lifetime_requests"]
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=canonical_json_bytes(head), metadata={}, etag='"tampered"'
    )
    later = START + timedelta(hours=2)
    transport = FakeTransportFactory(lambda: later)
    secret = FakeSecretReader()

    with pytest.raises(RecurringError, match="RECURRING_ACCOUNTING_TRANSITION_INVALID"):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(later),
            clock=lambda: later,
        )
    assert transport.requests == []
    assert secret.reads == 0


def test_detached_accounting_chain_cannot_bypass_initialized_root(
    tmp_path: Path,
) -> None:
    store = FakeStore()
    run_recurring_real_data(
        _config(tmp_path),
        store=store,
        transport_factory=FakeTransportFactory(lambda: START),
        secret_reader=FakeSecretReader(),
        resolver=lambda: _resolution(START),
        clock=lambda: START,
    )
    head = json.loads(store.projections[ACCOUNTING_HEAD_KEY].data)
    closure = json.loads(store.objects[head["node_key"]].data)
    original_open = json.loads(store.objects[closure["previous_node_key"]].data)
    orphan = dict(original_open) | {
        "previous_node_key": "missing-grandparent.json",
        "previous_node_sha256": "0" * 64,
    }
    orphan_bytes = canonical_json_bytes(orphan)
    orphan_key = "accounting/orphan-open.json"
    store.objects[orphan_key] = ObservedObject(data=orphan_bytes, metadata={})
    detached = dict(closure) | {
        "previous_node_key": orphan_key,
        "previous_node_sha256": hashlib.sha256(orphan_bytes).hexdigest(),
    }
    detached_bytes = canonical_json_bytes(detached)
    detached_key = "accounting/detached-closure.json"
    store.objects[detached_key] = ObservedObject(data=detached_bytes, metadata={})
    head["node_key"] = detached_key
    head["node_sha256"] = hashlib.sha256(detached_bytes).hexdigest()
    store.projections[ACCOUNTING_HEAD_KEY] = LatestProjection(
        data=canonical_json_bytes(head), metadata={}, etag='"detached"'
    )
    later = START + timedelta(hours=2)
    transport = FakeTransportFactory(lambda: later)
    secret = FakeSecretReader()

    with pytest.raises(RecurringError, match="RECURRING_ACCOUNTING_PREDECESSOR_MISSING"):
        run_recurring_real_data(
            _config(tmp_path, run_id="40000000002"),
            store=store,
            transport_factory=transport,
            secret_reader=secret,
            resolver=lambda: _resolution(later),
            clock=lambda: later,
        )
    assert transport.requests == []
    assert secret.reads == 0


def test_market_absent_and_duplicated_are_distinct_while_legacy_is_explicit() -> None:
    payload = json.loads(_payload(SPORT_KEYS[0], START))
    markets = payload[0]["bookmakers"][0]["markets"]
    missing_payload = json.loads(json.dumps(payload))
    missing_payload[0]["bookmakers"][0]["markets"] = [markets[0]]
    duplicated_payload = json.loads(json.dumps(payload))
    duplicated_payload[0]["bookmakers"][0]["markets"] = [
        markets[0],
        markets[0],
        markets[1],
    ]
    quota = _Quota(remaining=100, used=2, last=2, observed_at_utc=START)

    _rows, missing = _normalize_payload(
        json.dumps(missing_payload).encode(),
        cycle_index=1,
        sport_key=SPORT_KEYS[0],
        capture_time=START,
        quota=quota,
    )
    _rows, duplicated = _normalize_payload(
        json.dumps(duplicated_payload).encode(),
        cycle_index=1,
        sport_key=SPORT_KEYS[0],
        capture_time=START,
        quota=quota,
    )
    assert {item["code"] for item in missing} == {"RESULT_MARKET_MISSING"}
    assert {item["code"] for item in duplicated} == {"RESULT_MARKET_DUPLICATED"}
    assert classify_market_limitation("RESULT_MARKET_MISSING") == "MISSING"
    assert classify_market_limitation("RESULT_MARKET_DUPLICATED") == "DUPLICATED"
    assert classify_market_limitation("RESULT_MARKET_MISSING_OR_DUPLICATED") == "LEGACY_UNKNOWN"


def test_v2_raw_envelope_rejects_capture_outside_acquisition_bounds(
    tmp_path: Path,
) -> None:
    response = LiveTransportResponse(
        http_status=200,
        headers={},
        network_calls=1,
        provider_calls=1,
        retries=0,
        redirects=0,
        payload=b"[]",
        first_observed_at_utc=START - timedelta(minutes=1),
    )

    with pytest.raises(RecurringError, match="RECURRING_ACQUISITION_TIME_INVALID"):
        recurring._raw_envelope(
            _config(tmp_path),
            slot=START,
            sport_key=SPORT_KEYS[0],
            response=response,
            quota=None,
            quota_code=None,
            observed_cost=None,
            observed_remaining=None,
            acquisition_started_at=START,
            acquisition_finished_at=START + timedelta(minutes=1),
        )

    valid_response = LiveTransportResponse(
        http_status=200,
        headers={},
        network_calls=1,
        provider_calls=1,
        retries=0,
        redirects=0,
        payload=b"[]",
        first_observed_at_utc=START,
    )
    encoded = recurring._raw_envelope(
        _config(tmp_path),
        slot=START,
        sport_key=SPORT_KEYS[0],
        response=valid_response,
        quota=None,
        quota_code=None,
        observed_cost=None,
        observed_remaining=None,
        acquisition_started_at=START,
        acquisition_finished_at=START + timedelta(minutes=1),
    )
    malformed = json.loads(encoded)
    malformed["capture_time_utc"] = (
        (START - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    )

    with pytest.raises(RecurringError, match="RECURRING_RAW_ENVELOPE_INVALID"):
        recurring._payload_from_readback(
            canonical_json_bytes(malformed),
            slot=START,
            sport_key=SPORT_KEYS[0],
        )
