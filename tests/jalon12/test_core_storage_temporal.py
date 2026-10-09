from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from robin.prospective_observatory import (
    CAPTURE_POLICIES,
    AvailabilityStatus,
    CaptureContext,
    CaptureFamily,
    InMemoryObjectStore,
    InMemoryProjectionSink,
    ProspectiveFixture,
    ProspectiveR2Repository,
    classify_window,
    replay_from_r2,
    retry_disposition,
    schedule_windows,
    temporal_admissibility,
)
from robin.prospective_observatory.contracts import RetryDisposition
from robin.prospective_observatory.gates import (
    GateObservation,
    GateStatus,
    evaluate_lineup_gate,
)
from robin.prospective_observatory.r2 import AppendOnlyViolation

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)
KICKOFF = datetime(2026, 8, 3, 20, tzinfo=UTC)


def _fixture() -> ProspectiveFixture:
    return ProspectiveFixture(
        fixture_id="ligue1-2026-001",
        competition="Ligue 1",
        season="2026",
        phase="Regular Season",
        home_team_id="team-home",
        away_team_id="team-away",
        kickoff_at=KICKOFF,
        provider="api-football",
        provider_fixture_id="123456",
        registered_at=NOW,
        code_revision="revision-j12",
    )


def _context(
    *,
    observed_at: datetime,
    cutoff_at: datetime,
    family: CaptureFamily = CaptureFamily.LINEUP,
    window_id: str | None = "fixture:LINEUP:H-1",
    window_label: str = "H-1",
) -> CaptureContext:
    return CaptureContext(
        window_id=window_id,
        window_label=window_label,
        fixture_id="ligue1-2026-001",
        competition="Ligue 1",
        season="2026",
        provider="api-football",
        family=family,
        requested_at=observed_at - timedelta(seconds=2),
        response_received_at=observed_at - timedelta(seconds=1),
        observed_at=observed_at,
        cutoff_at=cutoff_at,
        kickoff_at=KICKOFF,
        http_status=200,
        source_endpoint="https://v3.football.api-sports.io/fixtures/lineups",
        complete=True,
        quality_status=AvailabilityStatus.CAPTURED,
        provider_calls=1,
        code_revision="revision-j12",
        materialized_at=observed_at,
    )


def test_fixture_business_hash_ignores_registration_metadata_only() -> None:
    fixture = _fixture()
    replayed = fixture.model_copy(
        update={
            "registered_at": fixture.registered_at + timedelta(minutes=5),
            "code_revision": "new-code-revision",
        }
    )
    changed_kickoff = fixture.model_copy(
        update={"kickoff_at": fixture.kickoff_at + timedelta(minutes=15)}
    )

    assert replayed.registry_hash == fixture.registry_hash
    assert changed_kickoff.registry_hash != fixture.registry_hash


def test_policy_is_canonical_and_matches_central_config() -> None:
    root = Path(__file__).resolve().parents[2]
    policy = json.loads(
        (root / "configs" / "prospective_observatory_v1.json").read_text("utf-8")
    )
    assert {family.value for family in CaptureFamily} == set(
        policy["capture_windows"]
    ) - {"policy_version", "operational_tolerance_seconds"}
    for family in CaptureFamily:
        assert [item.label for item in CAPTURE_POLICIES[family]] == policy[
            "capture_windows"
        ][family.value]


def test_windows_due_not_due_missed_and_late_retry_are_fail_closed() -> None:
    windows = schedule_windows(
        _fixture(),
        CaptureFamily.LINEUP,
        scheduled_at=NOW,
    )
    h1 = next(window for window in windows if window.label == "NEAR_KICKOFF")
    assert classify_window(h1, now=h1.opens_at - timedelta(seconds=1)) is (
        AvailabilityStatus.NOT_DUE
    )
    assert classify_window(h1, now=h1.due_at) is AvailabilityStatus.DUE
    assert classify_window(h1, now=h1.cutoff_at) is AvailabilityStatus.MISSED_WINDOW
    assert (
        retry_disposition(window=h1, now=h1.cutoff_at, attempts=1)
        is RetryDisposition.LATE_RETRY
    )
    assert classify_window(h1, now=KICKOFF + timedelta(seconds=1)) is (
        AvailabilityStatus.MISSED_WINDOW
    )


def test_r2_key_receipt_hash_and_replay_are_deterministic_and_index_only() -> None:
    store = InMemoryObjectStore()
    repository = ProspectiveR2Repository(store)
    context = _context(
        observed_at=KICKOFF - timedelta(hours=1),
        cutoff_at=KICKOFF - timedelta(minutes=50),
    )
    payload = {"response": [{"team": 1, "startXI": list(range(11))}]}
    first = repository.capture(payload=payload, context=context)
    second = repository.capture(payload=payload, context=context)

    assert first.payload_created and first.receipt_created
    assert not second.payload_created and not second.receipt_created
    assert first.receipt == second.receipt
    assert first.receipt.r2_key.startswith(
        "prospective-deep-data/schema-v1/competition=Ligue%201/"
    )
    assert temporal_admissibility(first.receipt) is AvailabilityStatus.COMPLETE
    # One append-only recovery intent accompanies payload + receipt.
    assert store.object_count == 3

    sink = InMemoryProjectionSink()
    initial = replay_from_r2(repository, sink)
    replay = replay_from_r2(repository, sink)
    assert initial.provider_calls == initial.provider_credits == 0
    assert initial.projections_inserted == 1
    assert replay.projections_inserted == 0
    assert replay.duplicates_avoided == 1
    assert replay.dataset_hash == initial.dataset_hash
    only_projection = next(iter(sink.rows.values()))[1]
    assert "data" not in only_projection
    assert "payload" not in only_projection
    assert only_projection["r2_key"] == first.receipt.r2_key


def test_same_raw_payload_has_one_object_and_distinct_receipts_per_window() -> None:
    store = InMemoryObjectStore()
    repository = ProspectiveR2Repository(store)
    observed_at = KICKOFF - timedelta(hours=1)
    payload = {"response": [{"team": 1, "startXI": list(range(11))}]}
    first = repository.capture(
        payload=payload,
        context=_context(
            observed_at=observed_at,
            cutoff_at=KICKOFF - timedelta(minutes=50),
            window_id="fixture:LINEUP:H-1",
            window_label="H-1",
        ),
    )
    second = repository.capture(
        payload=payload,
        context=_context(
            observed_at=observed_at,
            cutoff_at=KICKOFF - timedelta(minutes=35),
            window_id="fixture:LINEUP:H-0:45",
            window_label="H-0:45",
        ),
    )

    assert first.receipt.r2_key == second.receipt.r2_key
    assert first.receipt.receipt_r2_key != second.receipt.receipt_r2_key
    assert first.payload_created
    assert not second.payload_created
    assert first.receipt_created and second.receipt_created
    assert first.receipt.receipt_hash != second.receipt.receipt_hash
    # One shared payload, two receipts and two recovery intents.
    assert store.object_count == 5
    assert repository.read_capture(first.receipt.receipt_r2_key).receipt == first.receipt
    assert repository.read_capture(second.receipt.receipt_r2_key).receipt == second.receipt


def test_registry_capture_has_no_fictitious_due_window() -> None:
    repository = ProspectiveR2Repository(InMemoryObjectStore())
    stored = repository.capture(
        payload={"fixture": {"id": 123456}},
        context=_context(
            observed_at=NOW,
            cutoff_at=KICKOFF - timedelta(days=1),
            family=CaptureFamily.FIXTURE,
            window_id=None,
            window_label="REGISTRY",
        ),
    )
    assert stored.receipt.window_id is None
    assert stored.receipt.window_label == "REGISTRY"


def test_receipt_materialized_after_cutoff_is_never_temporally_admissible() -> None:
    cutoff = KICKOFF - timedelta(minutes=50)
    observed = cutoff - timedelta(seconds=1)
    repository = ProspectiveR2Repository(InMemoryObjectStore())
    base_context = _context(observed_at=observed, cutoff_at=cutoff)
    late_context = CaptureContext.model_validate(
        {
            **base_context.model_dump(),
            "materialized_at": cutoff + timedelta(seconds=1),
        }
    )
    stored = repository.capture(
        payload={"response": [{"team": 1}]},
        context=late_context,
    )
    assert stored.receipt.temporally_admissible is False


def test_capture_rejects_materialization_before_observation() -> None:
    observed = KICKOFF - timedelta(hours=1)
    context = _context(
        observed_at=observed,
        cutoff_at=KICKOFF - timedelta(minutes=50),
    )
    with pytest.raises(ValueError, match="MATERIALIZED_BEFORE_OBSERVATION"):
        CaptureContext.model_validate(
            {
                **context.model_dump(),
                "materialized_at": observed - timedelta(seconds=1),
            }
        )


def test_conflicting_equal_time_lineup_receipts_fail_closed() -> None:
    repository = ProspectiveR2Repository(InMemoryObjectStore())
    context = _context(
        observed_at=KICKOFF - timedelta(hours=1),
        cutoff_at=KICKOFF - timedelta(minutes=50),
    )
    first = repository.capture(payload={"version": 1}, context=context).receipt
    second = repository.capture(payload={"version": 2}, context=context).receipt
    evaluation = evaluate_lineup_gate(
        first.fixture_id,
        (
            GateObservation(first, {"team_id": "home", "starters": list(range(11))}),
            GateObservation(second, {"team_id": "away", "starters": list(range(11, 22))}),
        ),
    )
    assert evaluation.status is GateStatus.INVALID_PAYLOAD
    assert evaluation.reason == "CONFLICTING_EQUAL_TIME_RECEIPTS"
    assert evaluation.evidence["receipt_hashes"] == sorted(
        (first.receipt_hash, second.receipt_hash)
    )


def test_physical_response_identity_handles_global_odds_batches() -> None:
    observed_at = KICKOFF - timedelta(hours=1)
    base = _context(
        observed_at=observed_at,
        cutoff_at=KICKOFF - timedelta(minutes=1),
    )
    repository = ProspectiveR2Repository(InMemoryObjectStore())
    odds_a = repository.capture(
        payload={"fixture": "a"},
        context=base.model_copy(
            update={
                "fixture_id": "fixture-a",
                "provider": "the-odds-api",
                "family": CaptureFamily.ODDS,
                "source_endpoint": "/sports/soccer_france_ligue_one/odds",
            }
        ),
    )
    odds_b = repository.capture(
        payload={"fixture": "b"},
        context=base.model_copy(
            update={
                "fixture_id": "fixture-b",
                "provider": "the-odds-api",
                "family": CaptureFamily.ODDS,
                "source_endpoint": "/sports/soccer_france_ligue_one/odds",
            }
        ),
    )
    api_a = repository.capture(
        payload={"fixture": "a"},
        context=base.model_copy(update={"fixture_id": "fixture-a"}),
    )
    api_b = repository.capture(
        payload={"fixture": "b"},
        context=base.model_copy(update={"fixture_id": "fixture-b"}),
    )

    assert odds_a.receipt.physical_capture_id == (
        odds_b.receipt.physical_capture_id
    )
    assert api_a.receipt.physical_capture_id != (
        api_b.receipt.physical_capture_id
    )


def test_append_only_store_detects_existing_byte_divergence() -> None:
    store = InMemoryObjectStore()
    repository = ProspectiveR2Repository(store)
    context = _context(
        observed_at=KICKOFF - timedelta(hours=1),
        cutoff_at=KICKOFF - timedelta(minutes=50),
    )
    stored = repository.capture(payload={"lineup": []}, context=context)
    store._objects[stored.receipt.r2_key] = b"mutated"  # noqa: SLF001
    with pytest.raises(AppendOnlyViolation, match="R2_APPEND_ONLY_OBJECT_MISMATCH"):
        repository.capture(payload={"lineup": []}, context=context)


def test_late_capture_is_retained_but_not_admissible() -> None:
    repository = ProspectiveR2Repository(InMemoryObjectStore())
    stored = repository.capture(
        payload={"lineup": []},
        context=_context(
            observed_at=KICKOFF - timedelta(minutes=20),
            cutoff_at=KICKOFF - timedelta(minutes=30),
        ),
    )
    assert not stored.receipt.temporally_admissible
    assert temporal_admissibility(stored.receipt) is (
        AvailabilityStatus.TEMPORALITY_FAILED
    )
