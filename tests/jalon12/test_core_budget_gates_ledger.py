from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from robin.prospective_observatory import (
    AvailabilityStatus,
    BudgetExceeded,
    BudgetLedger,
    CaptureContext,
    CaptureFamily,
    CircuitBreaker,
    EvidenceEventKindV3,
    GateObservation,
    GateStatus,
    InMemoryObjectStore,
    ProspectiveR2Repository,
    ProviderKind,
    PublicEvidenceLedgerV3,
    evaluate_fixture_gates,
    frozen_h11_protocols,
    hypothesis_progress,
)
from robin.prospective_observatory.budgets import CircuitState
from robin.prospective_observatory.contracts import ProspectiveHypothesisStatus

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)
KICKOFF = datetime(2026, 8, 3, 20, tzinfo=UTC)


def _capture(
    *,
    family: CaptureFamily,
    window: str,
    observed_at: datetime,
    payload: object,
) -> GateObservation:
    context = CaptureContext(
        window_id=f"fixture:{family.value}:{window}",
        window_label=window,
        fixture_id="fixture-1",
        competition="Ligue 1",
        season="2026",
        provider="api-football" if family is not CaptureFamily.ODDS else "odds-api",
        family=family,
        requested_at=observed_at - timedelta(seconds=2),
        response_received_at=observed_at - timedelta(seconds=1),
        observed_at=observed_at,
        cutoff_at=KICKOFF - timedelta(minutes=20),
        kickoff_at=KICKOFF,
        http_status=200,
        source_endpoint="https://provider.example/v1/capture",
        complete=True,
        quality_status=AvailabilityStatus.CAPTURED,
        provider_calls=1,
        code_revision="revision-j12",
        materialized_at=observed_at,
    )
    stored = ProspectiveR2Repository(InMemoryObjectStore()).capture(
        payload=payload,
        context=context,
    )
    assert isinstance(payload, dict)
    return GateObservation(receipt=stored.receipt, projection=payload)


def test_budget_caps_external_reserves_idempotence_and_circuit_breaker() -> None:
    ledger = BudgetLedger()
    ledger.authorize(
        ProviderKind.API_FOOTBALL,
        1,
        provider_remaining=5_001,
    )
    with pytest.raises(BudgetExceeded, match="EXTERNAL_RESERVE"):
        ledger.authorize(
            ProviderKind.API_FOOTBALL,
            2,
            provider_remaining=5_001,
        )
    assert ledger.record(
        idempotency_key="capture-1",
        provider=ProviderKind.API_FOOTBALL,
        units=1,
        recorded_at=NOW,
        reason="FIXTURE_REGISTRY",
    )
    assert not ledger.record(
        idempotency_key="capture-1",
        provider=ProviderKind.API_FOOTBALL,
        units=1,
        recorded_at=NOW,
        reason="FIXTURE_REGISTRY",
    )
    # The former 250-credit pilot ceiling is now governed by the adaptive
    # central policy. This low-level ledger retains only an absolute
    # append-only corruption guard.
    with pytest.raises(BudgetExceeded):
        ledger.authorize(ProviderKind.ODDS_API, 10_001)

    breaker = CircuitBreaker(failure_threshold=2, cooldown=timedelta(minutes=5))
    breaker.record_failure(now=NOW)
    assert breaker.allow(now=NOW)
    breaker.record_failure(now=NOW)
    assert breaker.state(now=NOW) is CircuitState.OPEN
    assert not breaker.allow(now=NOW + timedelta(minutes=4))
    assert breaker.allow(now=NOW + timedelta(minutes=5))
    assert not breaker.allow(now=NOW + timedelta(minutes=5))
    breaker.record_success()
    assert breaker.state(now=NOW) is CircuitState.CLOSED


def test_three_identical_payloads_in_three_windows_pass_player_gate() -> None:
    observations = tuple(
        _capture(
            family=CaptureFamily.PLAYER_STATUS,
            window=label,
            observed_at=KICKOFF - offset,
            payload={"players": [{"id": "player-1"}]},
        )
        for label, offset in (
            ("J-7", timedelta(days=7)),
            ("J-3", timedelta(days=3)),
            ("J-1", timedelta(days=1)),
        )
    )
    assert len({item.receipt.payload_sha256 for item in observations}) == 1
    player_gate = evaluate_fixture_gates("fixture-1", observations)[0]
    assert player_gate.status is GateStatus.PASSED
    assert player_gate.observations == 3


def test_lineup_post_cutoff_and_incomplete_lineup_fail_closed() -> None:
    late = _capture(
        family=CaptureFamily.LINEUP,
        window="H-0:15",
        observed_at=KICKOFF - timedelta(minutes=10),
        payload={"starters": [f"p-{index}" for index in range(11)]},
    )
    late_gate = evaluate_fixture_gates("fixture-1", (late,))[2]
    assert late_gate.status is GateStatus.BLOCKED_BY_TEMPORALITY

    incomplete = _capture(
        family=CaptureFamily.LINEUP,
        window="H-1",
        observed_at=KICKOFF - timedelta(hours=1),
        payload={
            "team_id": "home",
            "starters": [f"p-{index}" for index in range(11)],
        },
    )
    incomplete_gate = evaluate_fixture_gates("fixture-1", (incomplete,))[2]
    assert incomplete_gate.status is GateStatus.INVALID_PAYLOAD

    home = _capture(
        family=CaptureFamily.LINEUP,
        window="H-1",
        observed_at=KICKOFF - timedelta(hours=1),
        payload={
            "team_id": "home",
            "starters": [f"h-{index}" for index in range(11)],
        },
    )
    away = GateObservation(
        receipt=home.receipt,
        projection={
            "team_id": "away",
            "starters": [f"a-{index}" for index in range(11)],
        },
    )
    complete_gate = evaluate_fixture_gates(
        "fixture-1",
        (home, away),
    )[2]
    assert complete_gate.status is GateStatus.PASSED


def test_empty_injury_response_is_valid_negative_point_in_time_evidence() -> None:
    captured = _capture(
        family=CaptureFamily.INJURY,
        window="J-1",
        observed_at=KICKOFF - timedelta(days=1),
        payload={},
    )
    empty = GateObservation(
        receipt=captured.receipt.model_copy(
            update={
                "complete": False,
                "quality_status": AvailabilityStatus.CAPTURED_EMPTY,
            }
        ),
        projection={},
    )

    injury_gate = evaluate_fixture_gates("fixture-1", (empty,))[1]

    assert injury_gate.status is GateStatus.PASSED
    assert injury_gate.observations == 1
    assert injury_gate.reason == "NO_INJURY_REPORTED_AT_CAPTURE"


def test_ledger_v3_chain_allowlist_and_recursive_betting_guard(tmp_path: object) -> None:
    ledger = PublicEvidenceLedgerV3()
    ledger.append(
        event_kind=EvidenceEventKindV3.FIXTURE_REGISTERED,
        recorded_at=NOW,
        code_revision="revision-j12",
        fixture_id="fixture-1",
        evidence_hashes=("a" * 64,),
        status="REGISTERED",
        reason="OFFICIAL_FIXTURE",
        payload={"dataset_version": "prospective-v1"},
    )
    assert ledger.audit()["status"] == "HASH_CHAIN_VERIFIED"
    with pytest.raises(ValueError, match="BETTING_FIELD_FORBIDDEN"):
        ledger.append(
            event_kind=EvidenceEventKindV3.CAPTURE_SUCCEEDED,
            recorded_at=NOW,
            code_revision="revision-j12",
            fixture_id="fixture-1",
            evidence_hashes=("b" * 64,),
            status="CAPTURED",
            reason="R2_VERIFIED",
            payload={"nested": {"stake_amount": 1}},
        )


def test_h11_protocols_are_frozen_and_samples_cannot_be_relaxed() -> None:
    protocols = frozen_h11_protocols()
    assert [item.hypothesis_id for item in protocols] == [
        f"H11-{index:03d}" for index in range(1, 9)
    ]
    assert all(item.frozen_before_capture for item in protocols)
    protocol = protocols[0]
    before = hypothesis_progress(
        protocol,
        fixtures_tracked=5,
        observations=protocol.minimum_observations - 1,
        first_potentially_eligible_match=KICKOFF,
    )
    assert before.status is ProspectiveHypothesisStatus.MINIMUM_SAMPLE_NOT_REACHED
    assert not before.conclusion_allowed
    eligible = hypothesis_progress(
        protocol,
        fixtures_tracked=20,
        observations=protocol.minimum_observations,
        first_potentially_eligible_match=KICKOFF,
    )
    assert eligible.status is (
        ProspectiveHypothesisStatus.ELIGIBLE_FOR_EXPLORATORY_ANALYSIS
    )
    assert eligible.conclusion_allowed
