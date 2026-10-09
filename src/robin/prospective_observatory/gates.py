"""Fixture-level and aggregate prospective data gates."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from robin.prospective_observatory.contracts import (
    AvailabilityStatus,
    CaptureFamily,
    CaptureReceipt,
)


class GateName(StrEnum):
    PROSPECTIVE_PLAYER_GATE = "PROSPECTIVE_PLAYER_GATE"
    PROSPECTIVE_INJURY_GATE = "PROSPECTIVE_INJURY_GATE"
    PROSPECTIVE_LINEUP_GATE = "PROSPECTIVE_LINEUP_GATE"
    PROSPECTIVE_FORMATION_GATE = "PROSPECTIVE_FORMATION_GATE"
    PROSPECTIVE_MARKET_GATE = "PROSPECTIVE_MARKET_GATE"


class GateStatus(StrEnum):
    PASSED = "PASSED"
    BLOCKED_BY_COVERAGE = "BLOCKED_BY_COVERAGE"
    BLOCKED_BY_TEMPORALITY = "BLOCKED_BY_TEMPORALITY"
    BLOCKED_BY_IDENTITY = "BLOCKED_BY_IDENTITY"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"


@dataclass(frozen=True, slots=True)
class GateObservation:
    receipt: CaptureReceipt
    projection: dict[str, object]
    identity_ok: bool = True


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    gate: GateName
    fixture_id: str
    status: GateStatus
    observations: int
    reason: str
    evidence: dict[str, object]


@dataclass(frozen=True, slots=True)
class AggregateGateEvaluation:
    gate: GateName
    fixtures: int
    passed: int
    status_counts: dict[str, int]
    coverage: float
    status: GateStatus


def fixture_matches(
    observation: GateObservation,
    *,
    fixture_id: str,
) -> bool:
    return observation.receipt.fixture_id == fixture_id


def _family(
    observations: tuple[GateObservation, ...],
    *families: CaptureFamily,
) -> tuple[GateObservation, ...]:
    allowed = set(families)
    return tuple(item for item in observations if item.receipt.family in allowed)


def _pre_cutoff(
    observations: tuple[GateObservation, ...],
) -> tuple[GateObservation, ...]:
    return tuple(item for item in observations if item.receipt.temporally_admissible)


def _independent_capture_count(
    observations: tuple[GateObservation, ...],
) -> int:
    return len(
        {
            (
                item.receipt.physical_capture_id,
                item.receipt.fixture_id,
                item.receipt.family,
            )
            for item in observations
        }
    )


def _receipt_evidence(
    observations: tuple[GateObservation, ...],
) -> dict[str, object]:
    return {
        "receipt_hashes": sorted(
            {item.receipt.receipt_hash for item in observations}
        )
    }


def _latest_receipt_observations(
    observations: tuple[GateObservation, ...],
) -> tuple[GateObservation, ...] | None:
    latest_time = max(
        item.receipt.response_received_at for item in observations
    )
    latest_at_time = tuple(
        item
        for item in observations
        if item.receipt.response_received_at == latest_time
    )
    hashes = {item.receipt.receipt_hash for item in latest_at_time}
    if len(hashes) != 1:
        return None
    receipt_hash = next(iter(hashes))
    return tuple(
        item
        for item in latest_at_time
        if item.receipt.receipt_hash == receipt_hash
    )


def _blocked(
    gate: GateName,
    fixture_id: str,
    observations: tuple[GateObservation, ...],
    *,
    require_identity: bool = True,
) -> GateEvaluation | None:
    if not observations:
        return GateEvaluation(
            gate=gate,
            fixture_id=fixture_id,
            status=GateStatus.BLOCKED_BY_COVERAGE,
            observations=0,
            reason="NO_PROSPECTIVE_OBSERVATION",
            evidence={},
        )
    temporal = _pre_cutoff(observations)
    if not temporal:
        return GateEvaluation(
            gate=gate,
            fixture_id=fixture_id,
            status=GateStatus.BLOCKED_BY_TEMPORALITY,
            observations=_independent_capture_count(observations),
            reason="NO_RESPONSE_RECEIVED_BEFORE_CUTOFF",
            evidence={
                "late_observations": _independent_capture_count(observations),
                **_receipt_evidence(observations),
            },
        )
    if require_identity and any(not item.identity_ok for item in temporal):
        return GateEvaluation(
            gate=gate,
            fixture_id=fixture_id,
            status=GateStatus.BLOCKED_BY_IDENTITY,
            observations=_independent_capture_count(temporal),
            reason="IDENTITY_NOT_CANONICAL",
            evidence=_receipt_evidence(temporal),
        )
    return None


def evaluate_player_gate(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
    *,
    minimum_captures: int = 3,
) -> GateEvaluation:
    selected = _family(
        observations,
        CaptureFamily.SQUAD,
        CaptureFamily.PLAYER_STATUS,
    )
    blocked = _blocked(
        GateName.PROSPECTIVE_PLAYER_GATE,
        fixture_id,
        selected,
    )
    if blocked is not None:
        return blocked
    temporal = _pre_cutoff(selected)
    distinct_captures = {
        item.receipt.physical_capture_id for item in temporal
    }
    if len(distinct_captures) < minimum_captures:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_PLAYER_GATE,
            fixture_id=fixture_id,
            status=GateStatus.BLOCKED_BY_COVERAGE,
            observations=len(distinct_captures),
            reason="THREE_PRIOR_CAPTURES_REQUIRED",
            evidence={
                "minimum_captures": minimum_captures,
                **_receipt_evidence(temporal),
            },
        )
    if any(not bool(item.projection.get("players")) for item in temporal):
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_PLAYER_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="PLAYER_LIST_MISSING",
            evidence=_receipt_evidence(temporal),
        )
    return GateEvaluation(
        gate=GateName.PROSPECTIVE_PLAYER_GATE,
        fixture_id=fixture_id,
        status=GateStatus.PASSED,
        observations=len(distinct_captures),
        reason="PLAYER_CAPTURE_POLICY_SATISFIED",
        evidence={
            "distinct_captures": len(distinct_captures),
            **_receipt_evidence(temporal),
        },
    )


def evaluate_injury_gate(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
) -> GateEvaluation:
    selected = _family(observations, CaptureFamily.INJURY)
    blocked = _blocked(
        GateName.PROSPECTIVE_INJURY_GATE,
        fixture_id,
        selected,
    )
    if blocked is not None:
        return blocked
    temporal = _pre_cutoff(selected)
    if temporal and all(
        item.receipt.quality_status is AvailabilityStatus.CAPTURED_EMPTY
        for item in temporal
    ):
        observations_count = _independent_capture_count(temporal)
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_INJURY_GATE,
            fixture_id=fixture_id,
            status=GateStatus.PASSED,
            observations=observations_count,
            reason="NO_INJURY_REPORTED_AT_CAPTURE",
            evidence={
                "empty_captures": observations_count,
                "meaning": "NO_PROVIDER_REPORTED_INJURY_AT_CAPTURE_TIME",
                **_receipt_evidence(temporal),
            },
        )
    valid = tuple(
        item
        for item in temporal
        if item.projection.get("player_id")
        and item.projection.get("status")
        and item.receipt.source_endpoint
    )
    if not valid:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_INJURY_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="INJURY_PLAYER_STATUS_OR_SOURCE_MISSING",
            evidence=_receipt_evidence(temporal),
        )
    return GateEvaluation(
        gate=GateName.PROSPECTIVE_INJURY_GATE,
        fixture_id=fixture_id,
        status=GateStatus.PASSED,
        observations=_independent_capture_count(valid),
        reason="INJURY_OBSERVED_BEFORE_CUTOFF",
        evidence={
            "identified_injuries": len(valid),
            **_receipt_evidence(tuple(valid)),
        },
    )


def evaluate_lineup_gate(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
) -> GateEvaluation:
    selected = _family(observations, CaptureFamily.LINEUP)
    blocked = _blocked(
        GateName.PROSPECTIVE_LINEUP_GATE,
        fixture_id,
        selected,
    )
    if blocked is not None:
        return blocked
    temporal = _pre_cutoff(selected)
    latest = _latest_receipt_observations(temporal)
    if latest is None:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_LINEUP_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="CONFLICTING_EQUAL_TIME_RECEIPTS",
            evidence=_receipt_evidence(temporal),
        )
    latest_receipt = latest[0].receipt
    teams: dict[str, list[object]] = {}
    for item in latest:
        team_id = str(item.projection.get("team_id", "")).strip()
        starters = item.projection.get("starters")
        if team_id and isinstance(starters, list) and team_id not in teams:
            teams[team_id] = starters
    valid_teams = {
        team_id
        for team_id, starters in teams.items()
        if len(starters) == 11
        and len({str(player) for player in starters}) == 11
        and all(str(player) for player in starters)
    }
    if not latest_receipt.complete or len(valid_teams) != 2:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_LINEUP_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="EXACTLY_TWO_COMPLETE_ELEVEN_PLAYER_LINEUPS_REQUIRED",
            evidence={
                "complete_teams": len(valid_teams),
                "expected_teams": 2,
                **_receipt_evidence(latest),
            },
        )
    return GateEvaluation(
        gate=GateName.PROSPECTIVE_LINEUP_GATE,
        fixture_id=fixture_id,
        status=GateStatus.PASSED,
        observations=_independent_capture_count(temporal),
        reason="BOTH_COMPLETE_LINEUPS_RECEIVED_BEFORE_KICKOFF",
        evidence={
            "teams": 2,
            "starter_count_per_team": 11,
            **_receipt_evidence(latest),
        },
    )


def evaluate_formation_gate(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
    lineup_gate: GateEvaluation,
) -> GateEvaluation:
    if lineup_gate.status is not GateStatus.PASSED:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_FORMATION_GATE,
            fixture_id=fixture_id,
            status=lineup_gate.status,
            observations=0,
            reason="LINEUP_GATE_REQUIRED",
            evidence={"lineup_gate": lineup_gate.status.value},
        )
    selected = _family(observations, CaptureFamily.FORMATION)
    blocked = _blocked(
        GateName.PROSPECTIVE_FORMATION_GATE,
        fixture_id,
        selected,
        require_identity=False,
    )
    if blocked is not None:
        return blocked
    temporal = _pre_cutoff(selected)
    latest = _latest_receipt_observations(temporal)
    if latest is None:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_FORMATION_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="CONFLICTING_EQUAL_TIME_RECEIPTS",
            evidence=_receipt_evidence(temporal),
        )
    latest_receipt = latest[0].receipt
    valid: dict[str, str] = {}
    for item in latest:
        team_id = str(item.projection.get("team_id", "")).strip()
        formation = str(item.projection.get("formation", "")).strip()
        try:
            lines = tuple(int(value) for value in formation.split("-"))
        except ValueError:
            continue
        if (
            team_id
            and team_id not in valid
            and 3 <= len(lines) <= 5
            and all(value > 0 for value in lines)
            and sum(lines) == 10
        ):
            valid[team_id] = formation
    if not latest_receipt.complete or len(valid) != 2:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_FORMATION_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="BOTH_TEAM_FORMATIONS_NOT_NORMALIZABLE",
            evidence={
                "complete_teams": len(valid),
                "expected_teams": 2,
                **_receipt_evidence(latest),
            },
        )
    return GateEvaluation(
        gate=GateName.PROSPECTIVE_FORMATION_GATE,
        fixture_id=fixture_id,
        status=GateStatus.PASSED,
        observations=_independent_capture_count(temporal),
        reason="BOTH_FORMATIONS_NORMALIZED_AFTER_LINEUP_GATE",
        evidence={
            "formations": dict(sorted(valid.items())),
            **_receipt_evidence(latest),
        },
    )


def evaluate_market_gate(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
) -> GateEvaluation:
    selected = _family(observations, CaptureFamily.ODDS)
    blocked = _blocked(
        GateName.PROSPECTIVE_MARKET_GATE,
        fixture_id,
        selected,
        require_identity=False,
    )
    if blocked is not None:
        return blocked
    temporal = _pre_cutoff(selected)
    valid: list[GateObservation] = []
    for item in temporal:
        odds = item.projection.get("odds")
        margin = item.projection.get("margin")
        raw_observed_at = item.projection.get("observed_at")
        try:
            projected_observed_at = datetime.fromisoformat(str(raw_observed_at))
        except ValueError:
            projected_observed_at = None
        if (
            item.projection.get("bookmaker")
            and item.projection.get("market") in {"1X2", "OVER_UNDER_2_5"}
            and item.projection.get("selection")
            and isinstance(odds, (int, float))
            and float(odds) > 1.0
            and isinstance(margin, (int, float))
            and float(margin) >= 0.0
            and projected_observed_at is not None
            and projected_observed_at.tzinfo is not None
            and projected_observed_at == item.receipt.observed_at
        ):
            valid.append(item)
    if not valid:
        return GateEvaluation(
            gate=GateName.PROSPECTIVE_MARKET_GATE,
            fixture_id=fixture_id,
            status=GateStatus.INVALID_PAYLOAD,
            observations=_independent_capture_count(temporal),
            reason="EXACT_ODDS_BOOKMAKER_MARGIN_OR_OBSERVED_AT_MISSING",
            evidence=_receipt_evidence(temporal),
        )
    return GateEvaluation(
        gate=GateName.PROSPECTIVE_MARKET_GATE,
        fixture_id=fixture_id,
        status=GateStatus.PASSED,
        observations=_independent_capture_count(tuple(valid)),
        reason="MARKET_SNAPSHOT_MATCHED_WITHOUT_AMBIGUITY",
        evidence={
            "snapshots": len(valid),
            **_receipt_evidence(tuple(valid)),
        },
    )


def evaluate_fixture_gates(
    fixture_id: str,
    observations: tuple[GateObservation, ...],
) -> tuple[GateEvaluation, ...]:
    scoped = tuple(
        item for item in observations if fixture_matches(item, fixture_id=fixture_id)
    )
    player = evaluate_player_gate(fixture_id, scoped)
    injury = evaluate_injury_gate(fixture_id, scoped)
    lineup = evaluate_lineup_gate(fixture_id, scoped)
    formation = evaluate_formation_gate(fixture_id, scoped, lineup)
    market = evaluate_market_gate(fixture_id, scoped)
    return (player, injury, lineup, formation, market)


def aggregate_gate_evaluations(
    evaluations: tuple[GateEvaluation, ...],
) -> tuple[AggregateGateEvaluation, ...]:
    output: list[AggregateGateEvaluation] = []
    for gate in GateName:
        scoped = tuple(item for item in evaluations if item.gate is gate)
        counts = Counter(item.status.value for item in scoped)
        passed = counts[GateStatus.PASSED.value]
        fixtures = len(scoped)
        coverage = passed / fixtures if fixtures else 0.0
        aggregate_status = (
            GateStatus.PASSED
            if fixtures > 0 and passed == fixtures
            else GateStatus.BLOCKED_BY_COVERAGE
        )
        output.append(
            AggregateGateEvaluation(
                gate=gate,
                fixtures=fixtures,
                passed=passed,
                status_counts=dict(sorted(counts.items())),
                coverage=coverage,
                status=aggregate_status,
            )
        )
    return tuple(output)
