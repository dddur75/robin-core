"""Frozen H11 protocols carried forward without tuning or premature testing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from robin.deep_football.matchups import owner_hypotheses
from robin.prospective_observatory.contracts import ProspectiveHypothesisStatus


@dataclass(frozen=True, slots=True)
class FrozenProspectiveProtocol:
    hypothesis_id: str
    title: str
    preregistration_hash: str
    required_gates: tuple[str, ...]
    required_windows: tuple[str, ...]
    minimum_observations: int
    frozen_before_capture: bool


@dataclass(frozen=True, slots=True)
class HypothesisProgress:
    hypothesis_id: str
    status: ProspectiveHypothesisStatus
    observations: int
    minimum_observations: int
    fixtures_tracked: int
    first_potentially_eligible_match: datetime | None
    preregistration_hash: str
    conclusion_allowed: bool = False


def _required_windows(required_gates: list[str]) -> tuple[str, ...]:
    windows: set[str] = set()
    for gate in required_gates:
        normalized = gate.upper()
        if "LINEUP" in normalized or "FORMATION" in normalized:
            windows.update({"H-2", "NEAR_KICKOFF"})
        elif "PLAYER" in normalized or "ABSENCE" in normalized or "INJURY" in normalized:
            windows.update(
                {"J-7", "J-3", "J-1", "H-6", "H-2", "NEAR_KICKOFF"}
            )
        elif "MARKET" in normalized:
            windows.update(
                {"J-7", "J-3", "J-1", "H-6", "H-2", "NEAR_KICKOFF"}
            )
    return tuple(sorted(windows))


def frozen_h11_protocols() -> tuple[FrozenProspectiveProtocol, ...]:
    protocols = tuple(
        FrozenProspectiveProtocol(
            hypothesis_id=contract.hypothesis_id,
            title=contract.title,
            preregistration_hash=contract.preregistration_hash,
            required_gates=tuple(contract.required_gates),
            required_windows=_required_windows(contract.required_gates),
            minimum_observations=contract.minimum_support,
            frozen_before_capture=contract.frozen_before_results,
        )
        for contract in owner_hypotheses()
    )
    if tuple(item.hypothesis_id for item in protocols) != tuple(
        f"H11-{index:03d}" for index in range(1, 9)
    ):
        raise ValueError("H11_FROZEN_PROTOCOL_SET_CHANGED")
    if any(not item.frozen_before_capture for item in protocols):
        raise ValueError("H11_PROTOCOL_NOT_FROZEN")
    return protocols


def hypothesis_progress(
    protocol: FrozenProspectiveProtocol,
    *,
    fixtures_tracked: int,
    observations: int,
    first_potentially_eligible_match: datetime | None,
) -> HypothesisProgress:
    if fixtures_tracked < 0 or observations < 0:
        raise ValueError("H11_PROSPECTIVE_COUNTS_MUST_BE_NON_NEGATIVE")
    if observations == 0 and fixtures_tracked == 0:
        status = ProspectiveHypothesisStatus.WAITING_FOR_OBSERVATIONS
    elif observations == 0:
        status = ProspectiveHypothesisStatus.DATA_CAPTURE_ACTIVE
    elif observations < protocol.minimum_observations:
        status = ProspectiveHypothesisStatus.MINIMUM_SAMPLE_NOT_REACHED
    else:
        status = ProspectiveHypothesisStatus.ELIGIBLE_FOR_EXPLORATORY_ANALYSIS
    return HypothesisProgress(
        hypothesis_id=protocol.hypothesis_id,
        status=status,
        observations=observations,
        minimum_observations=protocol.minimum_observations,
        fixtures_tracked=fixtures_tracked,
        first_potentially_eligible_match=first_potentially_eligible_match,
        preregistration_hash=protocol.preregistration_hash,
        conclusion_allowed=(
            status is ProspectiveHypothesisStatus.ELIGIBLE_FOR_EXPLORATORY_ANALYSIS
        ),
    )
