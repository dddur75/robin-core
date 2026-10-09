"""Owner-anchored H11 hypotheses frozen before deep results are inspected."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from robin.deep_football.contracts import (
    DataGateStatus,
    HypothesisContract,
    PatternStatus,
)


def owner_hypotheses() -> tuple[HypothesisContract, ...]:
    return (
        HypothesisContract(
            hypothesis_id="H11-001",
            title="Buteur en forme contre défense centrale amputée",
            mechanism="Une forme offensive antérieure interagit avec deux absences centrales prouvées.",
            expected_direction="POSITIVE_ATTACKING_RESIDUAL",
            markets=["1X2_TEAM", "TEAM_GOALS", "OVER_2_5", "BTTS_IF_PRICED"],
            cutoff="PRE_LINEUP_OR_POST_LINEUP_EXPLICIT",
            required_gates=[
                "PLAYER_FORM_GATE",
                "ABSENCE_GATE",
                "STARTER_BASELINE_GATE",
            ],
            minimum_support=80,
            statistical_family="interactions",
            negative_control="SHIFTED_ABSENCE",
            rejection_criterion="ANY_GATE_FAILS_OR_GLOBAL_Q_GT_0_05",
        ),
        HypothesisContract(
            hypothesis_id="H11-002",
            title="4-3-3 contre 4-4-2",
            mechanism="Association résiduelle ajustée entre deux structures tactiques.",
            expected_direction="PREREGISTERED_TWO_SIDED",
            markets=["1X2", "OVER_2_5"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "FORMATION_GATE"],
            minimum_support=120,
            statistical_family="formations",
            negative_control="FORMATION_SHIFTED_ONE_MATCH",
            rejection_criterion="UNSTABLE_OR_CONFOUNDED_OR_GLOBAL_Q_GT_0_05",
        ),
        HypothesisContract(
            hypothesis_id="H11-003",
            title="Trois attaquants droitiers contre défense gauchère",
            mechanism="Asymétrie de pied observée dans les unités titulaires.",
            expected_direction="PREREGISTERED_TWO_SIDED",
            markets=["1X2", "TEAM_GOALS"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "FOOTEDNESS_GATE"],
            minimum_support=100,
            statistical_family="footedness",
            negative_control="FALSE_FOOTEDNESS",
            rejection_criterion="ANY_INFERRED_FOOT_OR_INSUFFICIENT_SUPPORT",
        ),
        HypothesisContract(
            hypothesis_id="H11-004",
            title="Gardien titulaire absent",
            mechanism="Perte point-in-time du gardien habituel avant le match.",
            expected_direction="MORE_GOALS_CONCEDED",
            markets=["1X2", "OVER_2_5", "BTTS_IF_PRICED"],
            cutoff="PRE_LINEUP_OR_POST_LINEUP_EXPLICIT",
            required_gates=["ABSENCE_GATE", "STARTER_BASELINE_GATE"],
            minimum_support=80,
            statistical_family="absences",
            negative_control="SHIFTED_GOALKEEPER_ABSENCE",
            rejection_criterion="TEMPORALITY_FAILS_OR_GLOBAL_Q_GT_0_05",
        ),
        HypothesisContract(
            hypothesis_id="H11-005",
            title="Deux centraux nouveaux ensemble",
            mechanism="Faible continuité du duo central face à la force adverse.",
            expected_direction="MORE_GOALS_CONCEDED",
            markets=["1X2", "OVER_2_5"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "STARTER_BASELINE_GATE"],
            minimum_support=100,
            statistical_family="lineup",
            negative_control="FALSE_CENTRE_BACK_PAIR",
            rejection_criterion="LINEUP_GATE_FAILS_OR_CONCENTRATED",
        ),
        HypothesisContract(
            hypothesis_id="H11-006",
            title="Rupture du onze",
            mechanism="Interaction entre changements, importance, repos et marché.",
            expected_direction="NEGATIVE_TEAM_RESIDUAL",
            markets=["1X2", "TEAM_GOALS"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "ABSENCE_GATE"],
            minimum_support=120,
            statistical_family="lineup",
            negative_control="RANDOM_LINEUP",
            rejection_criterion="NO_INCREMENT_VERSUS_MARKET",
        ),
        HypothesisContract(
            hypothesis_id="H11-007",
            title="Congestion et tactique inhabituelle",
            mechanism="Congestion forte combinée à un changement tactique antérieur rare.",
            expected_direction="NEGATIVE_TEAM_RESIDUAL",
            markets=["1X2", "TEAM_GOALS"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "FORMATION_GATE"],
            minimum_support=100,
            statistical_family="interactions",
            negative_control="RANDOM_TACTICAL_INTERACTION",
            rejection_criterion="NO_STABLE_RESIDUAL_EFFECT",
        ),
        HypothesisContract(
            hypothesis_id="H11-008",
            title="Matchup structurel",
            mechanism="Front three/back three et front two/back four ajustés au marché.",
            expected_direction="PREREGISTERED_TWO_SIDED",
            markets=["1X2", "OVER_2_5"],
            cutoff="POST_LINEUP_ONLY",
            required_gates=["LINEUP_GATE", "FORMATION_GATE"],
            minimum_support=120,
            statistical_family="matchups",
            negative_control="RANDOM_TACTICAL_INTERACTION",
            rejection_criterion="NO_STABLE_ADJUSTED_ASSOCIATION",
        ),
    )


@dataclass(frozen=True, slots=True)
class HypothesisEligibility:
    hypothesis_id: str
    eligible: bool
    status: PatternStatus
    blocking_gates: tuple[str, ...]


def evaluate_hypothesis_eligibility(
    hypothesis: HypothesisContract,
    gate_statuses: Mapping[str, DataGateStatus | str],
) -> HypothesisEligibility:
    blocked = tuple(
        gate
        for gate in hypothesis.required_gates
        if str(gate_statuses.get(gate, "")) != DataGateStatus.READY.value
    )
    return HypothesisEligibility(
        hypothesis_id=hypothesis.hypothesis_id,
        eligible=not blocked,
        status=(
            PatternStatus.DISCOVERED
            if not blocked
            else PatternStatus.DATA_GATE_BLOCKED
        ),
        blocking_gates=blocked,
    )
