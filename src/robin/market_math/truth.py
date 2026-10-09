"""Versioned decision, staking, settlement, and performance truth functions."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from robin.market_math.devig import (
    DevigMethod,
    DevigResult,
    devig_probabilities,
    method_definition_hash,
    method_version,
    normalize_method,
)

SCIENTIFIC_KERNEL_VERSION = "ROBIN_SCIENTIFIC_TRUTH_KERNEL_V1"
ROI_DEFINITION_VERSION = "profit_over_actual_turnover_v1"
TURNOVER_DEFINITION_VERSION = "sum_of_accepted_stakes_v1"
YIELD_DEFINITION_VERSION = "profit_over_turnover_v1"
PROFIT_PER_BET_DEFINITION_VERSION = "profit_over_bet_count_v1"
DECISION_THRESHOLD_VERSION = "maximum_edge_gte_threshold_v1"
STAKING_VERSION = "fixed_proportional_fractional_kelly_v1"
SETTLEMENT_VERSION = "decimal_odds_net_profit_v1"


@dataclass(frozen=True, slots=True)
class MarketDecision:
    devig: DevigResult
    model_probabilities: tuple[float, ...]
    edges: tuple[float, ...]
    threshold: float
    minimum_probability: float
    selected_index: int
    selected_outcome: str
    accepted: bool

    @property
    def selected_edge(self) -> float:
        return self.edges[self.selected_index]


def _probabilities(values: Iterable[float]) -> tuple[float, ...]:
    try:
        probabilities = tuple(float(value) for value in values)
    except (TypeError, ValueError) as error:
        raise ValueError("MODEL_PROBABILITIES_INVALID") from error
    if not probabilities or any(
        not math.isfinite(value) or value < 0.0 or value > 1.0
        for value in probabilities
    ):
        raise ValueError("MODEL_PROBABILITIES_INVALID")
    if not math.isclose(math.fsum(probabilities), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("MODEL_PROBABILITIES_NOT_NORMALIZED")
    return probabilities


def decide_market(
    odds: Iterable[float | None],
    model_probabilities: Iterable[float],
    *,
    method: DevigMethod | str,
    threshold: float,
    minimum_probability: float = 0.0,
    outcome_labels: Sequence[str] | None = None,
) -> MarketDecision:
    """Evaluate one complete market under an explicit de-vig protocol."""

    if (
        not math.isfinite(threshold)
        or not math.isfinite(minimum_probability)
        or threshold < 0.0
        or threshold > 1.0
        or minimum_probability < 0.0
        or minimum_probability > 1.0
    ):
        raise ValueError("DECISION_THRESHOLD_INVALID")
    probabilities = _probabilities(model_probabilities)
    devig = devig_probabilities(
        odds,
        method=method,
        outcome_labels=outcome_labels,
    )
    if len(probabilities) != len(devig.fair_probabilities):
        raise ValueError("MODEL_MARKET_OUTCOME_COUNT_MISMATCH")
    edges = tuple(
        model - market
        for model, market in zip(
            probabilities,
            devig.fair_probabilities,
            strict=True,
        )
    )
    selection = max(range(len(edges)), key=edges.__getitem__)
    accepted = (
        edges[selection] >= threshold
        and probabilities[selection] >= minimum_probability
    )
    return MarketDecision(
        devig=devig,
        model_probabilities=probabilities,
        edges=edges,
        threshold=threshold,
        minimum_probability=minimum_probability,
        selected_index=selection,
        selected_outcome=devig.outcome_labels[selection],
        accepted=accepted,
    )


def stake_units(
    *,
    probability: float,
    odds: float,
    bankroll_units: float,
    staking: str,
    kelly_fraction: float,
    stake_cap_units: float,
) -> float:
    """Calculate an accepted stake without presentation rounding."""

    if any(
        not math.isfinite(value)
        for value in (
            probability,
            odds,
            bankroll_units,
            kelly_fraction,
            stake_cap_units,
        )
    ):
        raise ValueError("STAKING_INPUT_NOT_FINITE")
    if (
        probability < 0.0
        or probability > 1.0
        or odds <= 1.0
        or bankroll_units < 0.0
        or stake_cap_units < 0.0
        or kelly_fraction < 0.0
        or kelly_fraction > 1.0
    ):
        raise ValueError("STAKING_INPUT_INVALID")
    if staking == "FIXED":
        calculated = 1.0
    elif staking == "PROPORTIONAL":
        calculated = bankroll_units * 0.01
    elif staking == "FRACTIONAL_KELLY":
        net = odds - 1.0
        kelly = max((probability * odds - 1.0) / net, 0.0)
        calculated = bankroll_units * kelly * kelly_fraction
    else:
        raise ValueError(f"STAKING_METHOD_UNKNOWN:{staking}")
    return min(calculated, stake_cap_units, bankroll_units)


def settle_profit(*, stake_units: float, odds: float, won: bool) -> float:
    """Settle one decimal-odds bet as net profit in stake units."""

    if not isinstance(won, bool):
        raise TypeError("SETTLEMENT_WON_BOOLEAN_REQUIRED")
    if (
        not math.isfinite(stake_units)
        or not math.isfinite(odds)
        or stake_units < 0.0
        or odds <= 1.0
    ):
        raise ValueError("SETTLEMENT_INPUT_INVALID")
    return stake_units * (odds - 1.0) if won else -stake_units


def performance_summary(
    *,
    starting_bankroll_units: float,
    stakes: Iterable[float],
    profits: Iterable[float],
) -> dict[str, float | int | None | str]:
    """Summarize actual stakes and profits under unambiguous definitions."""

    stake_values = tuple(float(value) for value in stakes)
    profit_values = tuple(float(value) for value in profits)
    if len(stake_values) != len(profit_values):
        raise ValueError("PERFORMANCE_STAKE_PROFIT_COUNT_MISMATCH")
    if (
        not math.isfinite(starting_bankroll_units)
        or starting_bankroll_units < 0.0
        or any(not math.isfinite(value) or value <= 0.0 for value in stake_values)
        or any(not math.isfinite(value) for value in profit_values)
    ):
        raise ValueError("PERFORMANCE_INPUT_INVALID")
    bankroll = starting_bankroll_units
    for stake, item_profit in zip(stake_values, profit_values, strict=True):
        if stake > bankroll or item_profit < -stake:
            raise ValueError("PERFORMANCE_BANKROLL_OR_SETTLEMENT_INVALID")
        bankroll += item_profit
        if bankroll < -1e-12:
            raise ValueError("PERFORMANCE_BANKROLL_OR_SETTLEMENT_INVALID")
    turnover = math.fsum(stake_values)
    profit = math.fsum(profit_values)
    bets = len(profit_values)
    roi = profit / turnover if turnover > 0.0 else None
    profit_per_bet = profit / bets if bets > 0 else None
    return {
        "starting_bankroll_units": starting_bankroll_units,
        "ending_bankroll_units": bankroll,
        "bets": bets,
        "profit_units": profit,
        "turnover_units": turnover,
        "roi": roi,
        "yield": roi,
        "profit_per_bet": profit_per_bet,
        "roi_definition_version": ROI_DEFINITION_VERSION,
        "turnover_definition_version": TURNOVER_DEFINITION_VERSION,
        "yield_definition_version": YIELD_DEFINITION_VERSION,
        "profit_per_bet_definition_version": PROFIT_PER_BET_DEFINITION_VERSION,
    }


def kernel_versions(devig: DevigResult | DevigMethod | str) -> dict[str, str]:
    """Return the mandatory scientific lineage carried by new results."""

    if isinstance(devig, DevigResult):
        method = devig.method
        version = devig.version
        definition_hash = devig.definition_hash
    else:
        method = normalize_method(devig)
        version = method_version(method)
        definition_hash = method_definition_hash(method)
    return {
        "scientific_kernel_version": SCIENTIFIC_KERNEL_VERSION,
        "devig_method": method.value,
        "devig_version": version,
        "devig_definition_hash": definition_hash,
        "roi_definition_version": ROI_DEFINITION_VERSION,
        "turnover_definition_version": TURNOVER_DEFINITION_VERSION,
        "yield_definition_version": YIELD_DEFINITION_VERSION,
        "decision_threshold_version": DECISION_THRESHOLD_VERSION,
        "staking_version": STAKING_VERSION,
        "settlement_version": SETTLEMENT_VERSION,
    }


def devig_execution_metadata(devig: DevigResult) -> dict[str, str | None]:
    """Describe the method actually executed for this market instance."""

    return {
        "devig_effective_method": devig.effective_method.value,
        "devig_fallback_reason": devig.fallback_reason,
    }
