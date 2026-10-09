"""Explicit and versioned removal of bookmaker margin.

This module deliberately has no default method.  Repository-wide authority is
conflicting, so every caller must name the protocol it is executing.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum


class DevigMethod(StrEnum):
    """Mathematical methods supported for explicit execution and replay."""

    PROPORTIONAL = "PROPORTIONAL"
    SHIN = "SHIN"


class DevigInputError(ValueError):
    """A deterministic, fail-closed market-input error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DevigMethodError(ValueError):
    """An unknown or missing de-vig protocol identifier."""


_METHOD_SPECS: dict[DevigMethod, dict[str, object]] = {
    DevigMethod.PROPORTIONAL: {
        "method": "PROPORTIONAL",
        "version": "PROPORTIONAL_COMPLETE_MARKET_V1",
        "formula": "q_i=1/odds_i;p_i=q_i/sum(q)",
        "market_contract": "complete-labelled-decimal-odds-v1",
        "invalid_policy": "raise-devig-input-error-v1",
        "overround_policy": "report-without-performance-selection-v1",
    },
    DevigMethod.SHIN: {
        "method": "SHIN",
        "version": "LEGACY_SHIN_VAGUE1_V1",
        "formula": "legacy-shin-fixed-point-z",
        "max_iterations": 100,
        "convergence_tolerance": 1e-12,
        "z_bounds_inclusive": [0.0, 0.99],
        "non_convergence_policy": "use-last-bounded-iterate",
        "probability_bounds_inclusive": [1e-9, 1.0],
        "final_policy": "proportional-renormalization",
        "market_contract": "complete-labelled-decimal-odds-v1",
        "invalid_policy": "raise-devig-input-error-v1",
        "two_outcome_policy": "proportional-equivalent-with-explicit-reason-v1",
        "underround_policy": "proportional-fallback-with-explicit-reason-v1",
    },
}


def _definition_hash(method: DevigMethod) -> str:
    payload = json.dumps(
        _METHOD_SPECS[method],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class DevigResult:
    """Complete, replayable output from one named de-vig protocol."""

    method: DevigMethod
    effective_method: DevigMethod
    fallback_reason: str | None
    version: str
    definition_hash: str
    outcome_labels: tuple[str, ...]
    input_odds: tuple[float, ...]
    implied_probabilities: tuple[float, ...]
    fair_probabilities: tuple[float, ...]
    overround: float
    validation_status: str = "VALID"

    def as_dict(self) -> dict[str, object]:
        return {
            "method": self.method.value,
            "effective_method": self.effective_method.value,
            "fallback_reason": self.fallback_reason,
            "version": self.version,
            "definition_hash": self.definition_hash,
            "outcome_labels": list(self.outcome_labels),
            "input_odds": list(self.input_odds),
            "implied_probabilities": list(self.implied_probabilities),
            "fair_probabilities": list(self.fair_probabilities),
            "overround": self.overround,
            "validation_status": self.validation_status,
        }


def method_version(method: DevigMethod | str) -> str:
    """Return the frozen version for an explicitly named method."""

    normalized = _normalize_method(method)
    return str(_METHOD_SPECS[normalized]["version"])


def method_definition_hash(method: DevigMethod | str) -> str:
    """Return the frozen definition hash for an explicitly named method."""

    return _definition_hash(_normalize_method(method))


def normalize_method(method: DevigMethod | str) -> DevigMethod:
    """Validate and normalize a public method identifier without fallback."""

    return _normalize_method(method)


def _normalize_method(method: DevigMethod | str) -> DevigMethod:
    if isinstance(method, DevigMethod):
        return method
    if not isinstance(method, str) or not method.strip():
        raise DevigMethodError("DEVIG_METHOD_REQUIRED")
    try:
        return DevigMethod(method.strip().upper())
    except ValueError as error:
        raise DevigMethodError(f"DEVIG_METHOD_UNKNOWN:{method}") from error


def _validated_market(
    odds: Iterable[float | None],
    outcome_labels: Sequence[str] | None,
) -> tuple[tuple[float, ...], tuple[str, ...]]:
    if isinstance(odds, (str, bytes)):
        raise DevigInputError("DEVIG_MARKET_TYPE_INVALID")
    try:
        raw = tuple(odds)
    except TypeError as error:
        raise DevigInputError("DEVIG_MARKET_NOT_ITERABLE") from error
    if not raw:
        raise DevigInputError("DEVIG_MARKET_EMPTY")
    if len(raw) < 2:
        raise DevigInputError("DEVIG_MARKET_ONE_OUTCOME")

    values: list[float] = []
    for value in raw:
        if value is None:
            raise DevigInputError("DEVIG_ODDS_MISSING")
        try:
            number = float(value)
        except (TypeError, ValueError) as error:
            raise DevigInputError("DEVIG_ODDS_NOT_NUMERIC") from error
        if not math.isfinite(number):
            raise DevigInputError("DEVIG_ODDS_NOT_FINITE")
        if number <= 1.0:
            raise DevigInputError("DEVIG_ODDS_MUST_EXCEED_ONE")
        values.append(number)

    if outcome_labels is None:
        labels = tuple(f"OUTCOME_{index}" for index in range(len(values)))
    else:
        labels = tuple(str(label).strip() for label in outcome_labels)
        if len(labels) != len(values):
            raise DevigInputError("DEVIG_OUTCOME_COUNT_MISMATCH")
        if any(not label for label in labels):
            raise DevigInputError("DEVIG_OUTCOME_LABEL_MISSING")
        if len(set(labels)) != len(labels):
            raise DevigInputError("DEVIG_OUTCOME_LABEL_DUPLICATE")
    return tuple(values), labels


def _proportional(implied: tuple[float, ...]) -> tuple[float, ...]:
    total = math.fsum(implied)
    if not math.isfinite(total) or total <= 0.0:
        raise DevigInputError("DEVIG_IMPLIED_TOTAL_INVALID")
    return tuple(value / total for value in implied)


def _shin(
    implied: tuple[float, ...],
) -> tuple[tuple[float, ...], DevigMethod, str | None]:
    total = math.fsum(implied)
    if total <= 1.0:
        return (
            _proportional(implied),
            DevigMethod.PROPORTIONAL,
            "SHIN_UNDERROUND_PROPORTIONAL_FALLBACK",
        )
    if len(implied) == 2:
        return (
            _proportional(implied),
            DevigMethod.PROPORTIONAL,
            "SHIN_TWO_OUTCOME_PROPORTIONAL_EQUIVALENCE",
        )

    z = 0.0
    for _ in range(100):
        roots = tuple(
            math.sqrt(z**2 + 4.0 * (1.0 - z) * value**2 / total)
            for value in implied
        )
        z_next = (math.fsum(roots) - 2.0) / (len(implied) - 2.0)
        if abs(z_next - z) < 1e-12:
            z = z_next
            break
        z = max(0.0, min(0.99, z_next))

    z = max(0.0, min(0.99, z))
    roots = tuple(
        math.sqrt(z**2 + 4.0 * (1.0 - z) * value**2 / total)
        for value in implied
    )
    probabilities = tuple(
        min(1.0, max(1e-9, (root - z) / (2.0 * (1.0 - z))))
        for root in roots
    )
    return _proportional(probabilities), DevigMethod.SHIN, None


def devig_probabilities(
    odds: Iterable[float | None],
    *,
    method: DevigMethod | str,
    outcome_labels: Sequence[str] | None = None,
) -> DevigResult:
    """Remove margin using one explicitly named method.

    Complete decimal-odds markets with at least two uniquely labelled outcomes
    are required.  Underrounds and extreme overrounds are reported, not used to
    select a protocol.  Invalid inputs always raise :class:`DevigInputError`.
    """

    normalized_method = _normalize_method(method)
    values, labels = _validated_market(odds, outcome_labels)
    implied = tuple(1.0 / value for value in values)
    total = math.fsum(implied)
    if normalized_method is DevigMethod.PROPORTIONAL:
        fair = _proportional(implied)
        effective_method = DevigMethod.PROPORTIONAL
        fallback_reason = None
    else:
        fair, effective_method, fallback_reason = _shin(implied)
    if any(not math.isfinite(value) or value < 0.0 for value in fair):
        raise ArithmeticError("DEVIG_FAIR_PROBABILITIES_INVALID")
    fair_total = math.fsum(fair)
    if not math.isclose(fair_total, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise ArithmeticError("DEVIG_FAIR_PROBABILITIES_NOT_NORMALIZED")
    return DevigResult(
        method=normalized_method,
        effective_method=effective_method,
        fallback_reason=fallback_reason,
        version=method_version(normalized_method),
        definition_hash=_definition_hash(normalized_method),
        outcome_labels=labels,
        input_odds=values,
        implied_probabilities=implied,
        fair_probabilities=fair,
        overround=total - 1.0,
    )
