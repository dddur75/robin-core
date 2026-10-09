"""Versioned and fail-closed scientific contracts for Jalon 11."""

from __future__ import annotations

import hashlib
import json
import math
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCIENTIFIC_FLOAT_SIGNIFICANT_DIGITS = 15
SCIENTIFIC_FLOAT_CONTRACT_VERSION = "j11-scientific-float15-v1"


class DataGateStatus(StrEnum):
    READY = "READY"
    PARTIAL = "PARTIAL"
    BLOCKED_BY_COVERAGE = "BLOCKED_BY_COVERAGE"
    BLOCKED_BY_TEMPORALITY = "BLOCKED_BY_TEMPORALITY"
    BLOCKED_BY_IDENTITY = "BLOCKED_BY_IDENTITY"
    MARKET_UNAVAILABLE = "MARKET_UNAVAILABLE"


class ResearchMode(StrEnum):
    PRE_LINEUP = "PRE_LINEUP"
    POST_LINEUP = "POST_LINEUP"


class PatternStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    DATA_GATE_BLOCKED = "DATA_GATE_BLOCKED"
    LEAKAGE_REJECTED = "LEAKAGE_REJECTED"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    UNSTABLE = "UNSTABLE"
    CONCENTRATED = "CONCENTRATED"
    DOMINATED = "DOMINATED"
    MULTIPLE_TESTING_REJECTED = "MULTIPLE_TESTING_REJECTED"
    MARKET_UNAVAILABLE = "MARKET_UNAVAILABLE"
    EXPOSED_HISTORICAL_SURVIVOR = "EXPOSED_HISTORICAL_SURVIVOR"
    CROSS_LEAGUE_SURVIVOR = "CROSS_LEAGUE_SURVIVOR"
    PROSPECTIVE_WATCHLIST = "PROSPECTIVE_WATCHLIST"
    LIVE_SHADOW_CANDIDATE = "LIVE_SHADOW_CANDIDATE"
    LIVE_SHADOW = "LIVE_SHADOW"
    REJECTED = "REJECTED"


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_scientific_evidence(value: object) -> object:
    """Make insignificant binary-float noise stable before evidence hashing.

    Fifteen significant decimal digits with Python's round-half-even formatting
    retain the meaningful precision of an IEEE-754 double while removing
    last-bit differences caused by otherwise equivalent BLAS/reduction paths on
    separate runners.  Booleans and integers deliberately remain untouched,
    and non-finite or non-JSON evidence is rejected.
    """

    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("SCIENTIFIC_EVIDENCE_REQUIRES_FINITE_FLOATS")
        normalized = float(f"{value:.{SCIENTIFIC_FLOAT_SIGNIFICANT_DIGITS}g}")
        return 0.0 if normalized == 0.0 else normalized
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("SCIENTIFIC_EVIDENCE_REQUIRES_STRING_KEYS")
        return {key: normalize_scientific_evidence(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_scientific_evidence(item) for item in value]
    if isinstance(value, (int, str)):
        return value
    raise TypeError("SCIENTIFIC_EVIDENCE_REQUIRES_JSON_TYPES")


def scientific_evidence_hash(value: object) -> str:
    """Hash scientific evidence after deterministic numeric normalization."""

    return canonical_hash(normalize_scientific_evidence(value))


class FeatureContract(BaseModel):
    """Immutable contract; missing values remain explicit and never become facts."""

    model_config = ConfigDict(frozen=True)

    feature_name: str
    feature_version: str
    entity: str
    source: str
    available_at: str
    cutoff_policy: str = "STRICTLY_BEFORE_TARGET_KICKOFF"
    lookback: dict[str, object]
    missing_policy: str = "MISSING_NOT_ZERO"
    unit: str
    allowed_markets: list[str]
    allowed_research_modes: list[ResearchMode]
    quality_gate: str
    leakage_tests: list[str]
    provenance: dict[str, str]
    dataset_version: str = "deep-football-features-v1"

    @model_validator(mode="after")
    def validate_fail_closed_contract(self) -> Self:
        if self.missing_policy != "MISSING_NOT_ZERO":
            raise ValueError("DEEP_FEATURE_MISSING_POLICY_MUST_PRESERVE_MISSING")
        if self.cutoff_policy != "STRICTLY_BEFORE_TARGET_KICKOFF":
            raise ValueError("DEEP_FEATURE_CUTOFF_MUST_BE_STRICT")
        if not self.leakage_tests:
            raise ValueError("DEEP_FEATURE_LEAKAGE_TESTS_REQUIRED")
        if not self.allowed_research_modes:
            raise ValueError("DEEP_FEATURE_RESEARCH_MODE_REQUIRED")
        if not self.provenance.get("provider") or not self.provenance.get("source_field"):
            raise ValueError("DEEP_FEATURE_PROVENANCE_REQUIRED")
        return self

    @property
    def contract_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class HypothesisContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    hypothesis_id: str
    title: str
    mechanism: str
    expected_direction: str
    markets: list[str]
    cutoff: str
    required_gates: list[str]
    minimum_support: int = Field(ge=1)
    statistical_family: str
    negative_control: str
    rejection_criterion: str
    frozen_before_results: bool = True

    @model_validator(mode="after")
    def validate_preregistration(self) -> Self:
        if not self.hypothesis_id.startswith("H11-"):
            raise ValueError("JALON11_HYPOTHESIS_ID_REQUIRED")
        if not self.frozen_before_results:
            raise ValueError("HYPOTHESIS_MUST_BE_FROZEN_BEFORE_RESULTS")
        if not self.required_gates or not self.markets:
            raise ValueError("HYPOTHESIS_SCOPE_REQUIRED")
        return self

    @property
    def preregistration_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class DatasetContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    dataset_name: str
    dataset_version: str
    mode: ResearchMode
    cutoff_policy: str
    feature_contract_hashes: list[str]
    source_hashes: list[str]
    row_count: int = Field(ge=0)
    fixture_count: int = Field(ge=0)
    coverage: dict[str, object]
    missingness: dict[str, float]
    exclusions: dict[str, int]
    leakage_audit: dict[str, object]
    production_status: str = "PRODUCTION_LOCKED"
    demo_mode_enabled: bool = False

    @model_validator(mode="after")
    def validate_dataset(self) -> Self:
        if self.cutoff_policy != "STRICTLY_BEFORE_TARGET_KICKOFF":
            raise ValueError("DATASET_CUTOFF_NOT_STRICT")
        if self.demo_mode_enabled:
            raise ValueError("DEMO_DATASET_FORBIDDEN")
        if self.production_status != "PRODUCTION_LOCKED":
            raise ValueError("PRODUCTION_MUST_REMAIN_LOCKED")
        if not bool(self.leakage_audit.get("passed", False)):
            raise ValueError("DATASET_LEAKAGE_AUDIT_REQUIRED")
        return self

    @property
    def dataset_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))
